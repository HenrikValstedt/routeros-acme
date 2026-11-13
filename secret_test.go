package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newKeyStore makes a data folder with the default key and a few encrypted secrets.
func newKeyStore(t *testing.T) (string, *Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	sl, rep, err := openSealer(st, dir, keyConfig{source: keySourceData}, false)
	if err != nil || rep.Source != keySourceData {
		t.Fatal(rep, err)
	}
	_ = st.Update(func(c *Config) error {
		c.Mail.Password = sl.seal("smtp-pw")
		c.DNS = []*DNSAccount{{ID: "d1", Name: "CF", Token: sl.seal("cf-token")}}
		c.Routers = []*Router{{ID: "r1", Name: "gw", Secret: sl.seal("svc-pw"), ServiceUser: "acme", Pins: []string{"x"}}}
		c.Users = []*User{{ID: "u1", Username: "admin", TOTPSecret: sl.seal("JBSWY3DP"), Recovery: []string{"h"}, Passkeys: []*Passkey{{}}}}
		return nil
	})
	return dir, st
}

func reopen(t *testing.T, dir string) *Store {
	t.Helper()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func checkSecrets(t *testing.T, st *Store, sl *sealer) {
	t.Helper()
	c := st.Snapshot()
	for want, v := range map[string]string{"smtp-pw": c.Mail.Password, "cf-token": c.DNS[0].Token, "svc-pw": c.Routers[0].Secret, "JBSWY3DP": c.Users[0].TOTPSecret} {
		if got, err := sl.open(v); err != nil || got != want {
			t.Errorf("%s: got %q, %v", want, got, err)
		}
	}
}

func writeKey(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(content), 0o400); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKeyFromFile(t *testing.T) {
	raw := strings.Repeat("\x01", 32)
	if k, err := keyFromFile([]byte(raw)); err != nil || string(k) != raw {
		t.Fatal("32 bytes must be used as is")
	}
	a, err1 := keyFromFile([]byte("correct horse battery staple\n"))
	b, err2 := keyFromFile([]byte("  correct horse battery staple"))
	if err1 != nil || err2 != nil || string(a) != string(b) {
		t.Fatal("passphrase must ignore surrounding whitespace", err1, err2)
	}
	if _, err := keyFromFile([]byte("short\n")); err == nil {
		t.Fatal("short passphrase must be refused")
	}
	if _, err := keyFromFile([]byte("abc\x00\x01defghijklmnopqrstuvw")); err == nil {
		t.Fatal("binary that isn't 32 bytes must be refused")
	}
}

func TestReadKeyConfig(t *testing.T) {
	t.Setenv("SECRET_KEY_FILE", "")
	t.Setenv("SECRET_KEY", "")
	if kc, err := readKeyConfig(); err != nil || kc.key != nil || kc.source != keySourceData {
		t.Fatal(kc, err)
	}
	t.Setenv("SECRET_KEY_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := readKeyConfig(); err == nil {
		t.Fatal("a missing key file must stop the start, not fall back")
	}
	t.Setenv("SECRET_KEY_FILE", writeKey(t, "a-long-enough-passphrase\n"))
	if kc, err := readKeyConfig(); err != nil || kc.source != keySourceFile || len(kc.key) != 32 {
		t.Fatal(kc, err)
	}
	t.Setenv("SECRET_KEY", "x")
	if _, err := readKeyConfig(); err == nil {
		t.Fatal("both set must be refused")
	}
}

// Adding SECRET_KEY_FILE with a new key: everything is re-encrypted and secret.key is deleted.
// Removing it again: copying the key file into the data folder as secret.key just works.
func TestKeyMoveToFileAndBack(t *testing.T) {
	dir, _ := newKeyStore(t)
	keyFile := writeKey(t, "my-new-hardened-passphrase-123\n")
	t.Setenv("SECRET_KEY", "")
	t.Setenv("SECRET_KEY_FILE", keyFile)
	kc, err := readKeyConfig()
	if err != nil {
		t.Fatal(err)
	}
	st := reopen(t, dir)
	sl, rep, err := openSealer(st, dir, kc, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Reencrypted != 4 || !rep.RemovedKey { // SMTP, DNS token, device, 2FA
		t.Fatalf("report: %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(dir, "secret.key")); !os.IsNotExist(err) {
		t.Fatal("secret.key must be removed from the data folder")
	}
	checkSecrets(t, reopen(t, dir), sl) // saved to disk

	// next start with the same file: nothing to do
	_, rep, err = openSealer(reopen(t, dir), dir, kc, false)
	if err != nil || rep.Reencrypted != 0 || rep.RemovedKey {
		t.Fatal(rep, err)
	}

	// SECRET_KEY_FILE removed, key not copied back: clear error, no new key written
	_, _, err = openSealer(reopen(t, dir), dir, keyConfig{source: keySourceData}, false)
	if err == nil || !strings.Contains(err.Error(), "secret.key is missing") {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secret.key")); !os.IsNotExist(err) {
		t.Fatal("must not generate a new key over encrypted data")
	}

	// copy the key file back as secret.key: back to the default
	b, _ := os.ReadFile(keyFile)
	_ = os.WriteFile(filepath.Join(dir, "secret.key"), b, 0o600)
	sl2, rep, err := openSealer(reopen(t, dir), dir, keyConfig{source: keySourceData}, false)
	if err != nil || rep.Reencrypted != 0 {
		t.Fatal(rep, err)
	}
	checkSecrets(t, reopen(t, dir), sl2)
}

// Moving the existing secret.key out (same key) needs no re-encryption; a copy left behind is removed.
func TestKeyMovedUnchanged(t *testing.T) {
	dir, _ := newKeyStore(t)
	b, _ := os.ReadFile(filepath.Join(dir, "secret.key"))
	keyFile := writeKey(t, string(b))
	t.Setenv("SECRET_KEY", "")
	t.Setenv("SECRET_KEY_FILE", keyFile)
	kc, _ := readKeyConfig()
	sl, rep, err := openSealer(reopen(t, dir), dir, kc, false)
	if err != nil || rep.Reencrypted != 0 || !rep.RemovedKey {
		t.Fatal(rep, err)
	}
	checkSecrets(t, reopen(t, dir), sl)
}

func TestWrongKeyStops(t *testing.T) {
	dir, _ := newKeyStore(t)
	_ = os.Remove(filepath.Join(dir, "secret.key"))
	// data was sealed with a key that is gone; a different external key is given
	t.Setenv("SECRET_KEY", "")
	t.Setenv("SECRET_KEY_FILE", writeKey(t, "some-other-passphrase-xyz"))
	kc, _ := readKeyConfig()
	_, _, err := openSealer(reopen(t, dir), dir, kc, false)
	if err == nil || !strings.Contains(err.Error(), "4 of 4") {
		t.Fatal(err)
	}
	// a wrong secret.key: refused, and the file is left alone
	_ = os.WriteFile(filepath.Join(dir, "secret.key"), []byte(strings.Repeat("k", 32)), 0o600)
	if _, _, err := openSealer(reopen(t, dir), dir, keyConfig{source: keySourceData}, false); err == nil {
		t.Fatal("wrong secret.key must stop the start")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "secret.key")); string(b) != strings.Repeat("k", 32) {
		t.Fatal("secret.key must not be touched")
	}
}

func TestForgetSecrets(t *testing.T) {
	dir, _ := newKeyStore(t)
	_ = os.Remove(filepath.Join(dir, "secret.key")) // key lost
	sl, rep, err := openSealer(reopen(t, dir), dir, keyConfig{source: keySourceData}, true)
	if err != nil || len(rep.Forgotten) != 4 {
		t.Fatal(rep, err)
	}
	c := reopen(t, dir).Snapshot()
	if c.Mail.Password != "" || c.DNS[0].Token != "" || c.Routers[0].Secret != "" || c.Routers[0].enrolled() {
		t.Fatal("secrets not forgotten")
	}
	if u := c.Users[0]; u.TOTPSecret != "" || u.Recovery != nil || u.Passkeys != nil {
		t.Fatal("2FA must be reset with its secret")
	}
	if !strings.Contains(c.Routers[0].LastError, "enroll") {
		t.Fatal("device must say it needs enrolling")
	}
	// the new key works from now on
	if _, rep, err := openSealer(reopen(t, dir), dir, keyConfig{source: keySourceData}, false); err != nil || len(rep.Forgotten) != 0 {
		t.Fatal(rep, err)
	}
	_ = sl
}
