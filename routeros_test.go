package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAPILengthEncoding(t *testing.T) {
	for _, n := range []int{0, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0x1fffff, 0x200000, 0xfffffff, 0x10000000} {
		b := encodeLen(n)
		got, err := decodeLen(bufio.NewReader(bytes.NewReader(b)))
		if n <= maxWord && (err != nil || got != n) {
			t.Errorf("len %#x: encoded %x decoded %#x err %v", n, b, got, err)
		}
		if n > maxWord && err == nil {
			t.Errorf("len %#x: a word above the limit must be refused", n)
		}
	}
	// the largest 5-byte length: on 32-bit ARM this used to overflow int (a negative make() => crash)
	if _, err := decodeLen(bufio.NewReader(bytes.NewReader([]byte{0xF0, 0xFF, 0xFF, 0xFF, 0xFF}))); err == nil {
		t.Fatal("a 4 GiB word must be refused")
	}
}

func TestSealer(t *testing.T) {
	dir := t.TempDir()
	s, err := loadSealer(dir)
	if err != nil {
		t.Fatal(err)
	}
	sealed := s.seal("hunter2")
	if strings.Contains(sealed, "hunter2") {
		t.Fatal("not encrypted")
	}
	if p, err := s.open(sealed); err != nil || p != "hunter2" {
		t.Fatal(p, err)
	}
	s2, _ := loadSealer(dir) // same key file
	if p, _ := s2.open(sealed); p != "hunter2" {
		t.Fatal("key not persisted")
	}
	t.Setenv("SECRET_KEY", "other")
	s3, _ := loadSealer(dir)
	if _, err := s3.open(sealed); err == nil {
		t.Fatal("wrong key must fail")
	}
}

func TestRosQuote(t *testing.T) {
	if got := rosQuote(`a"b$c\d` + "\n?"); got != `"a\"b\$c\\d\n\?"` {
		t.Fatal(got)
	}
}

func TestLegacyCredentialsWiped(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(dir+"/config.json", []byte(`{"routers":[{"id":"r1","host":"h","password":"oldpw","privateKey":"KEY"}]}`), 0o600)
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(dir + "/config.json")
	if strings.Contains(string(b), "oldpw") || strings.Contains(string(b), "KEY") {
		t.Fatal("legacy SSH credentials still on disk")
	}
	if r := st.Snapshot().Routers[0]; r.enrolled() || r.LastError == "" {
		t.Fatalf("%+v", r)
	}
}

// testChain makes a CA + leaf chain like Let's Encrypt would deliver (leaf first).
func testChain(t *testing.T, cn string) (chain, key []byte, fp string) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	lTpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	lDER, _ := x509.CreateCertificate(rand.Reader, lTpl, ca, &lk.PublicKey, caKey)
	kDER, _ := x509.MarshalECPrivateKey(lk)
	chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: lDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kDER}), certFingerprint(lDER)
}

// TestRealRouterOS runs the whole device lifecycle against a real RouterOS 7 (e.g. a CHR VM).
// Opt-in: ROS_HOST=127.0.0.1 ROS_SSH_PORT=2222 ROS_API_PORT=8729 ROS_USER=admin ROS_PASS=... go test -run Real -v
func TestRealRouterOS(t *testing.T) {
	host := os.Getenv("ROS_HOST")
	if host == "" {
		t.Skip("set ROS_HOST/ROS_SSH_PORT/ROS_API_PORT/ROS_USER/ROS_PASS to run against a real RouterOS")
	}
	sshPort, _ := strconv.Atoi(os.Getenv("ROS_SSH_PORT"))
	apiPort, _ := strconv.Atoi(os.Getenv("ROS_API_PORT"))
	admin := sshLogin{Host: host, Port: sshPort, User: os.Getenv("ROS_USER"), Password: os.Getenv("ROS_PASS")}
	const svcUser = "routeros-acme-test"

	// 1. probe
	p, err := probeDevice(admin, svcUser)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("probe: %+v", p)
	if p.Version == "" || p.HostKey == "" || p.SourceIP == "" {
		t.Fatalf("incomplete probe: %+v", p)
	}

	// 2. enroll (host key confirmed, account restricted to our address)
	admin.HostKey = p.HostKey
	res, err := enrollDevice(admin, enrollOpts{APIPort: apiPort, ServiceUser: svcUser, AllowedFrom: p.SourceIP})
	for _, s := range res.Steps {
		t.Logf("  [%v] %s – %s", s.OK, s.Title, s.Detail)
	}
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sl, _ := loadSealer(dir)
	dev := res.Router
	dev.ID, dev.Name, dev.Secret = "d1", "chr", sl.seal(dev.Secret)
	dev.Services = []string{"www-ssl", "api-ssl"}
	dev.ExtraCmds = `:log info "routeros-acme test deployed {{cert}}"`
	t.Cleanup(func() {
		l := admin
		if err := cleanupDevice(l, svcUser); err != nil {
			t.Logf("cleanup: %v", err)
		}
		rc, err := dialSSH(l)
		if err == nil {
			rc.run(`/ip service set www-ssl certificate=none disabled=yes`)
			rc.run(`/ip service set api-ssl certificate=` + apiCertName)
			rc.run(`/certificate remove [find where name~"^le-c1-"]`)
			rc.Close()
		}
	})

	// 3. the service account can't do interactive things
	if _, err := dialSSH(sshLogin{Host: host, Port: sshPort, User: svcUser, Password: "x"}); err == nil {
		t.Fatal("service account must not be able to SSH")
	}

	// 4. deploy twice over the API (second time replaces the first)
	store := func(fp string) error { dev.Pins = uniq(append(dev.Pins, fp)); return nil }
	var lastFP string
	var deployedKeys [][]byte
	for i, cn := range []string{"one.example.test", "two.example.test"} {
		chain, key, fp := testChain(t, cn)
		deployedKeys = append(deployedKeys, key)
		cert := Cert{ID: "c1", Name: cn, Fingerprint: fp}
		c, _, _, err := connectDevice(dev, sl)
		if err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
		if err := deployAPI(c, dev, cert, chain, key, t.Logf, store); err != nil {
			t.Fatalf("deploy %d: %v", i, err)
		}
		// idempotent re-deploy of the same cert
		if err := deployAPI(c, dev, cert, chain, key, t.Logf, store); err != nil {
			t.Fatalf("re-deploy %d: %v", i, err)
		}
		c.Close()
		lastFP = fp
	}

	// 5. api-ssl now serves the deployed certificate, pinned
	c, _, _, err := connectDevice(dev, sl)
	if err != nil {
		t.Fatal(err)
	}
	if c.peerFP != lastFP {
		t.Fatalf("api-ssl serves %s, want deployed %s", c.peerFP, lastFP)
	}
	// 5b. a session through the Manager keeps only the pin api-ssl presents now: the
	// enrollment pin and the earlier deploy's pin are no longer accepted.
	if len(dev.Pins) < 2 {
		t.Fatalf("expected several pins after two deploys, have %v", dev.Pins)
	}
	oldPins := slices.DeleteFunc(slices.Clone(dev.Pins), func(p string) bool { return p == lastFP })
	mdir := t.TempDir()
	mst, _ := OpenStore(mdir)
	mdev := dev
	mdev.ID = "r1"
	_ = mst.Update(func(cf *Config) error { cf.Routers = []*Router{&mdev}; return nil })
	m := NewManager(mst, mdir)
	m.sealer = sl
	ms, _, err := m.session(mst.Snapshot().router("r1"))
	if err != nil {
		t.Fatal(err)
	}
	ms.Close()
	if got := mst.Snapshot().router("r1").Pins; len(got) != 1 || got[0] != lastFP {
		t.Fatalf("pins after a session: %v, want only %s", got, lastFP)
	}
	if _, err := dialAPI(host, apiPort, oldPins); err == nil || !strings.Contains(err.Error(), "not the pinned") {
		t.Fatalf("an old pin alone must be refused: %v", err)
	}
	t.Logf("pins: %d before, 1 after (old ones refused)", len(oldPins)+1)

	certs, _ := c.run("/certificate/print", "=.proplist=name,fingerprint")
	var mine []string
	for _, x := range certs {
		if strings.HasPrefix(x["name"], "le-c1-") {
			mine = append(mine, x["name"])
		}
	}
	t.Logf("certificates from this cert on the device: %v", mine)
	if len(mine) == 0 || len(mine) > 2 { // leaf + its CA
		t.Fatalf("old certificates not cleaned up: %v", mine)
	}
	if files, _ := c.run("/file/print", "=.proplist=name"); strings.Contains(strings.Join(func() []string {
		var n []string
		for _, f := range files {
			n = append(n, f["name"])
		}
		return n
	}(), ","), "le-c1-") {
		t.Fatal("uploaded files (private key!) left on the device")
	}
	if svc, _ := c.run("/ip/service/print", "?name=www-ssl", "=.proplist=certificate"); len(svc) == 0 || !strings.HasPrefix(svc[0]["certificate"], "le-c1-") {
		t.Fatalf("www-ssl certificate: %v", svc)
	}
	// the account cannot manage users
	if _, err := c.run("/user/add", "=name=evil", "=group=full", "=password=evil12345"); err == nil {
		c.run("/user/remove", "=numbers=evil")
		t.Fatal("service account could add users")
	}
	c.Close()

	// 5b. the private key must never appear in the router's log (RouterOS logs "/file add" contents)
	c, _, _, err = connectDevice(dev, sl)
	if err != nil {
		t.Fatal(err)
	}
	logs, _ := c.run("/log/print", "=.proplist=message")
	for _, l := range logs {
		if strings.Contains(l["message"], "PRIVATE KEY-----") && !strings.Contains(l["message"], "Proc-Type: 4,ENCRYPTED") {
			c.Close()
			t.Fatalf("plaintext private key in router log: %.120s", l["message"])
		}
	}
	for _, k := range deployedKeys {
		body := strings.Split(string(k), "\n")[1] // first base64 line of the plaintext key
		for _, l := range logs {
			if strings.Contains(strings.ReplaceAll(l["message"], "\\n", "\n"), body) || strings.Contains(l["message"], body[:40]) {
				c.Close()
				t.Fatalf("private key material found in router log")
			}
		}
	}
	c.Close()

	// 6. a wrong pin is refused
	bad := dev
	bad.Pins = []string{strings.Repeat("0", 64)}
	if _, _, _, err := connectDevice(bad, sl); err == nil || !strings.Contains(err.Error(), "not the pinned") {
		t.Fatalf("expected pin failure, got %v", err)
	}

	// 7. password rotation
	c, oldPw, _, err := connectDevice(dev, sl)
	if err != nil {
		t.Fatal(err)
	}
	newPw := randToken(32)
	if err := rotatePassword(c, oldPw, newPw); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	c.Close()
	oldDev := dev
	dev.Secret = sl.seal(newPw)
	if _, _, _, err := connectDevice(oldDev, sl); err == nil {
		t.Fatal("old password still works after rotation")
	}
	// crash during rotation: new password only in Pending -> still connects
	crashed := oldDev
	crashed.Pending = sl.seal(newPw)
	if c, _, pending, err := connectDevice(crashed, sl); err != nil || !pending {
		t.Fatalf("pending fallback: %v %v", pending, err)
	} else {
		c.Close()
	}
}
