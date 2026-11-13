package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// writeTestCert stores a leaf + intermediate chain the way issue() does, with the
// key in the format lego writes (PKCS#1 for RSA, SEC 1 for EC).
func writeTestCert(t *testing.T, dir, id string, rsaKey bool) (leaf *x509.Certificate, key crypto.Signer) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)

	var keyPEM []byte
	if rsaKey {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		key, keyPEM = k, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	} else {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		b, _ := x509.MarshalECPrivateKey(k)
		key, keyPEM = k, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "*.example.com"},
		DNSNames: []string{"*.example.com", "example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(der)
	d := filepath.Join(dir, "certs", id)
	_ = os.MkdirAll(d, 0o700)
	_ = os.WriteFile(filepath.Join(d, "privkey.pem"), keyPEM, 0o600)
	_ = os.WriteFile(filepath.Join(d, "fullchain.pem"), certPEM(leaf, ca), 0o600)
	return leaf, key
}

func TestCertExport(t *testing.T) {
	a, srv := newTestApp(t)
	admin := newClient(t, srv)
	admin.expect(200, "POST", "/api/setup", map[string]string{"code": a.setupCode, "username": "boss", "password": "supersecret"})
	admin.turnOn2FA()
	admin.expect(200, "POST", "/api/users", map[string]string{"username": "watcher", "role": "viewer", "password": "viewerpass"})
	viewer := newClient(t, srv)
	viewer.expect(200, "POST", "/api/login", map[string]string{"username": "watcher", "password": "viewerpass"})

	_ = a.store.Update(func(c *Config) error {
		c.Certs = []*Cert{{ID: "c1", Name: "*.example.com", Domains: []string{"*.example.com"}}, {ID: "c2", Name: "rsa"}, {ID: "c3", Name: "pending"}}
		return nil
	})
	leaf, key := writeTestCert(t, a.dataDir, "c1", false)
	rsaLeaf, rsaKey := writeTestCert(t, a.dataDir, "c2", true)

	setFresh := func(fresh bool) {
		a.sessions.mu.Lock()
		defer a.sessions.mu.Unlock()
		for k, s := range a.sessions.m {
			s.fresh, s.oneShot = time.Time{}, false
			if fresh {
				s.fresh = time.Now()
			}
			a.sessions.m[k] = s
		}
	}

	// viewers can't, admins need a fresh code
	viewer.expect(403, "POST", "/api/certs/c1/export", map[string]string{"format": "pem"})
	setFresh(false)
	if msg := admin.expect(403, "POST", "/api/certs/c1/export", map[string]string{"format": "pem"}); !strings.HasPrefix(msg, "otp_required") {
		t.Fatal(msg)
	}
	setFresh(true)

	admin.expect(404, "POST", "/api/certs/nope/export", map[string]string{"format": "pem"})
	admin.expect(409, "POST", "/api/certs/c3/export", map[string]string{"format": "pem"})
	admin.expect(400, "POST", "/api/certs/c1/export", map[string]string{"format": "der"})
	admin.expect(400, "POST", "/api/certs/c1/export", map[string]any{"format": "pfx", "password": "short"})

	// PEM zip
	body := exportBody(t, admin, "c1", map[string]any{"format": "pem"})
	z, err := zip.NewReader(strings.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range z.File {
		rc, _ := f.Open()
		files[f.Name], _ = io.ReadAll(rc)
		rc.Close()
	}
	if len(files) != 5 {
		t.Fatalf("zip has %d files", len(files))
	}
	if l, rest, err := splitChain(files["fullchain.pem"]); err != nil || !l.Equal(leaf) || len(rest) != 1 {
		t.Fatal("fullchain.pem", err)
	}
	if c, rest, _ := splitChain(files["cert.pem"]); !c.Equal(leaf) || len(rest) != 0 {
		t.Fatal("cert.pem must hold the leaf only")
	}
	if c, _, _ := splitChain(files["chain.pem"]); c.Subject.CommonName != "Test Intermediate" {
		t.Fatal("chain.pem must hold the intermediate")
	}
	if k, err := parseKey(files["privkey.pem"]); err != nil || !key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(k.(crypto.Signer).Public()) {
		t.Fatal("privkey.pem", err)
	}

	// PFX, modern and legacy, EC and RSA keys
	for _, tc := range []struct {
		id     string
		legacy bool
		leaf   *x509.Certificate
		key    crypto.Signer
	}{{"c1", false, leaf, key}, {"c1", true, leaf, key}, {"c2", false, rsaLeaf, rsaKey}, {"c2", true, rsaLeaf, rsaKey}} {
		body := exportBody(t, admin, tc.id, map[string]any{"format": "pfx", "password": "import-me-123", "legacy": tc.legacy})
		k, c, chain, err := pkcs12.DecodeChain([]byte(body), "import-me-123")
		if err != nil {
			t.Fatalf("%s legacy=%v: %v", tc.id, tc.legacy, err)
		}
		if !c.Equal(tc.leaf) || len(chain) != 1 || !tc.key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(k.(crypto.Signer).Public()) {
			t.Fatalf("%s legacy=%v: wrong content", tc.id, tc.legacy)
		}
		if _, _, _, err := pkcs12.DecodeChain([]byte(body), "wrong-password"); err == nil {
			t.Fatal("a wrong password must not open the PFX")
		}
	}

	// every export is logged, with who did it
	var logged int
	for _, l := range a.mgr.Logs() {
		if strings.Contains(fmt.Sprint(l), "exported as") && strings.Contains(fmt.Sprint(l), "by boss") {
			logged++
		}
	}
	if logged != 5 {
		t.Fatalf("%d exports logged, want 5", logged)
	}
}

// exportBody downloads an export byte for byte (client.do trims whitespace, which
// would cut a binary file that happens to end in a space or line break).
func exportBody(t *testing.T, c *client, id string, body map[string]any) string {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", c.srv.URL+"/api/certs/"+id+"/export", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("export %s: %d %s", id, resp.StatusCode, out)
	}
	return string(out)
}

func TestFileSafe(t *testing.T) {
	for in, want := range map[string]string{"*.example.com": "wildcard.example.com", "a b/c": "a_b_c", "../..": "certificate", "": "certificate"} {
		if got := fileSafe(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
