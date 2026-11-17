package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/registration"
)

// TestLabARI runs issue → ARI → renewal ("replaces") → revocation against a local ACME
// server (Pebble with PEBBLE_VA_ALWAYS_VALID=1) and a DNS server that accepts unsigned
// RFC 2136 updates for lab.test and is authoritative for it:
//
//	ACME_DIRECTORY_URL=https://127.0.0.1:14000/dir LEGO_CA_CERTIFICATES=pebble.minica.pem \
//	LAB_DNS=127.0.0.2:53 go test -run LabARI -v
func TestLabARI(t *testing.T) {
	dnsAddr := os.Getenv("LAB_DNS")
	if os.Getenv("ACME_DIRECTORY_URL") == "" || dnsAddr == "" {
		t.Skip("set ACME_DIRECTORY_URL, LEGO_CA_CERTIFICATES and LAB_DNS to run against a local Pebble + DNS lab")
	}
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(st, dir)
	if m.sealer, err = newSealer(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	name := "ari" + newID()[:6] + ".lab.test"
	_ = st.Update(func(c *Config) error {
		c.Settings.Email, c.Settings.DNSResolvers, c.Settings.KeyType = "lab@example.com", dnsAddr, "ec256"
		c.DNS = []*DNSAccount{{ID: "d1", Name: "lab", Provider: "rfc2136",
			Config: map[string]string{"nameserver": dnsAddr}, Zones: []string{"lab.test"}}}
		c.Certs = []*Cert{{ID: "c1", Name: "lab", Domains: []string{name}}}
		return nil
	})
	cert := func() Cert { return *m.store.Snapshot().cert("c1") }

	// 1. first issue: the renewal window is fetched right after
	m.issue("c1")
	c := cert()
	if c.LastError != "" || c.Fingerprint == "" {
		t.Fatalf("issue failed: %q", c.LastError)
	}
	if !c.hasARI() {
		t.Fatalf("no ARI window after issue (error %q)", c.ARIError)
	}
	if c.RenewAt.Before(c.ARIStart) || !c.RenewAt.Before(c.ARIEnd) {
		t.Fatalf("renewAt %v outside window %v – %v", c.RenewAt, c.ARIStart, c.ARIEnd)
	}
	t.Logf("cert valid until %v; window %v – %v; renewAt %v; next ask %v",
		c.NotAfter, c.ARIStart, c.ARIEnd, c.RenewAt, c.ARINext)
	if needsRenewal(&c, 30, time.Now()) {
		t.Fatal("a fresh certificate must not be due")
	}
	first := c.Fingerprint
	oldID := m.replacesID(c)
	if oldID == "" {
		t.Fatal("no replaces ID for a certificate the CA knows")
	}

	// within Retry-After nothing is asked again
	m.refreshARI("c1")
	if got := cert(); !got.ARINext.Equal(c.ARINext) {
		t.Fatal("asked the CA again before Retry-After")
	}

	// 2. renewal as "replaces": the CA links it to the first certificate
	m.issue("c1")
	c = cert()
	if c.LastError != "" || c.Fingerprint == first {
		t.Fatalf("renewal failed: %q", c.LastError)
	}
	// ordering again as a replacement of the first one must now be refused as
	// alreadyReplaced (lego then orders without it) – proof the link was accepted
	prov, _, err := dnsProviderFor(m.store.Snapshot(), c, m.sealer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := obtain(dir, m.store.Snapshot().Settings, c, prov, oldID, m.logf); err != nil {
		t.Fatalf("ordering with an already replaced ID: %v", err)
	}
	m.store.Update(func(cf *Config) error { cf.cert("c1").Fingerprint = "x"; return nil }) // files changed under it; re-read
	chain, _, _ := loadCertFiles(dir, "c1")
	leaf, _ := parseLeaf(chain)
	m.store.Update(func(cf *Config) error {
		x := cf.cert("c1")
		x.Fingerprint, x.NotAfter = fingerprint(leaf), leaf.NotAfter
		return nil
	})
	m.refreshARI("c1")
	c = cert()
	if !c.hasARI() {
		t.Fatalf("no window for the current certificate: %q", c.ARIError)
	}

	// 3. revocation: the CA moves the window into the past, the certificate is due
	client, u, _, err := newACMEClient(dir, m.store.Snapshot().Settings)
	if err != nil {
		t.Fatal(err)
	}
	if u.Registration == nil {
		u.Registration, _ = client.Registration.ResolveAccountByKey()
	}
	if u.Registration == nil {
		u.Registration, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := client.Certificate.Revoke(chain); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	m.store.Update(func(cf *Config) error { cf.cert("c1").ARINext = time.Time{}; return nil }) // as if Retry-After passed
	m.refreshARI("c1")
	c = cert()
	t.Logf("after revocation: window %v – %v, renewAt %v, explanation %q", c.ARIStart, c.ARIEnd, c.RenewAt, c.ARIExplain)
	if !needsRenewal(&c, 30, time.Now()) {
		t.Fatal("a revoked certificate must be due at once")
	}
	if !hasLog(m, "moved the renewal window earlier") {
		t.Fatal("the earlier window was not logged")
	}

	// 4. a certificate the CA doesn't know: no window, fixed rule
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "x"}, AuthorityKeyId: []byte{1, 2, 3},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	other, _ := x509.ParseCertificate(der)
	if _, err := renewalInfo(dir, m.store.Snapshot().Settings, other); err == nil || !strings.Contains(err.Error(), "no renewal information") {
		t.Fatalf("unknown certificate: got %v", err)
	}
}

func hasLog(m *Manager, s string) bool {
	for _, l := range m.Logs() {
		if strings.Contains(l.Msg, s) {
			return true
		}
	}
	return false
}
