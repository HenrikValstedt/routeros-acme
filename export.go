package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"software.sslmate.com/src/go-pkcs12"
)

// Certificate export, for installing a certificate by hand on something that isn't
// an enrolled router. Admins only, after a fresh 2FA code or passkey, because the
// files contain the private key. Every export is logged.
type exportRequest struct {
	Format   string `json:"format"`   // pem | pfx
	Password string `json:"password"` // pfx only
	Legacy   bool   `json:"legacy"`   // pfx only: 3DES/SHA-1 for older Windows, Java and appliances
}

func (a *app) exportCert(w http.ResponseWriter, r *http.Request) {
	var in exportRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	c := a.store.Snapshot().cert(r.PathValue("id"))
	if c == nil {
		fail(w, 404, errors.New("certificate not found"))
		return
	}
	chainPEM, keyPEM, err := loadCertFiles(a.dataDir, c.ID)
	if errors.Is(err, os.ErrNotExist) {
		fail(w, 409, errors.New("this certificate hasn't been issued yet"))
		return
	}
	if err != nil {
		fail(w, 500, err)
		return
	}
	leaf, rest, err := splitChain(chainPEM)
	if err != nil {
		fail(w, 500, err)
		return
	}

	base := fmt.Sprintf("%s-%s", fileSafe(c.Name), leaf.NotBefore.UTC().Format("2006-01-02"))
	var out []byte
	var name, ctype, what string
	switch in.Format {
	case "pem":
		out, err = pemZip(chainPEM, keyPEM, leaf, rest)
		name, ctype, what = base+".zip", "application/zip", "PEM files"
	case "pfx":
		if utf8.RuneCountInString(in.Password) < 8 {
			fail(w, 400, errors.New("the PFX password must be at least 8 characters"))
			return
		}
		out, err = pfx(keyPEM, leaf, rest, in.Password, in.Legacy)
		name, ctype, what = base+".pfx", "application/x-pkcs12", "PFX"
		if in.Legacy {
			what += " (compatible with older systems)"
		}
	default:
		fail(w, 400, errors.New("format must be pem or pfx"))
		return
	}
	if err != nil {
		fail(w, 500, err)
		return
	}
	a.mgr.logf("certificate %q exported as %s with its private key by %s", c.Name, what, currentUser(r).Username)
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write(out)
}

// splitChain returns the leaf certificate and the PEM of the rest of the chain.
func splitChain(chainPEM []byte) (*x509.Certificate, []*x509.Certificate, error) {
	var certs []*x509.Certificate
	for b := chainPEM; ; {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("the stored certificate file is empty")
	}
	return certs[0], certs[1:], nil
}

func certPEM(cs ...*x509.Certificate) []byte {
	var b bytes.Buffer
	for _, c := range cs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.Bytes()
}

// pemZip is the usual file set (as certbot names it): fullchain.pem for nginx,
// HAProxy, Proxmox and most others; cert.pem + chain.pem where they are separate.
func pemZip(chainPEM, keyPEM []byte, leaf *x509.Certificate, rest []*x509.Certificate) ([]byte, error) {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"fullchain.pem", chainPEM, 0o644},
		{"cert.pem", certPEM(leaf), 0o644},
		{"chain.pem", certPEM(rest...), 0o644},
		{"privkey.pem", keyPEM, 0o600},
		{"README.txt", []byte(readmeText(leaf)), 0o644},
	}
	for _, f := range files {
		h := &zip.FileHeader{Name: f.name, Method: zip.Deflate, Modified: time.Now()}
		h.SetMode(f.mode)
		fw, err := z.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func readmeText(leaf *x509.Certificate) string {
	return fmt.Sprintf(`Certificate for: %s
Valid until:     %s

fullchain.pem  certificate + intermediate(s): use this in most servers (nginx, HAProxy, Proxmox, ...)
cert.pem       the certificate only
chain.pem      the intermediate certificate(s) only
privkey.pem    the private key: keep it secret

Exported by RouterOS ACME. These files don't renew themselves: export again after each
renewal (turn on "Certificate renewed" e-mails to be reminded).
`, strings.Join(leaf.DNSNames, ", "), leaf.NotAfter.UTC().Format("2006-01-02 15:04 MST"))
}

func pfx(keyPEM []byte, leaf *x509.Certificate, rest []*x509.Certificate, password string, legacy bool) ([]byte, error) {
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	enc := pkcs12.Modern // AES-256, PBKDF2 (Windows Server 2019+, OpenSSL 1.1.1+, current Java)
	if legacy {
		enc = pkcs12.LegacyDES // 3DES, SHA-1: imports everywhere
	}
	return enc.Encode(key, leaf, rest, password)
}

func parseKey(keyPEM []byte) (crypto.PrivateKey, error) {
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, errors.New("the stored private key is unreadable")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("the stored private key has an unknown format")
}

// fileSafe turns a certificate name into a file name: "*.example.com" -> "wildcard.example.com".
func fileSafe(name string) string {
	name = strings.ReplaceAll(name, "*", "wildcard")
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if s := strings.Trim(b.String(), "._"); s != "" {
		return s
	}
	return "certificate"
}
