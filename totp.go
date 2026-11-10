package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"rsc.io/qr"
)

// TOTP per RFC 6238: HMAC-SHA1, 30-second steps, 6 digits. This is what Google/Microsoft
// Authenticator, Authy, 1Password, Bitwarden etc. use by default.
const (
	totpPeriod = 30
	totpDigits = 6
	totpSkew   = 1 // accept the previous and next step too (clock drift)
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() string {
	b := make([]byte, 20) // 160 bits, as recommended by RFC 4226
	_, _ = rand.Read(b)
	return b32.EncodeToString(b)
}

func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, code%mod)
}

func totpStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// totpCode returns the code for secret at time t (used by tests and the UI-less paths).
func totpCode(secret string, t time.Time) string {
	key, _ := b32.DecodeString(strings.ToUpper(secret))
	return hotp(key, uint64(totpStep(t)))
}

// checkTOTP verifies code against secret around now. It returns the matched time step,
// which must be greater than the last accepted one (each code works only once).
func checkTOTP(secret, code string, lastStep int64, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	cur := totpStep(now)
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		step := cur + d
		if step <= lastStep {
			continue // replay of an already used code
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(step))), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// otpauthURI is what authenticator apps read from the QR code.
func otpauthURI(secret, account, issuer string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// qrSVG renders text as an SVG QR code (black on white, with the required quiet zone).
func qrSVG(text string) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := c.Size + 2*quiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="QR code">`, n, n)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}

// ---- recovery codes ----

const recoveryCount = 10

// newRecoveryCodes returns codes to show once, and their hashes to store.
func newRecoveryCodes() (plain, hashed []string) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no 0/o, 1/l/i
	for i := 0; i < recoveryCount; i++ {
		b := make([]byte, 10)
		_, _ = rand.Read(b)
		var s strings.Builder
		for j, x := range b {
			if j == 5 {
				s.WriteByte('-')
			}
			s.WriteByte(alphabet[int(x)%len(alphabet)])
		}
		plain = append(plain, s.String())
		hashed = append(hashed, hashRecovery(s.String()))
	}
	return plain, hashed
}

func normRecovery(code string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(code)))
}

func hashRecovery(code string) string {
	h := sha256.Sum256([]byte("routeros-acme-recovery:" + normRecovery(code)))
	return hex.EncodeToString(h[:])
}

// looksLikeRecovery tells a recovery code (xxxxx-xxxxx) from a 6-digit TOTP code.
func looksLikeRecovery(code string) bool { return len(normRecovery(code)) == 10 }
