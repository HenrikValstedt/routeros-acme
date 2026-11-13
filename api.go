package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Minimal RouterOS API client (the binary "API" protocol, here always over TLS = api-ssl).
// https://help.mikrotik.com/docs/display/ROS/API

type apiClient struct {
	conn   net.Conn
	r      *bufio.Reader
	peerFP string
}

type apiError struct{ msg string }

func (e *apiError) Error() string { return e.msg }

func certFingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// dialAPI connects to api-ssl. The server certificate must match one of the pinned
// SHA-256 fingerprints (no CA trust is involved, so IP addresses and self-signed certs work).
func dialAPI(host string, port int, pins []string) (*apiClient, error) {
	if len(pins) == 0 {
		return nil, errors.New("no pinned api-ssl certificate for this device – re-enroll it")
	}
	c := &apiClient{}
	cfg := &tls.Config{
		InsecureSkipVerify: true, // replaced by the fingerprint pin below
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("router presented no certificate")
			}
			c.peerFP = certFingerprint(cs.PeerCertificates[0].Raw)
			if !slices.Contains(pins, c.peerFP) {
				return fmt.Errorf("api-ssl certificate fingerprint %s is not the pinned one – possible man-in-the-middle, or the api-ssl certificate was changed outside RouterOS ACME (re-enroll to accept it)", c.peerFP)
			}
			return nil
		},
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if err != nil {
		return nil, fmt.Errorf("api-ssl %s:%d: %w", host, port, err)
	}
	c.conn, c.r = conn, bufio.NewReader(conn)
	return c, nil
}

func (c *apiClient) Close() { c.conn.Close() }

func (c *apiClient) login(user, pass string) error {
	res, err := c.run("/login", "=name="+user, "=password="+pass)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) {
			return fmt.Errorf("api login as %q failed: %s", user, ae.msg)
		}
		return err
	}
	if len(res) > 0 && res[0]["ret"] != "" {
		return errors.New("RouterOS is too old (challenge login); version 7 or newer is required")
	}
	return nil
}

// run sends one command and returns the !re rows. A !trap becomes an *apiError.
func (c *apiClient) run(cmd string, args ...string) ([]map[string]string, error) {
	_ = c.conn.SetDeadline(time.Now().Add(90 * time.Second))
	if err := c.writeSentence(append([]string{cmd}, args...)); err != nil {
		return nil, err
	}
	var rows []map[string]string
	var trap error
	for {
		words, err := c.readSentence()
		if err != nil {
			return nil, err
		}
		if len(words) == 0 {
			continue
		}
		attrs := map[string]string{}
		for _, w := range words[1:] {
			if strings.HasPrefix(w, "=") {
				k, v, _ := strings.Cut(w[1:], "=")
				attrs[k] = v
			}
		}
		switch words[0] {
		case "!re":
			rows = append(rows, attrs)
		case "!trap":
			if trap == nil {
				trap = &apiError{attrs["message"]}
			}
		case "!fatal":
			c.conn.Close()
			return nil, fmt.Errorf("api fatal: %s", strings.Join(words[1:], " "))
		case "!done":
			if ret, ok := attrs["ret"]; ok {
				rows = append(rows, map[string]string{"ret": ret})
			}
			return rows, trap
		case "!empty": // 7.18+: no rows, !done follows
		}
	}
}

func (c *apiClient) writeSentence(words []string) error {
	var buf []byte
	for _, w := range words {
		buf = append(buf, encodeLen(len(w))...)
		buf = append(buf, w...)
	}
	buf = append(buf, 0)
	_, err := c.conn.Write(buf)
	return err
}

func (c *apiClient) readSentence() ([]string, error) {
	var words []string
	for {
		n, err := decodeLen(c.r)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return words, nil
		}
		w := make([]byte, n)
		if _, err := io.ReadFull(c.r, w); err != nil {
			return nil, err
		}
		words = append(words, string(w))
	}
}

func encodeLen(length int) []byte {
	n := uint64(length) // uint64: the 4/5-byte forms overflow int on 32-bit ARM
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x4000:
		n |= 0x8000
		return []byte{byte(n >> 8), byte(n)}
	case n < 0x200000:
		n |= 0xC00000
		return []byte{byte(n >> 16), byte(n >> 8), byte(n)}
	case n < 0x10000000:
		n |= 0xE0000000
		return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		return []byte{0xF0, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

// maxWord limits one API word from the router. Real replies are far smaller; without a
// limit a faulty or hostile device could announce up to 4 GiB, which overflows int on
// 32-bit ARM (a crash) or exhausts memory elsewhere.
const maxWord = 1 << 20

func decodeLen(r *bufio.Reader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	var extra int
	var n uint64 // the 4/5-byte forms don't fit int on 32-bit ARM
	switch {
	case b&0x80 == 0:
		return int(b), nil
	case b&0xC0 == 0x80:
		n, extra = uint64(b&0x3F), 1
	case b&0xE0 == 0xC0:
		n, extra = uint64(b&0x1F), 2
	case b&0xF0 == 0xE0:
		n, extra = uint64(b&0x0F), 3
	case b == 0xF0:
		n, extra = 0, 4
	default:
		return 0, fmt.Errorf("api: bad length byte %#x", b)
	}
	for i := 0; i < extra; i++ {
		x, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		n = n<<8 | uint64(x)
	}
	if n > maxWord {
		return 0, fmt.Errorf("api: the router sent a %d-byte word, more than the %d bytes allowed", n, maxWord)
	}
	return int(n), nil
}
