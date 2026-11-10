package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// SSH is used only while enrolling (or cleaning up) a device, with admin credentials
// that the admin types in. sshLogin is never persisted.
type sshLogin struct {
	Host       string `json:"host"`
	Port       int    `json:"sshPort"`
	User       string `json:"adminUser"`
	Password   string `json:"adminPassword"`
	PrivateKey string `json:"adminKey"`
	HostKey    string `json:"hostKey"` // expected SHA256 fingerprint ("" = report what is seen)
}

// wipe clears the credentials from memory (best effort).
func (l *sshLogin) wipe() { l.Password, l.PrivateKey = "", "" }

type rosConn struct {
	c      *ssh.Client
	hostFP string // fingerprint seen during handshake
}

func dialSSH(l sshLogin) (*rosConn, error) {
	conn := &rosConn{}
	var auth []ssh.AuthMethod
	if strings.TrimSpace(l.PrivateKey) != "" {
		signer, err := ssh.ParsePrivateKey([]byte(l.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("private key: %w (passphrase-protected keys are not supported)", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	} else {
		pw := l.Password
		auth = append(auth, ssh.Password(pw),
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				a := make([]string, len(qs))
				for i := range a {
					a[i] = pw
				}
				return a, nil
			}))
	}
	// Allow older algorithms too: older RouterOS versions often only offer ssh-rsa and sha1 kex.
	sup, ins := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	cfg := &ssh.ClientConfig{
		User:              l.User,
		Auth:              auth,
		Timeout:           15 * time.Second,
		HostKeyAlgorithms: append(sup.HostKeys, ins.HostKeys...),
		Config: ssh.Config{
			KeyExchanges: append(sup.KeyExchanges, ins.KeyExchanges...),
			Ciphers:      append(sup.Ciphers, ins.Ciphers...),
			MACs:         append(sup.MACs, ins.MACs...),
		},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			conn.hostFP = ssh.FingerprintSHA256(key)
			if l.HostKey != "" && l.HostKey != conn.hostFP {
				return fmt.Errorf("SSH host key changed: confirmed %s, now %s – stopping", l.HostKey, conn.hostFP)
			}
			return nil
		},
	}
	port := l.Port
	if port == 0 {
		port = 22
	}
	c, err := ssh.Dial("tcp", net.JoinHostPort(l.Host, strconv.Itoa(port)), cfg)
	if err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, errors.New("SSH login failed: wrong username or password/key")
		}
		return nil, fmt.Errorf("SSH %s:%d: %w", l.Host, port, err)
	}
	conn.c = c
	return conn, nil
}

func (rc *rosConn) Close() { rc.c.Close() }

// run executes one RouterOS CLI command and returns its trimmed output.
// Output is inspected too, since older RouterOS exits 0 even on failure.
// Never pass secrets in cmd unless the returned error is handled with care
// (errors echo the command); see runSecret.
func (rc *rosConn) run(cmd string) (string, error) {
	return rc.runRedacted(cmd, cmd)
}

// runRedacted runs cmd but reports errors using shown (with secrets removed).
func (rc *rosConn) runRedacted(cmd, shown string) (string, error) {
	s, err := rc.c.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	b, err := s.CombinedOutput(cmd)
	out := strings.TrimSpace(string(b))
	if err != nil {
		var ee *ssh.ExitError
		if !errors.As(err, &ee) {
			return out, err
		}
		return out, fmt.Errorf("%s: %s", shown, out)
	}
	// Match RouterOS error forms only (e.g. "failure: …", "syntax error (line 1 column 5)"),
	// not words inside normal output like "decryption-failures: 0".
	for _, line := range strings.Split(strings.ToLower(out), "\n") {
		line = strings.TrimSpace(line)
		for _, bad := range []string{"failure:", "syntax error", "no such item", "expected end of command", "expected command name",
			"invalid value", "bad command name", "input does not match", "ambiguous value", "already have such", "not enough permissions"} {
			if strings.HasPrefix(line, bad) || strings.Contains(line, " "+bad) {
				return out, fmt.Errorf("%s: %s", shown, out)
			}
		}
	}
	return out, nil
}

func (rc *rosConn) upload(name string, data []byte) error {
	sc, err := sftp.NewClient(rc.c)
	if err != nil {
		return fmt.Errorf("sftp: %w", err)
	}
	defer sc.Close()
	f, err := sc.Create(name)
	if err != nil {
		return fmt.Errorf("sftp create %s: %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// rosQuote makes a RouterOS string literal.
func rosQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "\n", `\n`, "\r", `\r`, "\t", `\t`, "?", `\?`)
	return `"` + r.Replace(s) + `"`
}
