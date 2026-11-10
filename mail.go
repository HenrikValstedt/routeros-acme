package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// parseEmail validates a single address and returns the bare addr-spec ("" for empty input).
func parseEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	a, err := mail.ParseAddress(s)
	if err != nil || strings.ContainsAny(a.Address, "\r\n") {
		return "", fmt.Errorf("invalid e-mail address %q", s)
	}
	return a.Address, nil
}

func noCRLF(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }

// buildMessage creates a plain-text UTF-8 message.
func buildMessage(from, to, subject, body string) []byte {
	var b bytes.Buffer
	host := "localhost"
	if i := strings.LastIndex(from, "@"); i >= 0 {
		host = from[i+1:]
	}
	hdr := [][2]string{
		{"From", "RouterOS ACME <" + from + ">"},
		{"To", to},
		{"Subject", mime.QEncoding.Encode("utf-8", noCRLF(subject))},
		{"Date", time.Now().Format(time.RFC1123Z)},
		{"Message-ID", "<" + randToken(12) + "@" + host + ">"},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=utf-8"},
		{"Content-Transfer-Encoding", "quoted-printable"},
		{"Auto-Submitted", "auto-generated"},
	}
	for _, h := range hdr {
		b.WriteString(h[0] + ": " + noCRLF(h[1]) + "\r\n")
	}
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	qp.Close()
	return b.Bytes()
}

// sendMail delivers one message per recipient.
func sendMail(m MailSettings, to []string, subject, body string) error {
	if !m.configured() {
		return errors.New("e-mail (SMTP) is not configured")
	}
	if len(to) == 0 {
		return errors.New("no recipients")
	}
	port := m.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(m.Host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	tlsCfg := &tls.Config{ServerName: m.Host, MinVersion: tls.VersionTLS12}

	var conn net.Conn
	var err error
	if m.Security == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp connect %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	c, err := smtp.NewClient(conn, m.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp: %w", err)
	}
	defer c.Close()
	if m.Security == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp server does not support STARTTLS")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if m.User != "" {
		// PlainAuth refuses to send credentials over an unencrypted connection (except to localhost).
		if err := c.Auth(smtp.PlainAuth("", m.User, m.Password, m.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	for _, rcpt := range to {
		if err := c.Mail(m.From); err != nil {
			return fmt.Errorf("smtp MAIL FROM: %w", err)
		}
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp RCPT TO %s: %w", rcpt, err)
		}
		w, err := c.Data()
		if err != nil {
			return fmt.Errorf("smtp DATA: %w", err)
		}
		if _, err := w.Write(buildMessage(m.From, rcpt, subject, body)); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("smtp: %w", err)
		}
		if err := c.Reset(); err != nil {
			return err
		}
	}
	return c.Quit()
}
