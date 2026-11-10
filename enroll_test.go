package main

import (
	"bufio"
	"io"
	"mime/quotedprintable"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is a minimal SMTP server (no TLS/auth) that records messages.
type fakeSMTP struct {
	mu   sync.Mutex
	msgs []string // raw DATA
	rcpt []string
	addr string
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	f := &fakeSMTP{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := func(s string) { io.WriteString(c, s+"\r\n") }
	w("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			w("250-fake")
			w("250 8BITMIME")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			f.mu.Lock()
			f.rcpt = append(f.rcpt, strings.Trim(strings.TrimSpace(line)[8:], "<>"))
			f.mu.Unlock()
			w("250 ok")
		case strings.HasPrefix(cmd, "DATA"):
			w("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.msgs = append(f.msgs, b.String())
			f.mu.Unlock()
			w("250 queued")
		case strings.HasPrefix(cmd, "QUIT"):
			w("221 bye")
			return
		default: // MAIL, RSET, NOOP
			w("250 ok")
		}
	}
}

func (f *fakeSMTP) wait(t *testing.T, n int) []string {
	t.Helper()
	for i := 0; i < 100; i++ {
		f.mu.Lock()
		if len(f.msgs) >= n {
			out := append([]string(nil), f.msgs...)
			f.mu.Unlock()
			return out
		}
		f.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected %d e-mails", n)
	return nil
}

func decodeBody(raw string) string {
	_, body, _ := strings.Cut(raw, "\r\n\r\n")
	b, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	return string(b)
}

func (f *fakeSMTP) settings() MailSettings {
	h, p, _ := net.SplitHostPort(f.addr)
	port, _ := strconv.Atoi(p)
	return MailSettings{Host: h, Port: port, Security: "none", From: "acme@example.org",
		PublicURL: "https://certs.example.org", WarnDays: 14,
		NotifyIssueOK: true, NotifyIssueFail: true, NotifyDeployFail: true, NotifyExpiry: true}
}

func TestSendMail(t *testing.T) {
	f := startFakeSMTP(t)
	err := sendMail(f.settings(), []string{"a@example.org", "b@example.org"}, "Hej\r\nBcc: evil@example.org åäö", "line1\nlänk: https://x/#invite=abc")
	if err != nil {
		t.Fatal(err)
	}
	msgs := f.wait(t, 2)
	if strings.Join(f.rcpt, ",") != "a@example.org,b@example.org" {
		t.Fatalf("rcpt %v", f.rcpt)
	}
	hdr, _, _ := strings.Cut(msgs[0], "\r\n\r\n")
	if strings.Contains(hdr, "\r\nBcc:") {
		t.Fatal("header injection via subject")
	}
	if !strings.Contains(hdr, "Subject: =?utf-8?q?") || !strings.Contains(hdr, "To: a@example.org") {
		t.Fatalf("headers:\n%s", hdr)
	}
	if b := decodeBody(msgs[0]); !strings.Contains(b, "länk: https://x/#invite=abc") {
		t.Fatalf("body: %q", b)
	}
	if err := sendMail(MailSettings{}, []string{"a@example.org"}, "x", "y"); err == nil {
		t.Fatal("expected not-configured error")
	}
}

var linkRE = regexp.MustCompile(`https://certs\.example\.org/#(invite|reset)=([A-Za-z0-9_-]+)`)

func TestInviteAndReset(t *testing.T) {
	a, srv := newTestApp(t)
	f := startFakeSMTP(t)
	admin := newClient(t, srv)
	admin.expect(200, "POST", "/api/setup", map[string]string{"code": a.setupCode, "username": "boss", "password": "supersecret", "email": "boss@example.org"})
	admin.turnOn2FA()

	// configure mail through the API
	ms := f.settings()
	admin.expect(200, "PUT", "/api/mail", ms)
	admin.expect(400, "PUT", "/api/mail", map[string]any{"host": "x", "port": 25, "security": "none", "from": "not an address", "warnDays": 14})
	admin.expect(200, "POST", "/api/mail/test", map[string]string{}) // goes to the admin's own address
	f.wait(t, 1)

	// invite
	if s := admin.expect(200, "POST", "/api/invites", map[string]string{"email": "Viewer <v@example.org>", "role": "viewer"}); !strings.Contains(s, `"emailed":true`) {
		t.Fatal(s)
	}
	admin.expect(400, "POST", "/api/invites", map[string]string{"email": "boss@example.org", "role": "viewer"}) // already a user
	msgs := f.wait(t, 2)
	m := linkRE.FindStringSubmatch(decodeBody(msgs[1]))
	if m == nil || m[1] != "invite" {
		t.Fatalf("no invite link in:\n%s", decodeBody(msgs[1]))
	}
	tok := m[2]
	if s := admin.expect(200, "GET", "/api/invites", nil); !strings.Contains(s, "v@example.org") {
		t.Fatal(s)
	}

	anon := newClient(t, srv)
	anon.expect(404, "POST", "/api/invite/check", map[string]string{"token": "nope"})
	if s := anon.expect(200, "POST", "/api/invite/check", map[string]string{"token": tok}); !strings.Contains(s, `"role":"viewer"`) {
		t.Fatal(s)
	}
	anon.expect(400, "POST", "/api/invite/accept", map[string]string{"token": tok, "username": "boss", "password": "viewerpass"}) // taken
	if s := anon.expect(200, "POST", "/api/invite/accept", map[string]string{"token": tok, "username": "vera", "password": "viewerpass"}); !strings.Contains(s, `"email":"v@example.org"`) {
		t.Fatal(s)
	}
	anon.expect(200, "GET", "/api/state", nil) // logged in after accepting
	anon.expect(403, "GET", "/api/invites", nil)
	anon.expect(403, "PUT", "/api/mail", ms)
	anon.expect(403, "POST", "/api/mail/test", map[string]string{})
	if s := anon.expect(200, "GET", "/api/state", nil); strings.Contains(s, `"password":"`) {
		t.Fatal("smtp password leaked")
	}
	newClient(t, srv).expect(400, "POST", "/api/invite/accept", map[string]string{"token": tok, "username": "again", "password": "viewerpass"}) // one-time

	// my account: opt in to notifications
	anon.expect(200, "PUT", "/api/me", map[string]any{"email": "v@example.org", "notify": true})
	anon.expect(400, "PUT", "/api/me", map[string]any{"email": "", "notify": true})

	// forgot password: same answer for unknown accounts, mail only for real ones
	other := newClient(t, srv)
	unknown := other.expect(200, "POST", "/api/forgot", map[string]string{"login": "nobody"})
	known := other.expect(200, "POST", "/api/forgot", map[string]string{"login": "V@example.org"})
	if unknown != known {
		t.Fatal("forgot responses differ")
	}
	msgs = f.wait(t, 3)
	m = linkRE.FindStringSubmatch(decodeBody(msgs[2]))
	if m == nil || m[1] != "reset" {
		t.Fatalf("no reset link in:\n%s", decodeBody(msgs[2]))
	}
	other.expect(400, "POST", "/api/reset", map[string]string{"token": m[2], "password": "short"})
	other.expect(200, "POST", "/api/reset", map[string]string{"token": m[2], "password": "brandnewpass"})
	other.expect(400, "POST", "/api/reset", map[string]string{"token": m[2], "password": "brandnewpass2"}) // one-time
	anon.expect(401, "GET", "/api/state", nil)                                                             // old sessions ended
	other.expect(401, "POST", "/api/login", map[string]string{"username": "vera", "password": "viewerpass"})
	other.expect(200, "POST", "/api/login", map[string]string{"username": "vera", "password": "brandnewpass"})

	// forgot-password is rate limited per client
	for i := 0; i < 3; i++ {
		other.do("POST", "/api/forgot", map[string]string{"login": "x"})
	}
	other.expect(429, "POST", "/api/forgot", map[string]string{"login": "x"})
}

func TestNotifications(t *testing.T) {
	st, _ := OpenStore(t.TempDir())
	_ = st.Update(func(c *Config) error {
		c.Mail = MailSettings{Host: "smtp", From: "a@b.c", WarnDays: 14, NotifyIssueFail: true, NotifyExpiry: true, NotifyDeployOK: false,
			ExtraRecipients: "ops@example.org"}
		c.Users = []*User{
			{ID: "1", Username: "a", Email: "a@example.org", Notify: true},
			{ID: "2", Username: "b", Email: "b@example.org", Notify: false},
			{ID: "3", Username: "c", Notify: true}, // no address
		}
		return nil
	})
	m := NewManager(st, t.TempDir())
	var sent []string
	var to []string
	m.mailer = func(_ MailSettings, rcpt []string, subj, body string) error {
		sent, to = append(sent, subj+"\n"+body), rcpt
		return nil
	}
	run := func(evs ...event) {
		for _, e := range evs {
			m.event(e.kind, e.key, e.text)
		}
		m.flushEvents()
	}

	run(event{evIssueFail, "cert:1", "c1: dns error"}, event{evDeployOK, "router:1", "r1 ok"})
	if len(sent) != 1 || !strings.Contains(sent[0], "1 certificate errors") || strings.Contains(sent[0], "r1 ok") {
		t.Fatalf("first: %q", sent)
	}
	if strings.Join(to, ",") != "a@example.org,ops@example.org" {
		t.Fatalf("recipients %v", to)
	}
	run(event{evIssueFail, "cert:1", "c1: dns error"}) // same error again -> suppressed
	if len(sent) != 1 {
		t.Fatal("duplicate failure not suppressed")
	}
	run(event{evIssueFail, "cert:1", "c1: other error"}) // new error -> sent
	if len(sent) != 2 {
		t.Fatal("changed failure not sent")
	}
	run(event{evIssueOK, "cert:1", "c1 renewed"}, event{evIssueFail, "cert:1", "c1: other error"}) // success resets
	if len(sent) != 3 {
		t.Fatal("failure after success not sent")
	}
}
