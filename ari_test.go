package main

import (
	"strings"
	"testing"
	"time"
)

func TestRenewTime(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	exp := now.Add(40 * 24 * time.Hour)
	day := 24 * time.Hour

	c := &Cert{NotAfter: exp, Fingerprint: "fp"}
	if got := renewTime(c, 30); !got.Equal(exp.Add(-30 * day)) {
		t.Fatalf("no ARI: got %v, want 30 days before expiry", got)
	}
	if needsRenewal(c, 30, now) {
		t.Fatal("no ARI, 40 days left, renewDays 30: not due yet")
	}
	if !needsRenewal(c, 45, now) {
		t.Fatal("no ARI, 40 days left, renewDays 45: due")
	}

	// ARI says later than the fixed rule: ARI wins
	c.ARIFor, c.RenewAt = "fp", exp.Add(-10*day)
	if got := renewTime(c, 30); !got.Equal(c.RenewAt) {
		t.Fatalf("ARI: got %v, want %v", got, c.RenewAt)
	}
	if needsRenewal(c, 30, now) {
		t.Fatal("ARI window not reached: not due")
	}
	// window in the past (e.g. revocation): due now
	c.RenewAt = now.Add(-time.Hour)
	if !needsRenewal(c, 30, now) {
		t.Fatal("ARI window in the past: due")
	}
	// a window after the safety floor is capped at 7 days before expiry
	c.RenewAt = exp.Add(-2 * day)
	if got := renewTime(c, 30); !got.Equal(exp.Add(-7 * day)) {
		t.Fatalf("floor: got %v, want 7 days before expiry", got)
	}
	// ... or renewDays, if that's fewer
	if got := renewTime(c, 3); !got.Equal(exp.Add(-3 * day)) {
		t.Fatalf("floor with renewDays 3: got %v", got)
	}
	// a window for an older certificate doesn't count
	c.RenewAt, c.Fingerprint = exp.Add(-10*day), "new"
	if got := renewTime(c, 30); !got.Equal(exp.Add(-30 * day)) {
		t.Fatalf("stale ARI: got %v, want the fixed rule", got)
	}
	// not issued yet: due
	if !needsRenewal(&Cert{}, 30, now) {
		t.Fatal("not issued: due")
	}
}

// Short-lived certificates (e.g. Let's Encrypt's 6-day profile) must not be due, or
// warned about, right after issue: the fixed rule, the floor and the expiry warning
// scale with the lifetime.
func TestShortLivedCert(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	c := &Cert{NotBefore: now, NotAfter: now.Add(6 * day), Fingerprint: "fp"}
	if got := renewTime(c, 30); !got.Equal(now.Add(4 * day)) {
		t.Fatalf("no ARI: got %v, want a third of the lifetime before expiry", got)
	}
	if needsRenewal(c, 30, now.Add(time.Hour)) {
		t.Fatal("a fresh 6-day certificate must not be due")
	}
	c.ARIFor, c.RenewAt = "fp", now.Add(5*day+12*time.Hour) // window after the floor
	if got := renewTime(c, 30); !got.Equal(now.Add(5 * day)) {
		t.Fatalf("floor: got %v, want a sixth of the lifetime before expiry", got)
	}
	if d := c.atMost(14*day, 6); d != day {
		t.Fatalf("expiry warning for a 6-day certificate: %v", d)
	}
	// a 90-day certificate keeps the plain values
	c = &Cert{NotBefore: now, NotAfter: now.Add(90 * day), Fingerprint: "fp"}
	if got := renewTime(c, 30); !got.Equal(now.Add(60 * day)) {
		t.Fatalf("90 days, no ARI: got %v", got)
	}
	if d := c.atMost(14*day, 6); d != 14*day {
		t.Fatalf("expiry warning for a 90-day certificate: %v", d)
	}
}

func TestPickInWindow(t *testing.T) {
	start := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)
	seen := map[bool]bool{}
	for range 1000 {
		p := pickInWindow(start, end)
		if p.Before(start) || !p.Before(end) {
			t.Fatalf("%v outside [%v, %v)", p, start, end)
		}
		seen[p.Before(start.Add(24*time.Hour))] = true
	}
	if !seen[true] || !seen[false] {
		t.Fatal("picks are not spread over the window")
	}
	if p := pickInWindow(start, start); !p.Equal(start) {
		t.Fatalf("empty window: got %v", p)
	}
}

func TestSameNames(t *testing.T) {
	if !sameNames([]string{"*.Example.com", "example.com"}, []string{"example.com.", "*.example.com", "example.com"}) {
		t.Fatal("order, case, trailing dot and duplicates must not matter")
	}
	if sameNames([]string{"a.example.com"}, []string{"a.example.com", "b.example.com"}) {
		t.Fatal("an added name is a different set")
	}
}

func TestNextWake(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	cfg := Config{Settings: Settings{CheckHours: 12, RenewDays: 30}}
	if d := nextWake(cfg, now); d != 12*time.Hour {
		t.Fatalf("no certs: %v", d)
	}
	exp := now.Add(60 * 24 * time.Hour)
	cfg.Certs = []*Cert{
		{NotAfter: exp, Fingerprint: "a", ARIFor: "a", RenewAt: now.Add(3 * time.Hour)},
		{NotAfter: exp, Fingerprint: "b", ARIFor: "b", RenewAt: now.Add(-time.Hour)}, // due: the cycle handles it
		{},
	}
	if d := nextWake(cfg, now); d != 3*time.Hour+time.Minute {
		t.Fatalf("wake at the renewal time: got %v", d)
	}

	// time to ask the CA again (Retry-After) comes first
	cfg.Certs[0].ARINext = now.Add(2 * time.Hour)
	if d := nextWake(cfg, now); d != 2*time.Hour+time.Minute {
		t.Fatalf("wake to ask the CA again: got %v", d)
	}

	// a due certificate whose renewal failed: retry after the back-off, not the check interval
	cfg.Certs[1].LastError, cfg.Certs[1].LastAttempt = "boom", now.Add(-50*time.Minute)
	if d := nextWake(cfg, now); d != 11*time.Minute {
		t.Fatalf("wake to retry a failed renewal: got %v", d)
	}
	// a failure on a certificate that isn't due (e.g. a manual Renew) doesn't shorten the wait
	cfg.Certs[1].LastError = ""
	cfg.Certs[0].LastError, cfg.Certs[0].LastAttempt = "boom", now.Add(-50*time.Minute)
	if d := nextWake(cfg, now); d != 2*time.Hour+time.Minute {
		t.Fatalf("failure on a certificate that isn't due: got %v", d)
	}
}

func TestEarlyRenewalNotification(t *testing.T) {
	if !kindEnabled(MailSettings{NotifyIssueFail: true}, evARIEarly) || kindEnabled(MailSettings{}, evARIEarly) {
		t.Fatal("early-renewal mails follow the 'Renewal failed' checkbox")
	}
	subj, body := summarize([]event{{evARIEarly, "cert:1", "lab (a.example): Let's Encrypt asks for renewal"}, {evIssueOK, "cert:1", "lab renewed"}}, "")
	if !strings.Contains(subj, "⚠") || !strings.Contains(subj, "1 early renewal requested by let's encrypt") ||
		!strings.Contains(body, "Early renewal requested by Let's Encrypt\n") {
		t.Fatalf("subject %q\nbody %q", subj, body)
	}
}
