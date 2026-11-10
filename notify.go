package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	evIssueOK    = "issueOk"
	evIssueFail  = "issueFail"
	evDeployOK   = "deployOk"
	evDeployFail = "deployFail"
	evExpiry     = "expiry"
)

type event struct {
	kind, key, text string
}

type sentRecord struct {
	text string
	at   time.Time
}

// event queues a notification; it is sent when the current job finishes.
// key identifies the object (e.g. "cert:<id>") for de-duplication.
func (m *Manager) event(kind, key, text string) {
	m.evMu.Lock()
	m.events = append(m.events, event{kind, key, text})
	m.evMu.Unlock()
}

func kindEnabled(ms MailSettings, kind string) bool {
	switch kind {
	case evIssueOK:
		return ms.NotifyIssueOK
	case evIssueFail:
		return ms.NotifyIssueFail
	case evDeployOK:
		return ms.NotifyDeployOK
	case evDeployFail:
		return ms.NotifyDeployFail
	case evExpiry:
		return ms.NotifyExpiry
	}
	return false
}

// recipients: users with an address who opted in, plus the extra addresses.
func recipients(c Config) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		if a, err := parseEmail(a); err == nil && a != "" && !seen[strings.ToLower(a)] {
			seen[strings.ToLower(a)] = true
			out = append(out, a)
		}
	}
	for _, u := range c.Users {
		if u.Notify {
			add(u.Email)
		}
	}
	for _, a := range splitList(c.Mail.ExtraRecipients) {
		add(a)
	}
	return out
}

// flushEvents sends one summary e-mail for the events of the finished job.
// The same failure/expiry message for the same object is sent at most once per 24h.
func (m *Manager) flushEvents() {
	m.evMu.Lock()
	evs := m.events
	m.events = nil
	m.evMu.Unlock()
	if len(evs) == 0 {
		return
	}
	cfg := m.store.Snapshot()

	var keep []event
	now := time.Now()
	m.evMu.Lock()
	for _, e := range evs {
		dk := e.kind + "|" + e.key
		switch e.kind {
		case evIssueOK: // success: a later failure should be reported again
			delete(m.sent, evIssueFail+"|"+e.key)
			delete(m.sent, evExpiry+"|"+e.key)
		case evDeployOK:
			delete(m.sent, evDeployFail+"|"+e.key)
		default:
			if prev, ok := m.sent[dk]; ok && prev.text == e.text && now.Sub(prev.at) < 24*time.Hour {
				continue
			}
		}
		if !kindEnabled(cfg.Mail, e.kind) {
			continue
		}
		if e.kind != evIssueOK && e.kind != evDeployOK {
			m.sent[dk] = sentRecord{e.text, now}
		}
		keep = append(keep, e)
	}
	m.evMu.Unlock()
	if len(keep) == 0 || !cfg.Mail.configured() {
		return
	}
	to := recipients(cfg)
	if len(to) == 0 {
		return
	}
	subject, body := summarize(keep, cfg.Mail.PublicURL)
	if err := m.mailer(cfg.Mail, to, subject, body); err != nil {
		m.logf("notification e-mail failed: %v", err)
		return
	}
	m.logf("notification e-mail sent to %s", strings.Join(to, ", "))
}

var kindTitle = map[string]string{
	evIssueFail: "Certificate errors", evExpiry: "Expiring certificates", evDeployFail: "Deploy errors",
	evIssueOK: "Certificates renewed", evDeployOK: "Deployed to routers",
}

func summarize(evs []event, publicURL string) (subject, body string) {
	count := map[string]int{}
	for _, e := range evs {
		count[e.kind]++
	}
	order := []string{evIssueFail, evDeployFail, evExpiry, evIssueOK, evDeployOK}
	var parts []string
	var b strings.Builder
	for _, k := range order {
		if count[k] == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d %s", count[k], strings.ToLower(kindTitle[k])))
		fmt.Fprintf(&b, "%s\n%s\n", kindTitle[k], strings.Repeat("-", len(kindTitle[k])))
		var lines []string
		for _, e := range evs {
			if e.kind == k {
				lines = append(lines, "- "+e.text)
			}
		}
		sort.Strings(lines)
		b.WriteString(strings.Join(lines, "\n") + "\n\n")
	}
	prefix := "[RouterOS ACME] "
	if count[evIssueFail]+count[evDeployFail]+count[evExpiry] > 0 {
		prefix = "[RouterOS ACME] ⚠ "
	}
	if publicURL != "" {
		b.WriteString("Open the dashboard: " + strings.TrimRight(publicURL, "/") + "/\n")
	}
	b.WriteString("\nYou receive this because notifications are enabled for your account in RouterOS ACME.\n")
	return prefix + strings.Join(parts, ", "), b.String()
}
