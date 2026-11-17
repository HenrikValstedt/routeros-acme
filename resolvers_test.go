package main

import (
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeResolver is a DNS server whose answers the test sets (a resolver the sync hasn't
// reached yet, then has).
type fakeResolver struct {
	mu   sync.Mutex
	recs map[string][]string // fqdn -> addresses
	addr string
}

func newFakeResolver(t *testing.T) *fakeResolver {
	f := &fakeResolver{recs: map[string][]string{}}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = pc.LocalAddr().String()
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		f.mu.Lock()
		for _, a := range f.recs[strings.ToLower(q.Question[0].Name)] {
			ip := net.ParseIP(a)
			hdr := dns.RR_Header{Name: q.Question[0].Name, Class: dns.ClassINET, Ttl: 300}
			switch {
			case ip.To4() != nil && q.Question[0].Qtype == dns.TypeA:
				hdr.Rrtype = dns.TypeA
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip})
			case ip.To4() == nil && q.Question[0].Qtype == dns.TypeAAAA:
				hdr.Rrtype = dns.TypeAAAA
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip})
			}
		}
		f.mu.Unlock()
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return f
}

func (f *fakeResolver) set(name string, addrs ...string) {
	f.mu.Lock()
	f.recs[dns.Fqdn(name)] = addrs
	f.mu.Unlock()
}

func TestResolverCheck(t *testing.T) {
	r1, r2 := newFakeResolver(t), newFakeResolver(t)
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		Routers: []*Router{
			{ID: "d1", Manual: true, DNS: &DNSRecord{Name: "nas.example.com", Static: []string{"192.0.2.20", "2001:db8::20"}}},
			{ID: "d2", Manual: true, DNS: &DNSRecord{Name: "blocked.example.com", Static: []string{"192.0.2.30"}}},
		},
		DNSServers: []*DNSServer{{RouterID: "primary", Resolvers: []string{r1.addr, r2.addr}, Blocked: []string{"blocked.example.com"}}},
	}
	s := cfg.DNSServers[0]
	// the app just wrote nas (and removed an old address of it)
	noteChanges(s, []dnsWant{{"d1", "nas.example.com", "192.0.2.20"}, {"d1", "nas.example.com", "2001:db8::20"}, {"", "nas.example.com", "192.0.2.19"}}, t0)
	exp := resolverExpect(cfg, s)
	if _, ok := exp["blocked.example.com"]; ok {
		t.Fatal("a name blocked by a conflict isn't checked")
	}
	if e := exp["nas.example.com"]; !slices.Equal(e.Gone, []string{"192.0.2.19"}) || len(e.Want) != 2 {
		t.Fatalf("expect %+v", e)
	}
	run := func(at time.Time) resolverReport {
		rep := checkResolvers(s, resolverExpect(cfg, s), dnsTargets(s.Resolvers), at)
		s.Since, s.Gone = rep.Since, rep.Gone
		return rep
	}

	// 1. nothing copied yet, 3 minutes in: copying (yellow)
	r1.set("nas.example.com", "192.0.2.19")
	rep := run(t0.Add(3 * time.Minute))
	if rep.State != "copying" || len(rep.Late) != 0 || rep.Status["nas.example.com"] != "copying" {
		t.Fatalf("3 min: %+v", rep)
	}
	t.Logf("3 min: %v", rep.Issues)

	// 2. still not there after the grace period: late (red), with what's wrong where
	rep = run(t0.Add(11 * time.Minute))
	if rep.State != "late" || len(rep.Late) != 1 {
		t.Fatalf("11 min: %+v", rep)
	}
	t.Logf("11 min: %v", rep.Late)
	for _, want := range []string{r1.addr + " lacks 192.0.2.20, 2001:db8::20 and still answers 192.0.2.19", r2.addr + " lacks"} {
		if !strings.Contains(rep.Late[0], want) {
			t.Fatalf("late text %q lacks %q", rep.Late[0], want)
		}
	}

	// 3. the sync arrives: ok (green), nothing waiting, the removed address is forgotten
	r1.set("nas.example.com", "192.0.2.20", "2001:db8::20")
	r2.set("nas.example.com", "192.0.2.20", "2001:db8::20", "198.51.100.1") // extra answers are fine
	rep = run(t0.Add(12 * time.Minute))
	if rep.State != "ok" || len(rep.Issues) != 0 || len(s.Since) != 0 || len(s.Gone) != 0 {
		t.Fatalf("12 min: %+v", rep)
	}

	// 4. a resolver loses the record later, without a change by the app: grace starts then
	r2.set("nas.example.com")
	rep = run(t0.Add(60 * time.Minute))
	if rep.State != "copying" || !s.Since["nas.example.com"].Equal(t0.Add(60*time.Minute)) {
		t.Fatalf("lost: %+v", rep)
	}

	// 5. a resolver that doesn't answer at all
	s.Resolvers = []string{"127.0.0.1:9"}
	rep = run(t0.Add(200 * time.Minute))
	if rep.State != "late" || !strings.Contains(rep.Late[0], "doesn't answer") {
		t.Fatalf("no answer: %+v", rep)
	}
	t.Logf("no answer: %v", rep.Late)

	// 6. a MikroTik resolver read over the API: its static list, by device name
	s.Resolvers, s.Since, s.Gone = nil, nil, nil
	static := map[string][]string{"nas.example.com": {"192.0.2.20"}}
	dev := []resolverTarget{{"resolver-1", func(n string) ([]string, error) { return static[n], nil }}}
	rep = checkResolvers(s, resolverExpect(cfg, s), dev, t0.Add(300*time.Minute))
	s.Since, s.Gone = rep.Since, rep.Gone
	if rep.State != "copying" || !strings.Contains(rep.Issues[0], "copying") {
		t.Fatalf("device resolver, AAAA missing: %+v", rep)
	}
	rep = checkResolvers(s, resolverExpect(cfg, s), dev, t0.Add(320*time.Minute))
	s.Since, s.Gone = rep.Since, rep.Gone
	if rep.State != "late" || !strings.Contains(rep.Late[0], "resolver-1 lacks 2001:db8::20") {
		t.Fatalf("device resolver late: %+v", rep)
	}
	t.Logf("device resolver: %v", rep.Late)
	static["nas.example.com"] = append(static["nas.example.com"], "2001:db8::20")
	if rep = checkResolvers(s, resolverExpect(cfg, s), dev, t0.Add(321*time.Minute)); rep.State != "ok" {
		t.Fatalf("device resolver synced: %+v", rep)
	}

	// 7. the grace period is per server
	s.Grace = 30
	if s.grace() != 30*time.Minute {
		t.Fatal("grace")
	}
}

func TestNormalizeResolver(t *testing.T) {
	for in, want := range map[string]string{"192.0.2.53": "192.0.2.53:53", " 192.0.2.53:5353 ": "192.0.2.53:5353",
		"2001:db8::53": "[2001:db8::53]:53", "[2001:db8::53]:5353": "[2001:db8::53]:5353"} {
		if got, err := normalizeResolver(in); err != nil || got != want {
			t.Fatalf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"ns1.example.com", "192.0.2.53:0", "300.1.1.1"} {
		if _, err := normalizeResolver(bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	if !kindEnabled(MailSettings{NotifyIssueFail: true}, evDNSLate) {
		t.Fatal("late DNS mails follow the 'Renewal failed or needed early' checkbox")
	}
}
