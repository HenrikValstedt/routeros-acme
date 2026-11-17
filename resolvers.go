package main

// Resolver check for local DNS records. Some networks write their records to a primary
// that isn't a resolver itself and copy them to the resolvers on a schedule. For such a
// DNS server the user lists the resolvers; the app then asks them (plain DNS queries)
// whether each record arrived. A record that's missing (or a removed address that's still
// answered) counts as "copying" for a grace period after the app changed it, and as
// "late" after that: shown in red and e-mailed.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultGrace     = 10 // minutes
	resolverPoll     = time.Minute
	resolverLatePoll = 5 * time.Minute
)

func (s *DNSServer) grace() time.Duration {
	g := s.Grace
	if g <= 0 {
		g = defaultGrace
	}
	return time.Duration(g) * time.Minute
}

// noteChanges records which names the app just changed on a server: their grace period
// starts now, and removed addresses must disappear from the resolvers.
func noteChanges(s *DNSServer, changed []dnsWant, now time.Time) {
	if len(s.Resolvers) == 0 {
		s.Since, s.Gone = nil, nil
		return
	}
	if s.Since == nil {
		s.Since = map[string]time.Time{}
	}
	if s.Gone == nil {
		s.Gone = map[string][]string{}
	}
	for _, c := range changed {
		name := strings.ToLower(c.Name)
		s.Since[name] = now
		if c.Device == "" { // removed
			if !slices.Contains(s.Gone[name], c.Addr) {
				s.Gone[name] = append(s.Gone[name], c.Addr)
			}
		} else { // added again: it shouldn't be gone any more
			s.Gone[name] = slices.DeleteFunc(s.Gone[name], func(a string) bool { return a == c.Addr })
			if len(s.Gone[name]) == 0 {
				delete(s.Gone, name)
			}
		}
	}
}

// dnsExpect is what the resolvers should answer for a name.
type dnsExpect struct{ Want, Gone []string }

// resolverExpect: for every name the app keeps on server s (not blocked by a conflict),
// the addresses it should have; plus removed addresses that should be gone.
func resolverExpect(cfg Config, s *DNSServer) map[string]dnsExpect {
	exp := map[string]dnsExpect{}
	for _, w := range dnsWants(cfg, s.RouterID) {
		name := strings.ToLower(w.Name)
		if slices.Contains(s.Blocked, name) {
			continue
		}
		e := exp[name]
		e.Want = append(e.Want, w.Addr)
		exp[name] = e
	}
	for name, addrs := range s.Gone {
		e := exp[name]
		for _, a := range addrs {
			if !slices.Contains(e.Want, a) {
				e.Gone = append(e.Gone, a)
			}
		}
		if len(e.Want)+len(e.Gone) > 0 {
			exp[name] = e
		}
	}
	return exp
}

// queryFunc asks one resolver for a name's A and AAAA addresses.
type queryFunc func(resolver, name string) ([]string, error)

type resolverReport struct {
	State  string   // ok | copying | late
	Issues []string // one line per name that isn't right everywhere
	Late   []string // event texts for names past the grace period (stable, for de-duplication)
	Since  map[string]time.Time
	Gone   map[string][]string
	Status map[string]string // name -> "copying" or the late text, for the devices
}

// checkResolvers compares what each resolver answers with what it should.
func checkResolvers(s *DNSServer, exp map[string]dnsExpect, query queryFunc, now time.Time) resolverReport {
	rep := resolverReport{State: "ok", Since: map[string]time.Time{}, Gone: map[string][]string{}, Status: map[string]string{}}
	names := make([]string, 0, len(exp))
	for n := range exp {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, name := range names {
		e := exp[name]
		var probs []string
		for _, rv := range s.Resolvers {
			got, err := query(rv, name)
			if err != nil {
				probs = append(probs, fmt.Sprintf("%s doesn't answer (%v)", rv, err))
				continue
			}
			var missing, stale []string
			for _, a := range e.Want {
				if !slices.Contains(got, a) {
					missing = append(missing, a)
				}
			}
			for _, a := range e.Gone {
				if slices.Contains(got, a) {
					stale = append(stale, a)
				}
			}
			switch {
			case len(missing) > 0 && len(stale) > 0:
				probs = append(probs, fmt.Sprintf("%s lacks %s and still answers %s", rv, strings.Join(missing, ", "), strings.Join(stale, ", ")))
			case len(missing) > 0:
				probs = append(probs, fmt.Sprintf("%s lacks %s", rv, strings.Join(missing, ", ")))
			case len(stale) > 0:
				probs = append(probs, fmt.Sprintf("%s still answers %s", rv, strings.Join(stale, ", ")))
			}
		}
		if len(probs) == 0 {
			continue // right everywhere: no longer waiting, removed addresses are gone
		}
		since, ok := s.Since[name]
		if !ok {
			since = now // wrong without a change by the app (e.g. a resolver lost it): grace from now
		}
		rep.Since[name] = since
		if len(e.Gone) > 0 {
			rep.Gone[name] = slices.Clone(e.Gone)
		}
		if age := now.Sub(since); age < s.grace() {
			rep.Issues = append(rep.Issues, fmt.Sprintf("%s: copying to the resolvers (%d of %d min)", name, int(age.Minutes()), int(s.grace().Minutes())))
			rep.Status[name] = "copying"
			if rep.State == "ok" {
				rep.State = "copying"
			}
		} else {
			text := fmt.Sprintf("%s: %s", name, strings.Join(probs, "; "))
			rep.Issues = append(rep.Issues, text+fmt.Sprintf(" (for %d min)", int(age.Minutes())))
			rep.Late = append(rep.Late, text)
			rep.Status[name] = "not on all resolvers: " + strings.Join(probs, "; ")
			rep.State = "late"
		}
	}
	return rep
}

// verifyResolvers runs the check for every DNS server that has resolvers (inside a job).
func (m *Manager) verifyResolvers() {
	cfg := m.store.Snapshot()
	reports := map[string]resolverReport{}
	for _, s := range cfg.DNSServers {
		if len(s.Resolvers) == 0 || m.stop() {
			continue
		}
		reports[s.RouterID] = checkResolvers(s, resolverExpect(cfg, s), queryResolver, time.Now())
	}
	if len(reports) == 0 {
		return
	}
	now := time.Now()
	status := map[string]string{}
	_ = m.store.Update(func(cf *Config) error {
		for _, s := range cf.DNSServers {
			rep, ok := reports[s.RouterID]
			if !ok {
				continue
			}
			if s.ResolverState != rep.State {
				name := s.RouterID
				if x := cf.router(s.RouterID); x != nil {
					name = x.Name
				}
				m.logf("[%s] local DNS: resolvers %s", name, map[string]string{
					"ok": "have all records", "copying": "are still copying the records", "late": "are late: " + strings.Join(rep.Late, "; ")}[rep.State])
			}
			s.ResolverState, s.ResolverIssues, s.ResolverChecked = rep.State, rep.Issues, now
			s.Since, s.Gone = rep.Since, rep.Gone
			for n, st := range rep.Status {
				if prev, ok := status[n]; !ok || prev == "copying" {
					status[n] = st // "late" beats "copying"
				}
			}
		}
		for _, r := range cf.Routers {
			if r.DNS != nil {
				r.DNS.Resolvers = status[r.DNS.Name]
			}
		}
		return nil
	})
	for id, rep := range reports {
		for _, text := range rep.Late {
			m.event(evDNSLate, "dns:"+id+":"+strings.SplitN(text, ":", 2)[0], text)
		}
	}
}

// ResolverWatch checks the resolvers between the regular checks while records are on
// their way (every minute) or late (every 5 minutes).
func (m *Manager) ResolverWatch() {
	t := time.NewTicker(resolverPoll)
	defer t.Stop()
	for range t.C {
		if m.stop() {
			return
		}
		due := false
		for _, s := range m.store.Snapshot().DNSServers {
			if len(s.Resolvers) == 0 {
				continue
			}
			switch {
			case s.ResolverState == "copying",
				s.ResolverState == "late" && time.Since(s.ResolverChecked) >= resolverLatePoll:
				due = true
			}
		}
		if due {
			m.Go(m.verifyResolvers)
		}
	}
}

// queryResolver asks a resolver directly (not through the system's DNS) for a name's
// A and AAAA records.
func queryResolver(resolver, name string) ([]string, error) {
	var out []string
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(name), qt)
		var in *dns.Msg
		var err error
		for range 2 { // one retry: a single lost UDP packet isn't a missing record
			in, _, err = (&dns.Client{Timeout: 2 * time.Second}).Exchange(msg, resolver)
			if err == nil {
				break
			}
		}
		if err == nil && in.Truncated {
			in, _, err = (&dns.Client{Net: "tcp", Timeout: 3 * time.Second}).Exchange(msg, resolver)
		}
		if err != nil {
			msg := err.Error()
			if i := strings.LastIndex(msg, ": "); i >= 0 {
				msg = msg[i+2:] // "connection refused", not the socket addresses before it
			}
			if strings.Contains(msg, "timeout") {
				msg = "no answer in time"
			}
			return nil, errors.New(msg)
		}
		for _, rr := range in.Answer {
			switch v := rr.(type) {
			case *dns.A:
				out = append(out, v.A.String())
			case *dns.AAAA:
				out = append(out, v.AAAA.String())
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// normalizeResolver turns "192.0.2.53", "192.0.2.53:5353", "2001:db8::53" or
// "[2001:db8::53]:5353" into host:port. Only addresses: the check mustn't depend on DNS.
func normalizeResolver(s string) (string, error) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return net.JoinHostPort(a.String(), "53"), nil
	}
	if ap, err := netip.ParseAddrPort(s); err == nil && ap.Port() != 0 {
		return net.JoinHostPort(ap.Addr().String(), strconv.Itoa(int(ap.Port()))), nil
	}
	return "", fmt.Errorf("%q is not an IP address (optionally with :port)", s)
}

// updateDNSServer sets a DNS server's resolvers and grace period.
func (a *app) updateDNSServer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Resolvers []string `json:"resolvers"`
		Grace     int      `json:"graceMinutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	var res []string
	for _, x := range in.Resolvers {
		if strings.TrimSpace(x) == "" {
			continue
		}
		n, err := normalizeResolver(x)
		if err != nil {
			fail(w, 400, err)
			return
		}
		if !slices.Contains(res, n) {
			res = append(res, n)
		}
	}
	if len(res) > 10 {
		fail(w, 400, errors.New("at most 10 resolvers"))
		return
	}
	if in.Grace == 0 {
		in.Grace = defaultGrace
	}
	if in.Grace < 1 || in.Grace > 120 {
		fail(w, 400, errors.New("the grace period must be 1–120 minutes"))
		return
	}
	id := r.PathValue("id")
	err := a.store.Update(func(c *Config) error {
		s := c.dnsServer(id)
		if s == nil {
			return errors.New("not a DNS server")
		}
		s.Resolvers, s.Grace = res, in.Grace
		s.ResolverState, s.ResolverIssues, s.Since, s.Gone = "", nil, nil, nil
		if len(res) == 0 {
			for _, x := range c.Routers {
				if x.DNS != nil {
					x.DNS.Resolvers = ""
				}
			}
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.mgr.Go(a.mgr.verifyResolvers)
	writeJSON(w, "ok")
}
