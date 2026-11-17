package main

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func rec(id, name, typ, addr, comment string, extra ...string) map[string]string {
	r := map[string]string{".id": id, "name": name, "type": typ, "address": addr, "comment": comment, "disabled": "false"}
	for i := 0; i+1 < len(extra); i += 2 {
		r[extra[i]] = extra[i+1]
	}
	return r
}

func TestPlanDNS(t *testing.T) {
	ours := dnsComment("d1")
	wants := []dnsWant{{"d1", "gw.example.com", "192.0.2.1"}, {"d1", "gw.example.com", "2001:db8::1"}}

	// empty server: both added
	p := planDNS(nil, wants)
	if len(p.Add) != 2 || len(p.Remove) != 0 || p.Records != 2 {
		t.Fatalf("empty: %+v", p)
	}

	// in place: nothing to do; a changed address is replaced; records of others are untouched
	rows := []map[string]string{
		rec("*1", "gw.example.com", "A", "192.0.2.9", ours),      // old address
		rec("*2", "gw.example.com", "AAAA", "2001:db8::1", ours), // still right
		rec("*3", "printer.example.com", "A", "192.0.2.50", "by hand"),
		rec("*4", "old.example.com", "A", "192.0.2.7", dnsComment("gone")), // device removed
		rec("*5", "gw.example.com", "AAAA", "2001:db8::1", ours),           // duplicate
	}
	p = planDNS(rows, wants)
	slices.Sort(p.Remove)
	if !slices.Equal(p.Remove, []string{"*1", "*4", "*5"}) {
		t.Fatalf("remove %v", p.Remove)
	}
	if len(p.Add) != 1 || p.Add[0].Addr != "192.0.2.1" || p.Records != 2 || len(p.Conflicts) != 0 {
		t.Fatalf("plan %+v", p)
	}

	// someone else's record for the name: conflict, nothing added, our existing one stays
	for _, other := range []map[string]string{
		rec("*9", "GW.example.com", "A", "203.0.113.1", "by hand"),
		rec("*9", "gw.example.com", "CNAME", "", "", "cname", "x.example.com"),
		rec("*9", "example.com", "A", "203.0.113.1", "", "match-subdomain", "true"),
		rec("*9", "", "A", "203.0.113.1", "", "regexp", `^.*\.example\.com$`),
	} {
		p = planDNS([]map[string]string{other, rec("*2", "gw.example.com", "AAAA", "2001:db8::1", ours)}, wants)
		if len(p.Add) != 0 || len(p.Remove) != 0 || len(p.Conflicts) != 1 || p.Records != 1 {
			t.Fatalf("conflict with %v: %+v", other, p)
		}
		t.Logf("conflict: %s: %s", p.Conflicts[0].Name, p.Conflicts[0].Text)
	}
	// a disabled record of someone else is no conflict; a wildcard elsewhere neither
	p = planDNS([]map[string]string{
		rec("*9", "gw.example.com", "A", "203.0.113.1", "", "disabled", "true"),
		rec("*8", "other.test", "A", "203.0.113.1", "", "match-subdomain", "true"),
		rec("*7", "notgw.example.com", "A", "203.0.113.1", ""),
	}, wants)
	if len(p.Conflicts) != 0 || len(p.Add) != 2 {
		t.Fatalf("no conflict expected: %+v", p)
	}
	// nothing wanted any more: all ours go, nothing else
	p = planDNS(rows, nil)
	if len(p.Remove) != 4 || p.Records != 0 {
		t.Fatalf("remove all ours: %+v", p)
	}
}

func TestDNSNamesAndRecords(t *testing.T) {
	for in, want := range map[string]string{"GW.Example.com.": "gw.example.com", " sw-01.lan.example.com ": "sw-01.lan.example.com"} {
		if got, err := normalizeDNSName(in); err != nil || got != want {
			t.Fatalf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "gw", "*.example.com", "192.168.1.1", "-a.example.com", "a_b.example.com", "a..example.com"} {
		if _, err := normalizeDNSName(bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	if d, ok := dnsCommentDevice(dnsComment("abc123")); !ok || d != "abc123" {
		t.Fatalf("comment round trip: %q %v", d, ok)
	}
	if _, ok := dnsCommentDevice("Managed by RouterOS ACME - do not edit"); ok {
		t.Fatal("other app comments are not DNS records")
	}

	r := &Router{ID: "d1", DNS: &DNSRecord{Name: "gw.example.com", Picks: []AddrPick{{"vlan10", 4}, {"vlan10", 6}}},
		Addresses: []DevAddr{{"192.0.2.1", "vlan10", 4, false}, {"2001:db8::1", "vlan10", 6, true}, {"198.51.100.1", "ether1", 4, true}}}
	if got := recordAddrs(r); !slices.Equal(got, []string{"192.0.2.1", "2001:db8::1"}) {
		t.Fatalf("picked %v", got)
	}
	r.Addresses[0].Address = "192.0.2.2" // DHCP gave a new address: the record follows
	if got := recordAddrs(r); got[0] != "192.0.2.2" {
		t.Fatalf("follow: %v", got)
	}
	if rrType("2001:db8::1") != "AAAA" || rrType("192.0.2.1") != "A" {
		t.Fatal("record types")
	}

	c := &Config{Routers: []*Router{r, {ID: "d2", Name: "nas", Manual: true}}, DNSServers: []*DNSServer{{RouterID: "d1"}}}
	if _, err := cleanDNS(c, c.Routers[1], &DNSRecord{Name: "gw.example.com", Static: []string{"192.0.2.5"}}); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("duplicate name: %v", err)
	}
	d, err := cleanDNS(c, c.Routers[1], &DNSRecord{Name: "NAS.example.com", Static: []string{" 192.0.2.5", "", "192.0.2.5"}, Skip: []string{"d1", "nope"}})
	if err != nil || d.Name != "nas.example.com" || !slices.Equal(d.Static, []string{"192.0.2.5"}) || !slices.Equal(d.Skip, []string{"d1"}) {
		t.Fatalf("manual: %+v %v", d, err)
	}
	if _, err := cleanDNS(c, c.Routers[1], &DNSRecord{Name: "nas.example.com", Static: []string{"nas"}}); err == nil {
		t.Fatal("a manual address must be an IP")
	}
	if _, err := cleanDNS(c, r, &DNSRecord{Name: "gw.example.com"}); err == nil {
		t.Fatal("a MikroTik record needs picked addresses")
	}
}

// A change that fails halfway must leave nothing behind (it used to stay in memory and be
// saved with the next change: a manual device refused for a duplicate DNS name was still
// created).
func TestUpdateIsAllOrNothing(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	err = st.Update(func(c *Config) error {
		c.Routers = append(c.Routers, &Router{ID: "x", Name: "half"})
		c.Settings.Email = "changed@example.com"
		return errors.New("refused")
	})
	if err == nil {
		t.Fatal("expected the error")
	}
	if c := st.Snapshot(); len(c.Routers) != 0 || c.Settings.Email == "changed@example.com" {
		t.Fatalf("a failed change stayed: %d routers, email %q", len(c.Routers), c.Settings.Email)
	}
	_ = st.Update(func(c *Config) error { c.Settings.CheckHours = 7; return nil })
	if c := st.Snapshot(); len(c.Routers) != 0 || c.Settings.CheckHours != 7 {
		t.Fatal("the next change must not bring the failed one back")
	}
}
