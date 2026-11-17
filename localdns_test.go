package main

import (
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestRealRouterOSLocalDNS checks, against a real RouterOS 7, what a "local DNS records"
// feature needs from the restricted service account: static A/AAAA records (several per
// name), finding and changing them by comment, refusing duplicates, seeing records made
// by someone else, and reading the device's own addresses. Same opt-in as
// TestRealRouterOS; with ROS_DNS=127.0.0.1:5354 (the router's DNS, allow-remote-requests
// on) it also checks the answers.
func TestRealRouterOSLocalDNS(t *testing.T) {
	host := os.Getenv("ROS_HOST")
	if host == "" {
		t.Skip("set ROS_HOST/ROS_SSH_PORT/ROS_API_PORT/ROS_USER/ROS_PASS to run against a real RouterOS")
	}
	sshPort, _ := strconv.Atoi(os.Getenv("ROS_SSH_PORT"))
	apiPort, _ := strconv.Atoi(os.Getenv("ROS_API_PORT"))
	admin := sshLogin{Host: host, Port: sshPort, User: os.Getenv("ROS_USER"), Password: os.Getenv("ROS_PASS")}
	const svcUser = "routeros-acme-dnstest"
	const name, tag = "dnstest.lab.test", "routeros-acme dns test"

	p, err := probeDevice(admin, svcUser)
	if err != nil {
		t.Fatal(err)
	}
	admin.HostKey = p.HostKey
	res, err := enrollDevice(admin, enrollOpts{APIPort: apiPort, ServiceUser: svcUser, AllowedFrom: p.SourceIP})
	if err != nil {
		t.Fatal(err)
	}
	sl, _ := loadSealer(t.TempDir())
	dev := res.Router
	dev.ID, dev.Name, dev.Secret = "d1", "chr", sl.seal(dev.Secret)
	t.Cleanup(func() {
		if rc, err := dialSSH(admin); err == nil {
			rc.run(`/ip dns static remove [find where name="` + name + `"]`)
			rc.Close()
		}
		if err := cleanupDevice(admin, svcUser); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	// someone else's record for the same name, made by the admin
	rc, err := dialSSH(admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.run(`/ip dns static add name=` + name + ` address=203.0.113.1 comment="made by hand"`); err != nil {
		t.Fatal(err)
	}
	rc.Close()

	c, _, _, err := connectDevice(dev, sl)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 1. the service account adds several addresses for one name, A and AAAA
	for _, a := range []struct{ typ, addr string }{{"A", "192.0.2.10"}, {"A", "198.51.100.10"}, {"AAAA", "2001:db8::10"}} {
		if _, err := c.run("/ip/dns/static/add", "=name="+name, "=type="+a.typ, "=address="+a.addr, "=ttl=5m", "=comment="+tag); err != nil {
			t.Fatalf("add %s %s: %v", a.typ, a.addr, err)
		}
	}
	// 2. an exact duplicate is refused (so "add" is safe to retry, the error tells us it's there)
	if _, err := c.run("/ip/dns/static/add", "=name="+name, "=address=192.0.2.10", "=comment="+tag); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate: got %v", err)
	}
	// 3. all records for the name, ours found by comment, the other one visible as a conflict
	rows, err := c.run("/ip/dns/static/print", "?name="+name)
	if err != nil {
		t.Fatal(err)
	}
	var ours, others int
	var oneID string
	for _, r := range rows {
		t.Logf("  record %s %s %s ttl=%s comment=%q", r[".id"], r["type"], r["address"], r["ttl"], r["comment"])
		if r["comment"] == tag {
			ours++
			if r["address"] == "198.51.100.10" {
				oneID = r[".id"]
			}
		} else {
			others++
		}
	}
	if ours != 3 || others != 1 {
		t.Fatalf("ours %d (want 3), others %d (want 1)", ours, others)
	}
	// 4. an address changes in place
	if _, err := c.run("/ip/dns/static/set", "=.id="+oneID, "=address=198.51.100.20"); err != nil {
		t.Fatalf("set: %v", err)
	}
	// 5. the device's own addresses (to fill in and to follow changes)
	for _, path := range []string{"/ip/address/print", "/ipv6/address/print"} {
		rows, err := c.run(path, "=.proplist=address,interface,dynamic,disabled")
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, r := range rows {
			t.Logf("  %s %s on %s (dynamic=%s)", path, r["address"], r["interface"], r["dynamic"])
		}
		if len(rows) == 0 {
			t.Fatalf("%s: no addresses", path)
		}
	}
	// 6. the answers, when the router's DNS is reachable
	if srv := os.Getenv("ROS_DNS"); srv != "" {
		got := map[uint16][]string{}
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(name), qt)
			cl := &dns.Client{Timeout: 3 * time.Second}
			var in *dns.Msg
			for range 3 { // the first UDP packet through QEMU's NAT is sometimes lost
				if in, _, err = cl.Exchange(m, srv); err == nil {
					break
				}
			}
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			for _, rr := range in.Answer {
				switch v := rr.(type) {
				case *dns.A:
					got[qt] = append(got[qt], v.A.String())
				case *dns.AAAA:
					got[qt] = append(got[qt], v.AAAA.String())
				}
			}
		}
		slices.Sort(got[dns.TypeA])
		t.Logf("  answers: A %v, AAAA %v", got[dns.TypeA], got[dns.TypeAAAA])
		if !slices.Equal(got[dns.TypeA], []string{"192.0.2.10", "198.51.100.20", "203.0.113.1"}) ||
			!slices.Equal(got[dns.TypeAAAA], []string{"2001:db8::10"}) {
			t.Fatal("unexpected answers")
		}
	}
	// 7. removing ours leaves the other record alone
	rows, _ = c.run("/ip/dns/static/print", "?comment="+tag, "=.proplist=.id")
	for _, r := range rows {
		if _, err := c.run("/ip/dns/static/remove", "=.id="+r[".id"]); err != nil {
			t.Fatalf("remove: %v", err)
		}
	}
	rows, _ = c.run("/ip/dns/static/print", "?name="+name)
	if len(rows) != 1 || rows[0]["comment"] != "made by hand" {
		t.Fatalf("after removing ours: %v", rows)
	}
}
