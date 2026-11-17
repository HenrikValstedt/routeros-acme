package main

// Local DNS records (see LOCAL-DNS-DESIGN.md): a device can get an A/AAAA record on the
// routers that serve DNS to the LAN, so its certificate's name works inside the network.
//
// Rules, from tests on RouterOS 7.25.1:
//   - the app only changes records it made, recognised by dnsComment;
//   - RouterOS merges records for the same name and lets a CNAME or a wildcard
//     (match-subdomain or regexp) override exact records, so a record by someone else
//     for the name, or a wildcard covering it, is a conflict: nothing is written for
//     that name on that server, and the conflict is shown;
//   - records are always exact names, also for wildcard certificates;
//   - the app reaches devices by their stored address, never through these records.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

// DNSRecord is a device's local DNS record.
type DNSRecord struct {
	Name   string     `json:"name"`             // FQDN
	Picks  []AddrPick `json:"picks,omitempty"`  // MikroTik devices: the addresses on these interfaces
	Static []string   `json:"static,omitempty"` // manual devices: typed-in addresses
	Skip   []string   `json:"skip,omitempty"`   // DNS servers (router ids) it isn't written to

	// status, maintained by the app
	Addrs  []string  `json:"addrs,omitempty"` // the addresses in the record at the last sync
	Error  string    `json:"error,omitempty"` // conflicts or problems at the last sync
	Synced time.Time `json:"synced,omitzero"`
}

// AddrPick selects a device's addresses by interface and family, so the record follows
// when the address on that interface changes (DHCP, SLAAC).
type AddrPick struct {
	Interface string `json:"interface"`
	Family    int    `json:"family"` // 4 or 6
}

// DevAddr is one address of a device, as read from it.
type DevAddr struct {
	Address   string `json:"address"`
	Interface string `json:"interface"`
	Family    int    `json:"family"`
	Dynamic   bool   `json:"dynamic,omitempty"` // DHCP (IPv4), DHCPv6/SLAAC (IPv6): can change
}

// DNSServer is an enrolled device that gets the local DNS records.
type DNSServer struct {
	RouterID  string    `json:"routerId"`
	AddedAt   time.Time `json:"addedAt,omitzero"`
	AddedBy   string    `json:"addedBy,omitempty"`
	LastSync  time.Time `json:"lastSync,omitzero"`
	LastError string    `json:"lastError,omitempty"`
	Records   int       `json:"records"`
	Conflicts []string  `json:"conflicts,omitempty"`
}

const (
	dnsTTL           = "5m"
	dnsCommentPrefix = "RouterOS ACME dns:"
)

func dnsComment(deviceID string) string {
	return dnsCommentPrefix + deviceID + " - managed by RouterOS ACME, do not edit"
}

// dnsCommentDevice returns the device id in a comment made by dnsComment.
func dnsCommentDevice(c string) (string, bool) {
	rest, ok := strings.CutPrefix(c, dnsCommentPrefix)
	if !ok {
		return "", false
	}
	if i := strings.IndexByte(rest, ' '); i >= 0 {
		rest = rest[:i]
	}
	return rest, rest != ""
}

// readAddresses reads a device's own addresses, without loopback and link-local.
func readAddresses(api *apiClient) ([]DevAddr, error) {
	var out []DevAddr
	for _, fam := range []int{4, 6} {
		path := "/ip/address/print"
		if fam == 6 {
			path = "/ipv6/address/print"
		}
		rows, err := api.run(path, "=.proplist=address,interface,dynamic,disabled,invalid")
		if err != nil {
			if fam == 6 {
				continue // IPv6 turned off on the device
			}
			return nil, err
		}
		for _, r := range rows {
			if r["disabled"] == "true" || r["invalid"] == "true" {
				continue
			}
			ip, _, _ := strings.Cut(r["address"], "/")
			a, err := netip.ParseAddr(ip)
			if err != nil || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() {
				continue
			}
			out = append(out, DevAddr{Address: a.String(), Interface: r["interface"], Family: fam, Dynamic: r["dynamic"] == "true"})
		}
	}
	return out, nil
}

// recordAddrs are the addresses that belong in r's record now.
func recordAddrs(r *Router) []string {
	if r.DNS == nil {
		return nil
	}
	var out []string
	if r.Manual {
		for _, s := range r.DNS.Static {
			if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
				out = append(out, a.String())
			}
		}
	} else {
		for _, a := range r.Addresses {
			if slices.Contains(r.DNS.Picks, AddrPick{a.Interface, a.Family}) {
				out = append(out, a.Address)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func rrType(addr string) string {
	if a, err := netip.ParseAddr(addr); err == nil && a.Is6() && !a.Is4In6() {
		return "AAAA"
	}
	return "A"
}

// dnsWant is one record that should be on a DNS server.
type dnsWant struct{ Device, Name, Addr string }

// dnsWants are the records that belong on DNS server serverID.
func dnsWants(cfg Config, serverID string) []dnsWant {
	var out []dnsWant
	for _, r := range cfg.Routers {
		if r.DNS == nil || r.DNS.Name == "" || slices.Contains(r.DNS.Skip, serverID) {
			continue
		}
		for _, a := range recordAddrs(r) {
			out = append(out, dnsWant{r.ID, r.DNS.Name, a})
		}
	}
	return out
}

// dnsConflict: a record by someone else, or a wildcard, that blocks a name.
type dnsConflict struct{ Name, Text string }

type dnsPlan struct {
	Add       []dnsWant
	Remove    []string // .id of the app's own records
	Conflicts []dnsConflict
	Records   int // the app's records on the server after the plan
}

// planDNS compares the static records on a DNS server with what should be there. It never
// touches records it didn't make. Names blocked by someone else's record get nothing new;
// the app's existing records for them stay until the conflict is solved.
func planDNS(rows []map[string]string, wants []dnsWant) dnsPlan {
	var p dnsPlan
	wanted := map[string]dnsWant{}
	names := map[string]bool{}
	for _, w := range wants {
		w.Name = strings.ToLower(w.Name)
		wanted[w.Device+"|"+w.Name+"|"+w.Addr] = w
		names[w.Name] = true
	}
	blocked := map[string]bool{}
	for _, r := range rows {
		if _, ours := dnsCommentDevice(r["comment"]); ours || r["disabled"] == "true" {
			continue
		}
		rn := strings.ToLower(strings.TrimSuffix(r["name"], "."))
		var re *regexp.Regexp
		if r["regexp"] != "" {
			re, _ = regexp.Compile("(?i)" + r["regexp"])
		}
		for n := range names {
			var text string
			switch {
			case rn == n:
				what := r["type"]
				if what == "" {
					what = "A"
				}
				val := r["address"]
				if val == "" {
					val = r["cname"]
				}
				text = fmt.Sprintf("a record made by someone else exists (%s %s)", what, val)
			case r["match-subdomain"] == "true" && rn != "" && strings.HasSuffix(n, "."+rn):
				text = fmt.Sprintf("covered by the wildcard record for %s (made by someone else)", rn)
			case re != nil && re.MatchString(n):
				text = fmt.Sprintf("covered by the regexp record %s (made by someone else)", r["regexp"])
			default:
				continue
			}
			p.Conflicts = append(p.Conflicts, dnsConflict{n, text})
			blocked[n] = true
		}
	}
	present := map[string]bool{}
	for _, r := range rows {
		dev, ours := dnsCommentDevice(r["comment"])
		if !ours {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(r["name"], "."))
		addr := r["address"]
		if a, err := netip.ParseAddr(addr); err == nil {
			addr = a.String()
		}
		key := dev + "|" + name + "|" + addr
		_, want := wanted[key]
		if want && !present[key] && r["regexp"] == "" && r["match-subdomain"] != "true" {
			present[key] = true // also while its name is blocked: left until the conflict is solved
			p.Records++
		} else {
			p.Remove = append(p.Remove, r[".id"]) // no longer wanted, or a duplicate
		}
	}
	for key, w := range wanted {
		if !present[key] && !blocked[w.Name] {
			p.Add = append(p.Add, w)
			p.Records++
		}
	}
	slices.SortFunc(p.Add, func(a, b dnsWant) int { return strings.Compare(a.Name+a.Addr, b.Name+b.Addr) })
	slices.SortFunc(p.Conflicts, func(a, b dnsConflict) int { return strings.Compare(a.Name+a.Text, b.Name+b.Text) })
	p.Conflicts = slices.Compact(p.Conflicts)
	return p
}

// syncDNS brings every DNS server in line with the devices' records (part of each check).
func (m *Manager) syncDNS() {
	cfg := m.store.Snapshot()
	hasRecords := slices.ContainsFunc(cfg.Routers, func(r *Router) bool { return r.DNS != nil })
	if !hasRecords && len(cfg.DNSServers) == 0 {
		return
	}
	// 1. the current addresses of MikroTik devices with a record
	for _, r := range cfg.Routers {
		if m.stop() {
			return
		}
		if r.DNS == nil || r.Manual || !r.enrolled() || len(r.DNS.Picks) == 0 {
			continue
		}
		addrs, err := m.deviceAddresses(r)
		if err != nil {
			m.logf("[%s] local DNS: can't read the device's addresses (%v) – keeping the last known ones", r.Name, err)
			continue
		}
		before := recordAddrs(r)
		after := recordAddrs(&Router{DNS: r.DNS, Addresses: addrs})
		if len(before) > 0 && !slices.Equal(before, after) {
			m.logf("[%s] local DNS: address changed: %s → %s", r.Name, strings.Join(before, ", "), strings.Join(after, ", "))
		}
	}

	// 2. each DNS server
	cfg = m.store.Snapshot()
	conflicts := map[string][]string{} // name -> texts
	type result struct {
		err       string
		records   int
		conflicts []string
	}
	results := map[string]result{}
	for _, s := range cfg.DNSServers {
		if m.stop() {
			return
		}
		r := cfg.router(s.RouterID)
		if r == nil || !r.enrolled() {
			results[s.RouterID] = result{err: "the device is not enrolled"}
			continue
		}
		p, err := m.syncServer(r, dnsWants(cfg, s.RouterID))
		res := result{records: p.Records}
		if err != nil {
			res.err = err.Error()
			m.logf("[%s] local DNS: %v", r.Name, err)
		}
		for _, c := range p.Conflicts {
			res.conflicts = append(res.conflicts, c.Name+": "+c.Text)
			conflicts[c.Name] = append(conflicts[c.Name], r.Name+": "+c.Text)
		}
		results[s.RouterID] = res
	}

	// 3. status
	now := time.Now()
	_ = m.store.Update(func(cf *Config) error {
		for _, s := range cf.DNSServers {
			if res, ok := results[s.RouterID]; ok {
				s.LastSync, s.LastError, s.Records, s.Conflicts = now, res.err, res.records, res.conflicts
			}
		}
		for _, r := range cf.Routers {
			if r.DNS == nil {
				continue
			}
			r.DNS.Addrs, r.DNS.Synced = recordAddrs(r), now
			var errs []string
			switch {
			case len(cf.DNSServers) == 0:
				errs = append(errs, "no DNS servers yet: add one under DNS servers")
			case len(r.DNS.Addrs) == 0:
				errs = append(errs, "no addresses to publish")
			}
			for _, s := range cf.DNSServers {
				if res, ok := results[s.RouterID]; ok && res.err != "" && !slices.Contains(r.DNS.Skip, s.RouterID) {
					name := s.RouterID
					if x := cf.router(s.RouterID); x != nil {
						name = x.Name
					}
					errs = append(errs, name+": "+res.err)
				}
			}
			errs = append(errs, conflicts[strings.ToLower(r.DNS.Name)]...)
			r.DNS.Error = strings.Join(errs, "; ")
		}
		return nil
	})
}

// deviceAddresses reads a device's addresses and remembers them.
func (m *Manager) deviceAddresses(r *Router) ([]DevAddr, error) {
	api, _, err := m.session(r)
	if err != nil {
		return nil, err
	}
	addrs, err := readAddresses(api)
	api.Close()
	if err != nil {
		return nil, err
	}
	_ = m.store.Update(func(cf *Config) error {
		if x := cf.router(r.ID); x != nil {
			x.Addresses = addrs
		}
		return nil
	})
	return addrs, nil
}

// syncServer applies the plan for one DNS server.
func (m *Manager) syncServer(r *Router, wants []dnsWant) (dnsPlan, error) {
	api, _, err := m.session(r)
	if err != nil {
		return dnsPlan{}, err
	}
	defer api.Close()
	rows, err := api.run("/ip/dns/static/print", "=.proplist=.id,name,type,address,cname,regexp,match-subdomain,disabled,comment")
	if err != nil {
		return dnsPlan{}, fmt.Errorf("reading the static DNS records: %w", err)
	}
	p := planDNS(rows, wants)
	for _, id := range p.Remove {
		var what string
		for _, x := range rows {
			if x[".id"] == id {
				what = x["name"] + " " + x["address"]
			}
		}
		if _, err := api.run("/ip/dns/static/remove", "=.id="+id); err != nil {
			return p, fmt.Errorf("removing %s: %w", what, err)
		}
		m.logf("[%s] local DNS: removed %s", r.Name, what)
	}
	for _, w := range p.Add {
		_, err := api.run("/ip/dns/static/add", "=name="+w.Name, "=type="+rrType(w.Addr), "=address="+w.Addr,
			"=ttl="+dnsTTL, "=comment="+dnsComment(w.Device))
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return p, fmt.Errorf("adding %s %s: %w", w.Name, w.Addr, err)
		}
		m.logf("[%s] local DNS: added %s %s %s", r.Name, w.Name, rrType(w.Addr), w.Addr)
	}
	return p, nil
}

// removeDNSRecords deletes every record the app made on a device (when it stops being a
// DNS server). Records made by others stay.
func (m *Manager) removeDNSRecords(r *Router) (int, error) {
	api, _, err := m.session(r)
	if err != nil {
		return 0, err
	}
	defer api.Close()
	rows, err := api.run("/ip/dns/static/print", "=.proplist=.id,comment")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, x := range rows {
		if _, ours := dnsCommentDevice(x["comment"]); ours {
			if _, err := api.run("/ip/dns/static/remove", "=.id="+x[".id"]); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// ---- validation ----

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// normalizeDNSName checks a DNS name: an exact FQDN (no wildcard), lower case.
func normalizeDNSName(s string) (string, error) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if n == "" {
		return "", errors.New("enter a DNS name")
	}
	if strings.Contains(n, "*") {
		return "", errors.New("the DNS name must be an exact name, not a wildcard")
	}
	labels := strings.Split(n, ".")
	if len(labels) < 2 || len(n) > 253 {
		return "", fmt.Errorf("%q is not a full DNS name (like gw.example.com)", s)
	}
	for _, l := range labels {
		if !dnsLabel.MatchString(l) {
			return "", fmt.Errorf("%q is not a valid DNS name", s)
		}
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return "", errors.New("the DNS name must be a name, not an address")
	}
	return n, nil
}

// cleanDNS validates a record from the UI for device r (nil = remove the record).
func cleanDNS(c *Config, r *Router, in *DNSRecord) (*DNSRecord, error) {
	if in == nil {
		return nil, nil
	}
	name, err := normalizeDNSName(in.Name)
	if err != nil {
		return nil, err
	}
	for _, x := range c.Routers {
		if x.ID != r.ID && x.DNS != nil && x.DNS.Name == name {
			return nil, fmt.Errorf("%s is already the DNS name of %s", name, x.Name)
		}
	}
	out := &DNSRecord{Name: name}
	if old := r.DNS; old != nil { // keep the status
		out.Addrs, out.Error, out.Synced = old.Addrs, old.Error, old.Synced
	}
	if r.Manual {
		for _, s := range in.Static {
			if s = strings.TrimSpace(s); s == "" {
				continue
			}
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("%q is not an IP address", s)
			}
			out.Static = append(out.Static, a.String())
		}
		slices.Sort(out.Static)
		out.Static = slices.Compact(out.Static)
		if len(out.Static) == 0 {
			return nil, errors.New("enter at least one address")
		}
	} else {
		for _, p := range in.Picks {
			if p.Interface != "" && (p.Family == 4 || p.Family == 6) && !slices.Contains(out.Picks, p) {
				out.Picks = append(out.Picks, p)
			}
		}
		if len(out.Picks) == 0 {
			return nil, errors.New("pick at least one address")
		}
	}
	for _, id := range in.Skip {
		if c.dnsServer(id) != nil && !slices.Contains(out.Skip, id) {
			out.Skip = append(out.Skip, id)
		}
	}
	return out, nil
}

// sameDNSSetup reports whether two records publish the same thing (status ignored).
func sameDNSSetup(a, b *DNSRecord) bool {
	if a == nil || b == nil {
		return a == b
	}
	key := func(d *DNSRecord) string {
		j, _ := json.Marshal(DNSRecord{Name: d.Name, Picks: d.Picks, Static: d.Static, Skip: d.Skip})
		return string(j)
	}
	return key(a) == key(b)
}

// ---- API ----

// deviceAddressesAPI reads a device's addresses live, for the DNS record dialog.
func (a *app) deviceAddressesAPI(w http.ResponseWriter, r *http.Request) {
	dev := a.store.Snapshot().router(r.PathValue("id"))
	if dev == nil || !dev.enrolled() {
		fail(w, 404, errors.New("not an enrolled device"))
		return
	}
	addrs, err := a.mgr.deviceAddresses(dev)
	if err != nil {
		fail(w, 502, fmt.Errorf("can't read the device's addresses: %w", err))
		return
	}
	if addrs == nil {
		addrs = []DevAddr{}
	}
	writeJSON(w, addrs)
}

func (a *app) addDNSServer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RouterID string `json:"routerId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, 400, err)
		return
	}
	var name string
	err := a.store.Update(func(c *Config) error {
		x := c.router(in.RouterID)
		if x == nil || !x.enrolled() {
			return errors.New("pick an enrolled device")
		}
		if c.dnsServer(x.ID) != nil {
			return fmt.Errorf("%s is already a DNS server", x.Name)
		}
		name = x.Name
		c.DNSServers = append(c.DNSServers, &DNSServer{RouterID: x.ID, AddedAt: time.Now(), AddedBy: currentUser(r).Username})
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.mgr.logf("%s added DNS server %q", currentUser(r).Username, name)
	a.mgr.Trigger()
	writeJSON(w, "ok")
}

// removeDNSServer stops using a device as DNS server and deletes the app's records on it
// (in the background, after any running job).
func (a *app) removeDNSServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var dev *Router
	err := a.store.Update(func(c *Config) error {
		if c.dnsServer(id) == nil {
			return errors.New("not a DNS server")
		}
		c.DNSServers = slices.DeleteFunc(c.DNSServers, func(s *DNSServer) bool { return s.RouterID == id })
		for _, x := range c.Routers {
			if x.DNS != nil {
				x.DNS.Skip = slices.DeleteFunc(x.DNS.Skip, func(s string) bool { return s == id })
			}
		}
		if x := c.router(id); x != nil {
			cp := *x
			dev = &cp
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	if dev == nil {
		writeJSON(w, "ok")
		return
	}
	a.mgr.logf("%s removed DNS server %q", currentUser(r).Username, dev.Name)
	a.mgr.Go(func() {
		if !dev.enrolled() {
			return
		}
		n, err := a.mgr.removeDNSRecords(dev)
		if err != nil {
			a.mgr.logf("[%s] local DNS: removing the app's records failed (%v) – %d removed; delete the rest by hand (comment %q)", dev.Name, err, n, dnsCommentPrefix)
			return
		}
		a.mgr.logf("[%s] local DNS: removed the app's %d record(s)", dev.Name, n)
	})
	writeJSON(w, "ok")
}
