package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// proxyTrust decides when X-Forwarded-* headers can be believed: only when the
// TCP peer is one of the configured reverse proxies (TRUSTED_PROXIES).
type proxyTrust struct {
	nets []netip.Prefix
}

var privateNets = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"}

// parseTrustedProxies accepts IPs, CIDRs and the keyword "private"
// (loopback + RFC1918 + IPv6 ULA), separated by commas or spaces.
func parseTrustedProxies(s string) (proxyTrust, error) {
	var p proxyTrust
	for _, item := range splitList(s) {
		items := []string{item}
		if strings.EqualFold(item, "private") {
			items = privateNets
		}
		for _, it := range items {
			if strings.Contains(it, "/") {
				pf, err := netip.ParsePrefix(it)
				if err != nil {
					return p, fmt.Errorf("TRUSTED_PROXIES: %q: %w", it, err)
				}
				p.nets = append(p.nets, pf.Masked())
				continue
			}
			a, err := netip.ParseAddr(it)
			if err != nil {
				return p, fmt.Errorf("TRUSTED_PROXIES: %q: %w", it, err)
			}
			a = a.Unmap()
			p.nets = append(p.nets, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return p, nil
}

func (p proxyTrust) enabled() bool { return len(p.nets) > 0 }

func (p proxyTrust) trusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, n := range p.nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

func (p proxyTrust) String() string {
	s := make([]string, len(p.nets))
	for i, n := range p.nets {
		s[i] = n.String()
	}
	return strings.Join(s, ", ")
}

func peerAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	return a.Unmap(), err == nil
}

// fromProxy reports whether the request came directly from a trusted proxy.
func (p proxyTrust) fromProxy(r *http.Request) bool {
	a, ok := peerAddr(r)
	return ok && p.trusted(a)
}

// clientIP returns the real client address. X-Forwarded-For is walked from the
// right, skipping trusted proxies, so a client can't spoof it by sending its own header.
func (p proxyTrust) clientIP(r *http.Request) string {
	peer, ok := peerAddr(r)
	if !ok {
		return r.RemoteAddr
	}
	if !p.trusted(peer) {
		return peer.String()
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	if len(hops) == 0 {
		if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
			return a.Unmap().String()
		}
		return peer.String()
	}
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // garbage: stop at the last good hop
		}
		client = a.Unmap()
		if !p.trusted(client) {
			break
		}
	}
	return client.String()
}

// isHTTPS reports whether the client connection is HTTPS (directly or via a trusted proxy).
func (p proxyTrust) isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !p.fromProxy(r) {
		return false
	}
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

// normalizeBasePath turns "certs/", "/certs" etc. into "/certs" ("" for root).
func normalizeBasePath(s string) (string, error) {
	s = strings.Trim(strings.TrimSpace(s), "/")
	if s == "" {
		return "", nil
	}
	if strings.ContainsAny(s, " ?#%\\") || strings.Contains(s, "..") {
		return "", fmt.Errorf("BASE_PATH: invalid value %q", s)
	}
	return "/" + s, nil
}

// withBasePath serves h under base. Requests that already had the prefix stripped
// by the proxy are served too, so both proxy styles work.
func withBasePath(base string, h http.Handler) http.Handler {
	if base == "" {
		return h
	}
	stripped := http.StripPrefix(base, h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == base:
			http.Redirect(w, r, base+"/", http.StatusMovedPermanently)
		case strings.HasPrefix(r.URL.Path, base+"/"):
			stripped.ServeHTTP(w, r)
		default:
			h.ServeHTTP(w, r)
		}
	})
}
