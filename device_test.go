package main

import (
	"slices"
	"testing"
)

// RouterOS links a renewed leaf to the CA certificates of an earlier set; those must stay.
func TestStaleCerts(t *testing.T) {
	const (
		old   = "le-c1-20261001T120000-aaaaaaaa"
		older = "le-c1-20260801T120000-bbbbbbbb"
		cur   = "le-c1-20261114T120000-cccccccc"
		gone  = "le-dead0001-20260901T120000-dddddddd" // cert deleted in the app
		other = "le-c2-20261101T120000-eeeeeeee"       // cert of another entry for this router
		sstp  = "le-c3-20261001T120000-ffffffff"       // replaced, but sstp still uses it
	)
	all := []map[string]string{
		{".id": "*1", "name": old, "fingerprint": "leaf1", "akid": "int", "skid": "l1"},
		{".id": "*2", "name": old + ".crt_1", "fingerprint": "int", "akid": "root", "skid": "int"},
		{".id": "*3", "name": old + ".crt_2", "fingerprint": "root", "akid": "x1", "skid": "root"},
		{".id": "*4", "name": cur, "fingerprint": "leaf2", "akid": "int2", "skid": "l2"},
		{".id": "*5", "name": cur + ".crt_1", "fingerprint": "int2", "akid": "root", "skid": "int2"},
		{".id": "*6", "name": older + ".crt_1", "fingerprint": "intA", "akid": "rootA", "skid": "intA"},
		{".id": "*7", "name": older + ".crt_2", "fingerprint": "intB", "akid": "rootA", "skid": "intB"},
		{".id": "*8", "name": "le-c9-20261101T120000-99999999", "fingerprint": "leafC9", "akid": "intB", "skid": "c9"},
		{".id": "*9", "name": "mine", "fingerprint": "other", "akid": "y", "skid": "z"},
		{".id": "*10", "name": "le-manual", "fingerprint": "m", "akid": "y", "skid": "m"},
		{".id": "*11", "name": gone, "fingerprint": "g", "akid": "int", "skid": "g"},
		{".id": "*12", "name": other, "fingerprint": "o", "akid": "int", "skid": "o"},
		{".id": "*13", "name": sstp, "fingerprint": "s", "akid": "intS", "skid": "s"},
		{".id": "*14", "name": sstp + ".crt_1", "fingerprint": "intS", "akid": "rootS", "skid": "intS"},
	}
	// new chain: leaf2, int2, root (root reused from the old set)
	keep := map[string]bool{"leaf2": true, "int2": true, "root": true}
	protect := map[string]bool{"c2": true}
	inUse := map[string]bool{sstp: true, cur: true}
	got := staleCerts(all, "c1", cur, keep, protect, inUse)
	// gone: the old leaf, the deleted cert's leaf, the unused intA, and leafC9 (a cert no
	// entry for this router uses); then intB, which nothing chains to any more. int stays:
	// the other entry's leaf (c2, protected) chains to it. The sstp set stays (in use, and
	// its CA because the sstp leaf chains to it). Names not made by the app stay.
	if want := []string{"*1", "*6", "*7", "*8", "*11"}; !slices.Equal(got, want) {
		t.Fatalf("stale = %v, want %v", got, want)
	}
	// without the keep list, the root still stays: int2 chains to it
	if got := staleCerts(all, "c1", cur, map[string]bool{"leaf2": true}, nil, nil); slices.Contains(got, "*3") || slices.Contains(got, "*5") {
		t.Fatalf("certificates the new leaf chains to were removed: %v", got)
	}
}

func TestCertNames(t *testing.T) {
	for name, want := range map[string]bool{
		"le-3920ccab-20261110T111908-1cf228b2":       true,
		"le-3920ccab-20261110T111908-1cf228b2.crt_2": true,
		"le-c1-20261110T111908-1cf228b2":             true,
		"le-3920ccab-20261110T111908-1cf228b2-copy":  false,
		"le-manual":         false,
		"letsencrypt":       false,
		"routeros-acme-api": false,
	} {
		if appCertRE.MatchString(name) != want {
			t.Errorf("%q: want %v", name, want)
		}
	}
}

func TestProtectedCerts(t *testing.T) {
	cfg := Config{Routers: []*Router{
		{ID: "a", Host: "gw.example.com", CertID: "c1"},
		{ID: "b", Host: "GW.example.com", CertID: "c2"},
		{ID: "c", Host: "gw.example.com", CertID: "c1"},
		{ID: "d", Host: "other.example.com", CertID: "c3"},
	}}
	got := cfg.protectedCerts(cfg.Routers[0])
	if len(got) != 1 || !got["c2"] {
		t.Fatalf("protected = %v, want only c2", got)
	}
}

func TestChainFingerprints(t *testing.T) {
	chain, _, fp := testChain(t, "x.example.test")
	fps := chainFingerprints(chain)
	if len(fps) != 2 || fps[0] != fp {
		t.Fatalf("fingerprints %v, leaf %s", fps, fp)
	}
}
