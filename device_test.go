package main

import (
	"slices"
	"testing"
)

// RouterOS links a renewed leaf to the CA certificates of an earlier set; those must stay.
func TestStaleCerts(t *testing.T) {
	all := []map[string]string{
		{".id": "*1", "name": "le-c1-old", "fingerprint": "leaf1", "akid": "int", "skid": "l1"},
		{".id": "*2", "name": "le-c1-old.crt_1", "fingerprint": "int", "akid": "root", "skid": "int"},
		{".id": "*3", "name": "le-c1-old.crt_2", "fingerprint": "root", "akid": "x1", "skid": "root"},
		{".id": "*4", "name": "le-c1-new", "fingerprint": "leaf2", "akid": "int2", "skid": "l2"},
		{".id": "*5", "name": "le-c1-new.crt_1", "fingerprint": "int2", "akid": "root", "skid": "int2"},
		{".id": "*6", "name": "le-c1-older.crt_1", "fingerprint": "intA", "akid": "rootA", "skid": "intA"},
		{".id": "*7", "name": "le-c1-older.crt_2", "fingerprint": "intB", "akid": "rootA", "skid": "intB"},
		{".id": "*8", "name": "le-c2-x", "fingerprint": "leafC2", "akid": "intB", "skid": "c2"},
		{".id": "*9", "name": "mine", "fingerprint": "other", "akid": "y", "skid": "z"},
	}
	// new chain: leaf2, int2, root (root reused from the old set)
	keep := map[string]bool{"leaf2": true, "int2": true, "root": true}
	got := staleCerts(all, "le-c1-", "le-c1-new", keep)
	// old leaf and its unused intermediate go; root stays (in the new chain, and int2
	// chains to it anyway); intB stays because cert c2's leaf still chains to it
	if want := []string{"*1", "*2", "*6"}; !slices.Equal(got, want) {
		t.Fatalf("stale = %v, want %v", got, want)
	}
	// without the keep list, the root still stays: int2 chains to it
	if got := staleCerts(all, "le-c1-", "le-c1-new", map[string]bool{"leaf2": true}); slices.Contains(got, "*3") || slices.Contains(got, "*5") {
		t.Fatalf("certificates the new leaf chains to were removed: %v", got)
	}
}

func TestChainFingerprints(t *testing.T) {
	chain, _, fp := testChain(t, "x.example.test")
	fps := chainFingerprints(chain)
	if len(fps) != 2 || fps[0] != fp {
		t.Fatalf("fingerprints %v, leaf %s", fps, fp)
	}
}
