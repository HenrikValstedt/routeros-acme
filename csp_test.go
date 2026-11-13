package main

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// The page must work under the strict Content Security Policy: no inline scripts,
// event handlers or style attributes anywhere in the HTML or in HTML built by app.js.
func TestNoInlineCode(t *testing.T) {
	inline := regexp.MustCompile(`(?i)<[a-z][^>]*\s(on[a-z]+|style)\s*=\s*["']|<script>|<style>|javascript:`)
	for _, f := range []string{"web/index.html", "web/app.js"} {
		b, err := webFS.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if inline.MatchString(line) {
				t.Errorf("%s:%d: inline code or style is blocked by the CSP: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
	if strings.Contains(contentSecurityPolicy, "unsafe") {
		t.Fatal("the CSP must not allow unsafe-inline or unsafe-eval")
	}
}

func TestPageAndAssets(t *testing.T) {
	_, srv := newTestApp(t)
	get := func(path string) (*http.Response, string) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	resp, page := get("/")
	if csp := resp.Header.Get("Content-Security-Policy"); csp != contentSecurityPolicy {
		t.Fatalf("CSP: %q", csp)
	}
	for _, name := range []string{"app.js", "app.css"} {
		m := regexp.MustCompile(`"` + regexp.QuoteMeta(name) + `\?v=([0-9a-f]{12})"`).FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("page doesn't link %s with a version", name)
		}
		r, body := get("/" + name + "?v=" + m[1])
		if r.StatusCode != 200 || len(body) < 1000 || !strings.Contains(r.Header.Get("Cache-Control"), "immutable") {
			t.Fatalf("%s: %d, %d bytes, %q", name, r.StatusCode, len(body), r.Header.Get("Cache-Control"))
		}
		if r, _ := get("/" + name + "?v=old"); r.Header.Get("Cache-Control") != "no-cache" {
			t.Fatalf("%s with a stale version must not be cached for long", name)
		}
	}
}
