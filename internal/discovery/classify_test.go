package discovery

import (
	"bytes"
	"testing"
	"time"
)

func TestClassifyResponse(t *testing.T) {
	bl := &baseline{status: 200, length: 10, set: true}
	bl.hash = sha256Sum([]byte("not-found!"))
	cases := []struct {
		name   string
		status int
		body   string
		loc    string
		want   Classification
	}{
		{"available", 200, "real content here", "", ClassAvailable},
		{"soft404 same body", 200, "not-found!", "", ClassSoft404},
		// Same LENGTH as the hint page but different bytes: a real page must
		// never be merged into soft_404 just because of equal size.
		{"available same length different body", 200, "xxxxxxxxx!", "", ClassAvailable},
		{"available one byte off", 200, "not-found?", "", ClassAvailable},
		{"not found", 404, "", "", ClassNotFound},
		{"gone", 410, "", "", ClassNotFound},
		{"redirect", 302, "", "/login", ClassRedirect},
		{"redirect 301", 301, "", "/x", ClassRedirect},
		{"auth required", 401, "", "", ClassAuthRequired},
		{"forbidden", 403, "", "", ClassForbidden},
		{"rate limited exhausted", 429, "", "", ClassError},
		{"server error exhausted", 503, "", "", ClassError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyResponse(c.status, []byte(c.body), c.loc, bl)
			if got != c.want {
				t.Fatalf("got %s want %s", got, c.want)
			}
		})
	}
}

// TestBaselineMatchesExactBody pins the soft-404 equivalence semantics: a
// response is equivalent to the hint page only when status AND every body
// byte match. Equal length alone, or an unset baseline, never matches.
func TestBaselineMatchesExactBody(t *testing.T) {
	hint := []byte("<html>404 page not found here</html>")
	bl := &baseline{status: 200, length: int64(len(hint)), set: true}
	bl.hash = sha256Sum(hint)

	if !bl.matches(200, hint) {
		t.Error("byte-identical body must match the soft-404 baseline")
	}
	// Deterministically build a real page of the EXACT same length as the
	// hint page but with different bytes.
	sameSize := bytes.Repeat([]byte("R"), len(hint))
	if bl.matches(200, sameSize) {
		t.Error("equal-length but different body must NOT match soft-404 baseline")
	}
	// Different status never matches even with identical body.
	if bl.matches(404, hint) {
		t.Error("different status must not match")
	}
	// Unset baseline never matches.
	if (&baseline{}).matches(200, hint) {
		t.Error("unset baseline must not match")
	}
	if (*baseline)(nil).matches(200, hint) {
		t.Error("nil baseline must not match")
	}
}

func TestBackoffDeterministic(t *testing.T) {
	base, max := 100*time.Millisecond, 500*time.Millisecond
	want := []time.Duration{100, 200, 400, 500, 500}
	for i, w := range want {
		if got := Backoff(base, max, i+1); got != w*time.Millisecond {
			t.Fatalf("attempt %d: got %v want %v", i+1, got, w*time.Millisecond)
		}
	}
}
