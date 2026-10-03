package discovery

import (
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
		{"soft404 same length", 200, "xxxxxxxxx!", "", ClassSoft404},
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

func TestBackoffDeterministic(t *testing.T) {
	base, max := 100*time.Millisecond, 500*time.Millisecond
	want := []time.Duration{100, 200, 400, 500, 500}
	for i, w := range want {
		if got := Backoff(base, max, i+1); got != w*time.Millisecond {
			t.Fatalf("attempt %d: got %v want %v", i+1, got, w*time.Millisecond)
		}
	}
}
