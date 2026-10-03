package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingServer records how many times each path was requested.
type countingServer struct {
	*httptest.Server
	mu     sync.Mutex
	counts map[string]int
}

func newCountingServer(t *testing.T, h http.HandlerFunc) *countingServer {
	t.Helper()
	cs := &countingServer{counts: map[string]int{}}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		cs.counts[r.URL.Path]++
		cs.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(cs.Server.Close)
	return cs
}

func (cs *countingServer) count(path string) int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.counts[path]
}

func testConfig(target string, words []string) Config {
	return Config{
		Target:            target,
		Wordlist:          words,
		Concurrency:       4,
		RequestsPerSecond: 1000,
		MaxRetries:        3,
		BackoffBase:       time.Millisecond,
		BackoffMax:        10 * time.Millisecond,
		Timeout:           5 * time.Second,
		Logger:            log.New(discardWriter{}, "", 0),
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func runScan(t *testing.T, cfg Config) *Result {
	t.Helper()
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	res, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

func findingByPath(res *Result, path string) *Finding {
	for i := range res.Findings {
		if res.Findings[i].Path == path {
			return &res.Findings[i]
		}
	}
	return nil
}

func TestEngineBasicClassification(t *testing.T) {
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index":
			fmt.Fprint(w, "welcome to the real index page")
		case "/redir":
			http.Redirect(w, r, "/index", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/protected":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	res := runScan(t, testConfig(srv.URL, []string{"index", "redir", "loop", "protected", "missing"}))

	cases := map[string]Classification{
		"/index":     ClassAvailable,
		"/redir":     ClassAvailable, // chain followed to /index
		"/loop":      ClassRedirect,  // chain never resolves
		"/protected": ClassAuthRequired,
		"/missing":   ClassNotFound,
	}
	for path, want := range cases {
		f := findingByPath(res, path)
		if f == nil {
			t.Fatalf("no finding for %s", path)
		}
		if f.Class != want {
			t.Errorf("%s: got %s want %s", path, f.Class, want)
		}
	}
	if f := findingByPath(res, "/redir"); f.RedirectTo == "" {
		t.Error("followed redirect should record final location")
	}
	// Sorted output.
	for i := 1; i < len(res.Findings); i++ {
		if res.Findings[i-1].Path > res.Findings[i].Path {
			t.Fatal("findings not sorted by path")
		}
	}
}

func TestEngineSoft404(t *testing.T) {
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real" {
			fmt.Fprint(w, "genuine content, definitely exists")
			return
		}
		// Everything unknown returns 200 with a "not found" page.
		fmt.Fprint(w, "<html><body>sorry, page not found</body></html>")
	})
	res := runScan(t, testConfig(srv.URL, []string{"real", "bogus1", "bogus2"}))
	if f := findingByPath(res, "/real"); f.Class != ClassAvailable {
		t.Errorf("/real: got %s", f.Class)
	}
	for _, p := range []string{"/bogus1", "/bogus2"} {
		if f := findingByPath(res, p); f.Class != ClassSoft404 {
			t.Errorf("%s: got %s want soft_404", p, f.Class)
		}
	}
}

func TestEngineRateLimitRetry(t *testing.T) {
	var calls atomic.Int64
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/flaky" {
			if calls.Add(1) <= 2 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			fmt.Fprint(w, "finally ok")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	res := runScan(t, testConfig(srv.URL, []string{"flaky"}))
	f := findingByPath(res, "/flaky")
	if f.Class != ClassAvailable {
		t.Fatalf("got %s want available", f.Class)
	}
	if got := srv.count("/flaky"); got != 3 {
		t.Fatalf("server saw %d requests, want exactly 3 (no amplification)", got)
	}
	if res.Stats.Retried != 2 {
		t.Fatalf("retried = %d, want 2", res.Stats.Retried)
	}
}

func TestEngineGlobalRateLimit(t *testing.T) {
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	cfg := testConfig(srv.URL, []string{"a", "b", "c", "d", "e", "g", "h", "i"})
	cfg.RequestsPerSecond = 20
	start := time.Now()
	runScan(t, cfg)
	elapsed := time.Since(start)
	// 8 paths + 1 baseline = 9 requests; first is instant, remaining 8
	// spaced at 50ms => >= ~350ms even with scheduling slack.
	if elapsed < 300*time.Millisecond {
		t.Fatalf("rate limit not enforced: 9 requests in %v", elapsed)
	}
}

func TestEngineOutOfScopeNeverRequested(t *testing.T) {
	other := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should never be seen")
	})
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	res := runScan(t, testConfig(srv.URL, []string{
		"local",
		other.URL + "/secret",  // unauthorized host:port
		"../escape",            // resolves outside... still same host, allowed
		"http://example.com/x", // foreign host
	}))
	total := 0
	for _, c := range other.counts {
		total += c
	}
	if total != 0 {
		t.Fatalf("out-of-scope server received %d requests", total)
	}
	if res.Stats.Rejected < 2 {
		t.Fatalf("rejected = %d, want >= 2", res.Stats.Rejected)
	}
}

func TestEngineDedup(t *testing.T) {
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "unique body for "+r.URL.Path)
	})
	res := runScan(t, testConfig(srv.URL, []string{
		"/Admin", "/admin/", "/ADMIN?x=1", "/admin?y=2",
	}))
	if got := srv.count("/Admin") + srv.count("/admin") + srv.count("/ADMIN"); got != 1 {
		t.Fatalf("canonical path requested %d times, want 1", got)
	}
	n := 0
	for _, f := range res.Findings {
		if f.Path == "/admin" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d findings for /admin, want 1", n)
	}
}

func TestEngineContentExpansion(t *testing.T) {
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index":
			fmt.Fprint(w, `<a href="/hidden">h</a> <a href="/hidden/">dup</a> <img src="/img.png">`)
		case "/hidden":
			fmt.Fprint(w, "secret page found via link")
		case "/img.png":
			fmt.Fprint(w, "binary-ish")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	cfg := testConfig(srv.URL, []string{"index", "hidden"})
	cfg.ExpandFromContent = true
	res := runScan(t, cfg)
	if f := findingByPath(res, "/hidden"); f == nil || f.Class != ClassAvailable {
		t.Fatalf("/hidden not discovered: %+v", f)
	}
	if f := findingByPath(res, "/img.png"); f == nil || f.Class != ClassAvailable {
		t.Fatalf("/img.png not discovered: %+v", f)
	}
	// /hidden appears in wordlist AND in content: requested exactly once.
	if got := srv.count("/hidden"); got != 1 {
		t.Fatalf("/hidden requested %d times, want 1", got)
	}
}

func TestEngineAuthAndRedaction(t *testing.T) {
	const secret = "s3cr3t-token"
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/protected" {
			if r.Header.Get("X-Api-Key") != secret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, "protected content")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	// Without credentials: identified as auth-required, not "unavailable".
	res := runScan(t, testConfig(srv.URL, []string{"protected"}))
	if f := findingByPath(res, "/protected"); f.Class != ClassAuthRequired {
		t.Fatalf("no-cred: got %s want auth_required", f.Class)
	}
	// With credentials: available; secret must not leak into results.
	cfg := testConfig(srv.URL, []string{"protected"})
	cfg.Headers = map[string]string{"X-Api-Key": secret}
	res = runScan(t, cfg)
	if f := findingByPath(res, "/protected"); f.Class != ClassAvailable {
		t.Fatalf("with-cred: got %s want available", f.Class)
	}
	blob, _ := json.Marshal(res)
	if strings.Contains(string(blob), secret) {
		t.Fatal("secret leaked into result JSON")
	}
	if got := cfg.RedactedHeaders()["X-Api-Key"]; got != redactedValue {
		t.Fatalf("redaction = %q", got)
	}
}

func TestEngineDeterministicAcrossConcurrency(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a", "/b", "/c":
			fmt.Fprint(w, "content of "+r.URL.Path)
		case "/r":
			http.Redirect(w, r, "/a", http.StatusMovedPermanently)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
	words := []string{"a", "b", "c", "r", "x1", "x2", "x3", "x4"}
	srv := newCountingServer(t, handler)
	var ref string
	for _, conc := range []int{1, 3, 8} {
		cfg := testConfig(srv.URL, words)
		cfg.Concurrency = conc
		res := runScan(t, cfg)
		blob, _ := json.Marshal(res.Findings)
		if ref == "" {
			ref = string(blob)
		} else if string(blob) != ref {
			t.Fatalf("concurrency %d produced different findings:\n%s\nvs\n%s", conc, blob, ref)
		}
	}
}

func TestEngineResume(t *testing.T) {
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		fmt.Fprint(w, "body of "+r.URL.Path)
	})
	var words []string
	for i := 0; i < 20; i++ {
		words = append(words, fmt.Sprintf("p%02d", i))
	}
	stateFile := t.TempDir() + "/state.jsonl"

	// First run: cancel partway through.
	cfg := testConfig(srv.URL, words)
	cfg.StateFile = stateFile
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	eng.Run(ctx) //nolint:errcheck // expected to be interrupted

	// Second run: resume to completion.
	res := runScan(t, cfg)
	if len(res.Findings) != 20 {
		t.Fatalf("got %d findings, want 20 (no omissions)", len(res.Findings))
	}
	seen := map[string]bool{}
	for _, f := range res.Findings {
		if seen[f.Path] {
			t.Fatalf("duplicate finding for %s", f.Path)
		}
		seen[f.Path] = true
		if f.Class != ClassAvailable {
			t.Fatalf("%s: got %s want available", f.Path, f.Class)
		}
	}
	if res.Stats.Resumed == 0 {
		t.Fatal("expected some paths to be resumed from checkpoint")
	}
	// No path was fully requested twice across runs except those in-flight
	// at cancellation; every path was requested at least once.
	for _, w := range words {
		if srv.count("/"+w) < 1 {
			t.Fatalf("/%s never requested", w)
		}
	}
}
