package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
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

// total returns how many requests the server received in total.
func (cs *countingServer) total() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	n := 0
	for _, c := range cs.counts {
		n += c
	}
	return n
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

// A real page whose body is DIFFERENT from the hint page but happens to be
// exactly the same size must be classified available — equivalence requires
// byte-identical bodies, never just equal length.
func TestEngineSoft404SameLengthRealPage(t *testing.T) {
	const hint = "<html><body>sorry, page not found</body></html>"
	// Same length as hint, different content.
	realBody := "<html><body>REAL DATA: hello, world!</body></html>"
	for len(realBody) < len(hint) {
		realBody += "!"
	}
	realBody = realBody[:len(hint)]
	if len(realBody) != len(hint) {
		t.Fatalf("test setup: bodies must be equal length (%d vs %d)", len(realBody), len(hint))
	}
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real" {
			fmt.Fprint(w, realBody)
			return
		}
		fmt.Fprint(w, hint)
	})
	res := runScan(t, testConfig(srv.URL, []string{"real", "bogus"}))
	if f := findingByPath(res, "/real"); f.Class != ClassAvailable {
		t.Errorf("/real (same length, different body): got %s want available", f.Class)
	}
	if f := findingByPath(res, "/bogus"); f.Class != ClassSoft404 {
		t.Errorf("/bogus (identical body): got %s want soft_404", f.Class)
	}
}

// A redirect chain that ends on the hint page must be classified exactly
// like directly visiting that page (soft_404), and a chain ending on a hard
// 404 like a direct 404 (not_found) — going through redirects must never
// make an unavailable page look real.
func TestEngineRedirectToUnavailable(t *testing.T) {
	const hint = "<html><body>sorry, page not found</body></html>"
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/to-hint":
			http.Redirect(w, r, "/hint", http.StatusFound)
		case "/hint":
			fmt.Fprint(w, hint)
		case "/to-404":
			http.Redirect(w, r, "/gone", http.StatusFound)
		case "/gone":
			w.WriteHeader(http.StatusNotFound)
		case "/to-real":
			http.Redirect(w, r, "/real", http.StatusFound)
		case "/real":
			fmt.Fprint(w, "genuine content here")
		default:
			// Unknown paths serve the hint page directly with 200.
			fmt.Fprint(w, hint)
		}
	})
	res := runScan(t, testConfig(srv.URL, []string{"to-hint", "hint", "to-404", "gone", "to-real", "real"}))
	cases := map[string]Classification{
		"/hint":    ClassSoft404, // direct access to hint page
		"/to-hint": ClassSoft404, // chain landing on hint page: same verdict
		"/gone":    ClassNotFound,
		"/to-404":  ClassNotFound, // chain landing on hard 404
		"/real":    ClassAvailable,
		"/to-real": ClassAvailable, // chain landing on real content
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
}

// When the target answers unknown paths with a REDIRECT to a hint page, the
// baseline probe must follow that chain; otherwise every soft 404 would be
// misclassified as available.
func TestEngineBaselineFollowsRedirect(t *testing.T) {
	const hint = "<html><body>sorry, page not found</body></html>"
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/real":
			fmt.Fprint(w, "genuine content here")
		case "/not-found":
			fmt.Fprint(w, hint)
		default:
			http.Redirect(w, r, "/not-found", http.StatusFound)
		}
	})
	res := runScan(t, testConfig(srv.URL, []string{"real", "bogus1", "bogus2"}))
	if f := findingByPath(res, "/real"); f.Class != ClassAvailable {
		t.Errorf("/real: got %s want available", f.Class)
	}
	for _, p := range []string{"/bogus1", "/bogus2"} {
		if f := findingByPath(res, p); f.Class != ClassSoft404 {
			t.Errorf("%s: got %s want soft_404 (baseline must follow redirects)", p, f.Class)
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
		"/Admin", "/admin/", "/ADMIN?x=1", "/admin?y=2", "admin#frag",
	}))
	// Exactly one request for the canonical path, and no other path was
	// requested at all (the server saw only the baseline + this one).
	if got := srv.total(); got != 2 {
		t.Fatalf("server received %d requests, want 2 (baseline + one canonical)", got)
	}
	if got := srv.count("/admin"); got != 1 {
		t.Fatalf("canonical path requested %d times, want 1", got)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("%d findings, want exactly 1: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Path != "/admin" {
		t.Fatalf("finding path = %q, want /admin", res.Findings[0].Path)
	}
	if res.Stats.Submitted != 1 {
		t.Fatalf("submitted = %d, want 1", res.Stats.Submitted)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var hits atomic.Int64
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Deterministic interruption: once the server has served a few
		// requests, cancel the scan shortly AFTER in-flight requests had
		// time to complete (handler sleep is 10ms). This guarantees some
		// paths are confirmed done and the rest are still pending,
		// regardless of machine speed.
		if hits.Add(1) == 5 {
			go func() {
				time.Sleep(25 * time.Millisecond)
				cancel()
			}()
		}
		time.Sleep(10 * time.Millisecond)
		fmt.Fprint(w, "body of "+r.URL.Path)
	})
	var words []string
	for i := 0; i < 20; i++ {
		words = append(words, fmt.Sprintf("p%02d", i))
	}
	stateFile := t.TempDir() + "/state.jsonl"

	// First run: interrupted partway through.
	cfg := testConfig(srv.URL, words)
	cfg.StateFile = stateFile
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
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

// Repeatedly interrupting and resuming must converge to exactly the same
// result as one uninterrupted run: no duplicates, no omissions, and the
// final finding set must be byte-identical across repetitions.
func TestEngineResumeRepeatedInterrupts(t *testing.T) {
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		fmt.Fprint(w, "body of "+r.URL.Path)
	})
	var words []string
	for i := 0; i < 30; i++ {
		words = append(words, fmt.Sprintf("p%02d", i))
	}

	// Reference: single uninterrupted run with its own state file.
	refCfg := testConfig(srv.URL, words)
	refCfg.StateFile = t.TempDir() + "/ref.jsonl"
	ref := runScan(t, refCfg)
	refBlob, _ := json.Marshal(ref.Findings)

	// Interrupted run: resume with a fresh engine (process restart) until
	// completion, however many rounds it takes.
	stateFile := t.TempDir() + "/state.jsonl"
	cfg := testConfig(srv.URL, words)
	cfg.StateFile = stateFile
	var res *Result
	for round := 0; round < 20; round++ {
		eng, err := NewEngine(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		res, err = eng.Run(ctx)
		cancel()
		if err == nil {
			break
		}
		if err != context.DeadlineExceeded {
			t.Fatalf("round %d: unexpected error %v", round, err)
		}
	}
	if res == nil {
		t.Fatal("scan never completed after repeated resumes")
	}
	gotBlob, _ := json.Marshal(res.Findings)
	if string(gotBlob) != string(refBlob) {
		t.Fatalf("resumed findings differ from uninterrupted run:\n%s\nvs\n%s", gotBlob, refBlob)
	}
	seen := map[string]bool{}
	for _, f := range res.Findings {
		if seen[f.Path] {
			t.Fatalf("duplicate finding for %s", f.Path)
		}
		seen[f.Path] = true
	}
	if len(seen) != len(words) {
		t.Fatalf("got %d unique findings, want %d", len(seen), len(words))
	}
}

// Re-running a completed scan against the same checkpoint must be a no-op:
// identical findings and zero additional requests for wordlist paths.
func TestEngineResumeCompletedRunIsNoop(t *testing.T) {
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "body of "+r.URL.Path)
	})
	words := []string{"a", "b", "c", "d"}
	cfg := testConfig(srv.URL, words)
	cfg.StateFile = t.TempDir() + "/state.jsonl"

	first := runScan(t, cfg)
	before := srv.total()
	second := runScan(t, cfg)

	b1, _ := json.Marshal(first.Findings)
	b2, _ := json.Marshal(second.Findings)
	if string(b1) != string(b2) {
		t.Fatalf("re-run findings differ:\n%s\nvs\n%s", b1, b2)
	}
	// Only the baseline probe may hit the server again.
	if got := srv.total() - before; got != 1 {
		t.Fatalf("completed re-run issued %d extra requests, want 1 (baseline only)", got)
	}
	if second.Stats.Resumed != len(words) {
		t.Fatalf("resumed = %d, want %d", second.Stats.Resumed, len(words))
	}
}

// A finding persisted WITHOUT its done marker (crash in between) is
// unconfirmed: the path must be re-probed and the fresh result recorded —
// the stale checkpoint finding must not shadow it.
func TestEngineResumeUnconfirmedFindingReprobed(t *testing.T) {
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "fresh body of "+r.URL.Path)
	})
	stateFile := t.TempDir() + "/state.jsonl"

	keyOf := func(path string) string {
		u, err := NormalizeURL(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		return CanonicalKey(u)
	}
	staleKey := keyOf("/flaky")
	doneKey := keyOf("/old")
	stale := Finding{Path: "/flaky", URL: staleKey, Class: ClassError, StatusCode: 503}
	confirmed := Finding{Path: "/old", URL: doneKey, Class: ClassAvailable, StatusCode: 200, ContentLength: 3}

	f, err := os.Create(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, ev := range []stateEvent{
		{Op: "discover", Key: staleKey},
		{Op: "finding", Key: staleKey, Finding: &stale}, // crash before done
		{Op: "discover", Key: doneKey},
		{Op: "finding", Key: doneKey, Finding: &confirmed},
		{Op: "done", Key: doneKey},
	} {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	cfg := testConfig(srv.URL, []string{"flaky", "old"})
	cfg.StateFile = stateFile
	res := runScan(t, cfg)

	if got := srv.count("/flaky"); got != 1 {
		t.Fatalf("/flaky requested %d times, want 1 (unconfirmed must be re-probed)", got)
	}
	if got := srv.count("/old"); got != 0 {
		t.Fatalf("/old requested %d times, want 0 (confirmed done)", got)
	}
	fres := findingByPath(res, "/flaky")
	if fres == nil || fres.Class != ClassAvailable {
		t.Fatalf("/flaky: got %+v, want fresh available result", fres)
	}
	if f := findingByPath(res, "/old"); f == nil || f.Class != ClassAvailable {
		t.Fatalf("/old: got %+v, want confirmed checkpoint finding", f)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("got %d findings, want exactly 2 (no duplicates)", len(res.Findings))
	}
}

// Discovery set, classification and ordering must be identical at low and
// high concurrency, with dedup and completion tracking intact for a
// candidate set in the thousands.
func TestEngineDeterministicLargeWordlist(t *testing.T) {
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "body of "+r.URL.Path)
	})
	var words []string
	for i := 0; i < 1200; i++ {
		words = append(words, fmt.Sprintf("item-%04d", i))
		// Duplicate spellings of the same path: case, trailing slash, query.
		words = append(words, fmt.Sprintf("/ITEM-%04d/", i), fmt.Sprintf("item-%04d?x=%d", i, i))
	}
	var ref string
	for _, conc := range []int{1, 16} {
		cfg := testConfig(srv.URL, words)
		cfg.Concurrency = conc
		res := runScan(t, cfg)
		if len(res.Findings) != 1200 {
			t.Fatalf("concurrency %d: got %d findings, want 1200", conc, len(res.Findings))
		}
		seen := map[string]bool{}
		for _, f := range res.Findings {
			if seen[f.Path] {
				t.Fatalf("concurrency %d: duplicate finding %s", conc, f.Path)
			}
			seen[f.Path] = true
			if f.Class != ClassAvailable {
				t.Fatalf("concurrency %d: %s got %s", conc, f.Path, f.Class)
			}
		}
		blob, _ := json.Marshal(res.Findings)
		if ref == "" {
			ref = string(blob)
		} else if string(blob) != ref {
			t.Fatalf("concurrency %d produced different findings", conc)
		}
	}
	// Each canonical path requested exactly once across both runs:
	// 2 runs * (1200 paths + 1 baseline).
	if got := srv.total(); got != 2*1201 {
		t.Fatalf("server received %d requests, want %d (no duplicates)", got, 2*1201)
	}
}
