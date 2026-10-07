package discovery

import (
	"bytes"
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

// totalHits reports every request path (and raw request URI) the server
// received, so tests can prove that equivalent spellings never cause more
// than one physical request per canonical path.
func (cs *countingServer) totalHits() map[string]int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := make(map[string]int, len(cs.counts))
	for k, v := range cs.counts {
		out[k] = v
	}
	return out
}

// resetCounts zeroes the recorded hit counts (does not affect the server).
func (cs *countingServer) resetCounts() {
	cs.mu.Lock()
	cs.counts = map[string]int{}
	cs.mu.Unlock()
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
		"/Admin", "/admin/", "/ADMIN?x=1", "/admin?y=2", "admin?z=3",
	}))
	// Exactly one physical request for the canonical path: verify by the
	// TOTAL request count (excluding the fixed soft-404 baseline probe),
	// not by looking up pre-guessed spellings (a %3F-escaped query would
	// otherwise hide duplicate hits).
	total := 0
	for p, c := range srv.totalHits() {
		if !strings.HasPrefix(p, "/.endscan-baseline") {
			total += c
		}
	}
	if total != 1 {
		t.Fatalf("target received %d requests for one canonical path, want 1: %v", total, srv.totalHits())
	}
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
	// The surviving finding carries no query string and the canonical URL.
	if f := findingByPath(res, "/admin"); f != nil && strings.Contains(f.URL, "?") {
		t.Fatalf("canonical finding URL must not carry a query: %q", f.URL)
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

// gateServer hands out one channel per word-path request: a handler blocks
// on its channel until the test closes that channel (allowing exactly that
// response to complete) or until the client gives up (scan cancelled). The
// baseline probe is always answered immediately. This makes resume tests
// deterministic without any sleeps or timing assumptions.
type gateServer struct {
	*countingServer
	mu      sync.Mutex
	arrived []chan struct{} // one gate per word-path request, in arrival order
	abort   chan struct{}   // closed by abortAll: every parked handler exits
	auto    bool            // after abortAll, answer every request normally
}

func newGateServer(t *testing.T) *gateServer {
	gs := &gateServer{abort: make(chan struct{})}
	cs := &countingServer{counts: map[string]int{}}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		cs.counts[r.URL.Path]++
		cs.mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/"+baselinePrefix) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gs.mu.Lock()
		auto := gs.auto
		gs.mu.Unlock()
		if auto {
			fmt.Fprint(w, "body of "+r.URL.Path)
			return
		}
		gate := make(chan struct{})
		gs.mu.Lock()
		gs.arrived = append(gs.arrived, gate)
		gs.mu.Unlock()
		select {
		case <-gate:
			fmt.Fprint(w, "body of "+r.URL.Path)
		case <-gs.abort:
			// Scan aborted: end the response NOW on a fresh connection so no
			// half-used keep-alive connection is ever pooled and reused.
			w.Header().Set("Connection", "close")
			http.Error(w, "aborted", http.StatusServiceUnavailable)
		case <-r.Context().Done():
			// Client cancelled mid-flight: this response never reaches the
			// engine and the path MUST NOT be recorded as complete.
		}
	}))
	gs.countingServer = cs
	t.Cleanup(cs.Server.Close)
	t.Cleanup(gs.releaseAll)
	return gs
}

// awaitGate waits for the nth word-path request (0-based) to be parked and
// returns its release gate.
func (gs *gateServer) awaitGate(t *testing.T, n int) chan struct{} {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		gs.mu.Lock()
		if len(gs.arrived) > n {
			g := gs.arrived[n]
			gs.mu.Unlock()
			return g
		}
		gs.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("gate %d never arrived", n)
	return nil
}

func (gs *gateServer) abortAll() {
	select {
	case <-gs.abort:
	default:
		close(gs.abort)
	}
	// Subsequent runs (simulating a process restart against a healthy
	// target) are answered immediately.
	gs.mu.Lock()
	gs.auto = true
	gs.mu.Unlock()
}

func (gs *gateServer) releaseAll() {
	gs.abortAll()
	gs.mu.Lock()
	defer gs.mu.Unlock()
	for _, g := range gs.arrived {
		select {
		case <-g:
		default:
			close(g)
		}
	}
	gs.arrived = nil
}

const baselinePrefix = ".endscan-baseline-3f9a1c7e"

// TestEngineResumeCompletionSemantics proves, without timing assumptions,
// that after cancellation only confirmed-complete paths are skipped: the
// path parked at cancellation is re-probed, the recovered set has no
// duplicates or omissions, and a third run is an idempotent no-op.
func TestEngineResumeCompletionSemantics(t *testing.T) {
	const n = 8
	const completeBeforeCancel = 3
	srv := newGateServer(t)
	var words []string
	for i := 0; i < n; i++ {
		words = append(words, fmt.Sprintf("q%02d", i))
	}
	stateFile := t.TempDir() + "/state.jsonl"
	cfg := testConfig(srv.URL, words)
	cfg.Concurrency = 1 // serialize: one parked request at a time, in seed order
	cfg.StateFile = stateFile

	// --- Run 1: complete exactly completeBeforeCancel paths, cancel on the
	// next one while its response is held by the gate.
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		_, e := eng.Run(ctx)
		runErr <- e
	}()
	for i := 0; i < completeBeforeCancel; i++ {
		close(srv.awaitGate(t, i)) // let q%02d(i) finish and be marked done
	}
	// q{completeBeforeCancel} is now parked and unconfirmed; cancel on it.
	srv.awaitGate(t, completeBeforeCancel)
	cancel()
	<-runErr
	// Release every parked handler and switch the target to normal answering
	// for the resumed runs (simulating a process restart).
	srv.abortAll()

	// Checkpoint must contain exactly completeBeforeCancel done keys.
	st, err := OpenStateStore(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	doneBefore := st.done
	pending := st.Pending()
	st.Close()
	if len(doneBefore) != completeBeforeCancel {
		t.Fatalf("done keys = %d, want %d (only confirmed paths)", len(doneBefore), completeBeforeCancel)
	}
	if len(pending) == 0 {
		t.Fatal("expected discovered-but-undone keys to survive the checkpoint")
	}
	var confirmedPaths []string
	for i := 0; i < completeBeforeCancel; i++ {
		confirmedPaths = append(confirmedPaths, fmt.Sprintf("/q%02d", i))
	}
	for _, p := range confirmedPaths {
		if !doneBefore[srv.URL+p] {
			t.Fatalf("confirmed path %s missing from done set", p)
		}
	}

	// --- Run 2: resume to completion (fresh engine, same checkpoint).
	res := runScan(t, cfg)
	if len(res.Findings) != n {
		t.Fatalf("got %d findings, want %d (no omissions)", len(res.Findings), n)
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
	for i := 0; i < n; i++ {
		p := fmt.Sprintf("/q%02d", i)
		if !seen[p] {
			t.Fatalf("missing finding for %s", p)
		}
	}
	if res.Stats.Resumed != completeBeforeCancel {
		t.Fatalf("resumed = %d, want exactly %d confirmed paths", res.Stats.Resumed, completeBeforeCancel)
	}
	// Confirmed paths were never re-requested after their confirmation; the
	// parked one was re-probed at least once.
	for i := 0; i < completeBeforeCancel; i++ {
		p := fmt.Sprintf("/q%02d", i)
		if got := srv.count(p); got != 1 {
			t.Fatalf("confirmed %s hit %d times, want exactly 1 (zero duplicate requests)", p, got)
		}
	}
	if got := srv.count(fmt.Sprintf("/q%02d", completeBeforeCancel)); got < 2 {
		t.Fatalf("unconfirmed parked path should be re-probed on resume, hits=%d", got)
	}

	// --- Run 3: repeat against the completed checkpoint; result identical
	// and the server must not see a single extra word-path request.
	before := map[string]int{}
	for k, v := range srv.totalHits() {
		before[k] = v
	}
	res3 := runScan(t, cfg)
	if len(res3.Findings) != n {
		t.Fatalf("repeat run: got %d findings, want %d", len(res3.Findings), n)
	}
	if res3.Stats.Resumed != n {
		t.Fatalf("repeat run: resumed = %d, want %d", res3.Stats.Resumed, n)
	}
	for p, c := range srv.totalHits() {
		if strings.HasPrefix(p, "/"+baselinePrefix) {
			continue // baseline is intentionally re-probed each run
		}
		if c != before[p] {
			t.Fatalf("repeat run issued duplicate requests for %s: %d -> %d", p, before[p], c)
		}
	}
}

// TestEngineRedirectToHintPage: unknown paths 302-redirect to a fixed hint
// page (200). The baseline probe must follow the chain and learn the hint
// body, so a chain landing on the hint page is classified exactly like
// requesting the hint page directly (soft_404), while a real page reached
// through a redirect stays available.
func TestEngineRedirectToHintPage(t *testing.T) {
	const hint = "<html>this page moved or is missing, sorry</html>"
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/real":
			fmt.Fprint(w, "genuine real content that exists")
		case "/alias":
			http.Redirect(w, r, "/real", http.StatusFound)
		case "/__hint":
			fmt.Fprint(w, hint)
		default:
			// Every unknown path (including the fixed baseline path and
			// the bogus wordlist entries) redirects to the hint page.
			http.Redirect(w, r, "/__hint", http.StatusFound)
		}
	})
	res := runScan(t, testConfig(srv.URL, []string{"real", "alias", "bogus1", "bogus2"}))
	cases := map[string]Classification{
		"/real":   ClassAvailable,
		"/alias":  ClassAvailable, // chain ends on the real page
		"/bogus1": ClassSoft404,   // chain ends on the hint page
		"/bogus2": ClassSoft404,
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
	// Direct access to the hint page must agree with the redirect verdict.
	res2 := runScan(t, testConfig(srv.URL, []string{"/__hint"}))
	if f := findingByPath(res2, "/__hint"); f == nil || f.Class != ClassSoft404 {
		t.Fatalf("direct hint access: got %+v want soft_404", f)
	}
}

// TestEngineRedirectToHard404: a chain landing on a hard 404 is not_found,
// same as visiting the 404 target directly; it must never look available.
func TestEngineRedirectToHard404(t *testing.T) {
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dead":
			http.Redirect(w, r, "/missing-target", http.StatusFound)
		case "/missing-target":
			w.WriteHeader(http.StatusNotFound)
		case "/alive":
			fmt.Fprint(w, "ok")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	res := runScan(t, testConfig(srv.URL, []string{"dead", "missing-target", "alive"}))
	for _, p := range []string{"/dead", "/missing-target"} {
		if f := findingByPath(res, p); f == nil || f.Class != ClassNotFound {
			t.Fatalf("%s: got %+v want not_found", p, f)
		}
	}
	if f := findingByPath(res, "/alive"); f == nil || f.Class != ClassAvailable {
		t.Fatalf("/alive: got %+v want available", f)
	}
}

// TestEngineLargeSetConcurrencyInvariant scales the candidate set past a
// thousand unique paths plus many case/trailing-slash/query duplicates and
// verifies that small and large concurrency produce byte-identical result
// sets, classifications and ordering, with correct dedup (one physical
// request per canonical path) and an exact done set.
func TestEngineLargeSetConcurrencyInvariant(t *testing.T) {
	const unique = 1200
	const hint = "ERROR 404: this exact fixed hint page is served for gaps"
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/ok"):
			fmt.Fprint(w, "real content for "+p)
		case strings.HasPrefix(p, "/deny"):
			w.WriteHeader(http.StatusForbidden)
		case strings.HasPrefix(p, "/auth"):
			w.WriteHeader(http.StatusUnauthorized)
		case strings.HasPrefix(p, "/gone"):
			w.WriteHeader(http.StatusGone)
		case p == "/real-same-size":
			// Genuine page padded to the SAME size as the fixed hint page,
			// different bytes: must stay available, never soft_404.
			body := bytes.Repeat([]byte("Z"), len(hint))
			w.Write(body)
		default:
			fmt.Fprint(w, hint) // gaps return the fixed hint page (200)
		}
	})

	// Unique candidates: ok*, deny*, auth*, gone*, gaps*, one same-size real.
	var words []string
	for i := 0; i < 400; i++ {
		words = append(words, fmt.Sprintf("/ok%04d", i))
	}
	for i := 0; i < 200; i++ {
		words = append(words, fmt.Sprintf("/deny%04d", i))
	}
	for i := 0; i < 100; i++ {
		words = append(words, fmt.Sprintf("/auth%04d", i))
	}
	for i := 0; i < 100; i++ {
		words = append(words, fmt.Sprintf("/gone%04d", i))
	}
	for i := 0; i < 399; i++ {
		words = append(words, fmt.Sprintf("/gap%04d", i))
	}
	words = append(words, "/real-same-size")

	// Duplicate spellings for a subset, deliberately out of order.
	dup := []string{
		"/OK0000/", "/ok0000?a=1", "/Ok0000?b=2&a=9",
		"/DENY0007/", "/deny0007?x=",
		"/GAP0003?z", "/gap0003/", "/GaP0003#frag",
		"/real-same-size?cache=bust", "/Real-Same-Size/",
	}
	// Shuffle duplicates into the list.
	words = append(words, dup...)

	uniqueCount := unique
	run := func(conc int) string {
		cfg := testConfig(srv.URL, words)
		cfg.Concurrency = conc
		cfg.RequestsPerSecond = 100000 // effectively unlimited; test is not about pacing
		res := runScan(t, cfg)
		if len(res.Findings) != uniqueCount {
			t.Fatalf("conc=%d: findings=%d want %d", conc, len(res.Findings), uniqueCount)
		}
		// Exactly one class per canonical path and stable ordering.
		for i := 1; i < len(res.Findings); i++ {
			if res.Findings[i-1].Path >= res.Findings[i].Path {
				t.Fatalf("conc=%d: order violation at %d: %q !< %q", conc, i,
					res.Findings[i-1].Path, res.Findings[i].Path)
			}
		}
		blob, _ := json.Marshal(res.Findings)
		return string(blob)
	}
	ref := run(1)
	for _, conc := range []int{8, 32} {
		if got := run(conc); got != ref {
			t.Fatalf("concurrency %d result differs from concurrency 1", conc)
		}
	}

	// Isolated final run: reset counters, then every canonical word path
	// must be served exactly once (the fixed baseline probe excepted).
	srv.resetCounts()
	if got := run(32); got != ref {
		t.Fatal("isolated high-concurrency run differs")
	}
	hits := srv.totalHits()
	wordHits := 0
	for p, c := range hits {
		if strings.HasPrefix(p, "/"+baselinePrefix) {
			if c != 1 {
				t.Fatalf("baseline hit %d times, want 1", c)
			}
			continue
		}
		if c != 1 {
			t.Fatalf("canonical path %s requested %d times in one run, want exactly 1", p, c)
		}
		wordHits++
	}
	if wordHits != uniqueCount {
		t.Fatalf("server saw %d distinct canonical paths, want %d", wordHits, uniqueCount)
	}
	// Spot-check dedup keys.
	for _, p := range []string{"/ok0000", "/deny0007", "/gap0003", "/real-same-size"} {
		if got := srv.count(p); got != 1 {
			t.Fatalf("%s requested %d times, want exactly 1", p, got)
		}
	}
	// The equal-size real page survived strict soft-404 equivalence.
	if f := findFindingBlob(ref, "/real-same-size"); f != string(ClassAvailable) {
		t.Fatalf("/real-same-size class in reference = %q want available", f)
	}
}

func findFindingBlob(blob, path string) string {
	var fs []Finding
	if err := json.Unmarshal([]byte(blob), &fs); err != nil {
		return ""
	}
	for _, f := range fs {
		if f.Path == path {
			return string(f.Class)
		}
	}
	return ""
}

// TestEngineRepeatableAcrossRuns runs the same wordlist against the same
// target multiple times as independent scans and requires identical
// findings each time, with exactly one physical request per canonical path
// per run. Covers the fixed hint page plus a real page padded to the same
// size, so this also pins strict soft-404 equivalence end to end.
func TestEngineRepeatableAcrossRuns(t *testing.T) {
	hint := []byte("FIXED-HINT-PAGE-0123456789")
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/real":
			fmt.Fprint(w, "a genuinely different real page body here!!")
		case "/samesize":
			w.Write(bytes.Repeat([]byte("Q"), len(hint))) // equal size, != hint
		default:
			w.Write(hint)
		}
	})
	words := []string{
		"/real", "/Real/", "/REAL?x=1",
		"/samesize", "/SameSize?z=9",
		"/gap1", "/gap1/", "/GAP1?a=b",
		"/gap2",
	}
	var ref string
	for run := 0; run < 4; run++ {
		cfg := testConfig(srv.URL, words)
		cfg.RequestsPerSecond = 100000
		srv.resetCounts()
		res := runScan(t, cfg)
		blob, _ := json.Marshal(res.Findings)
		if ref == "" {
			ref = string(blob)
		} else if string(blob) != ref {
			t.Fatalf("run %d findings differ:\n%s\nvs\n%s", run, blob, ref)
		}
		// Exactly one request per canonical path in this run.
		for p, c := range srv.totalHits() {
			if strings.HasPrefix(p, "/"+baselinePrefix) {
				continue
			}
			if c != 1 {
				t.Fatalf("run %d: %s requested %d times, want 1", run, p, c)
			}
		}
	}
	// Final classification spot checks.
	cfg := testConfig(srv.URL, words)
	res := runScan(t, cfg)
	want := map[string]Classification{
		"/real":     ClassAvailable,
		"/samesize": ClassAvailable, // equal size but different body
		"/gap1":     ClassSoft404,
		"/gap2":     ClassSoft404,
	}
	for p, c := range want {
		if f := findingByPath(res, p); f == nil || f.Class != c {
			t.Fatalf("%s: got %+v want %s", p, f, c)
		}
	}
}

// TestEngineResumeReplaysExpansionPending seeds a checkpoint with one done
// wordlist key and one DISCOVERED-but-not-done key that came from content
// expansion (not present in the wordlist), then resumes. The orphan pending
// key must be re-enqueued and completed without duplication.
func TestEngineResumeReplaysExpansionPending(t *testing.T) {
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/done-key":
			fmt.Fprint(w, "finished earlier")
		case "/expanded-orphan":
			fmt.Fprint(w, "found only via expansion previously")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	stateFile := t.TempDir() + "/state.jsonl"
	st, err := OpenStateStore(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	doneKey := srv.URL + "/done-key"
	orphan := srv.URL + "/expanded-orphan"
	st.MarkDiscovered(doneKey)
	st.RecordFinding(doneKey, Finding{Path: "/done-key", URL: doneKey, Class: ClassAvailable, StatusCode: 200})
	st.MarkDone(doneKey)
	st.MarkDiscovered(orphan) // expansion-sourced, unfinished
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Resume with a wordlist containing the done key only (and an unrelated
	// new one); the orphan must be picked up from pending.
	cfg := testConfig(srv.URL, []string{"done-key", "fresh"})
	cfg.StateFile = stateFile
	res := runScan(t, cfg)
	want := map[string]Classification{
		"/done-key":        ClassAvailable,
		"/expanded-orphan": ClassAvailable,
		"/fresh":           ClassNotFound,
	}
	if len(res.Findings) != len(want) {
		t.Fatalf("findings=%d want %d: %+v", len(res.Findings), len(want), res.Findings)
	}
	for p, c := range want {
		f := findingByPath(res, p)
		if f == nil {
			t.Fatalf("missing finding %s", p)
		}
		if f.Class != c {
			t.Errorf("%s: got %s want %s", p, f.Class, c)
		}
	}
	if res.Stats.Resumed < 1 {
		t.Fatal("expected the done key to count as resumed")
	}
	// Orphan probed exactly once after resume; done key never re-requested
	// (wordlist seed counts it resumed and skips).
	if got := srv.count("/expanded-orphan"); got != 1 {
		t.Fatalf("orphan requested %d times, want 1", got)
	}
	if got := srv.count("/done-key"); got != 0 {
		t.Fatalf("previously done key requested %d times on resume, want 0", got)
	}
}

// TestEngineRedirectFollowDisabled: MaxRedirects<0 means do not follow. A
// redirect must stay ClassRedirect (never silently treated as available),
// and its redirect_to is the declared location.
func TestEngineRedirectFollowDisabled(t *testing.T) {
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jump" {
			http.Redirect(w, r, "/real", http.StatusFound)
			return
		}
		fmt.Fprint(w, "body")
	})
	cfg := testConfig(srv.URL, []string{"jump"})
	cfg.MaxRedirects = -1
	res := runScan(t, cfg)
	f := findingByPath(res, "/jump")
	if f == nil {
		t.Fatal("no finding /jump")
	}
	if f.Class != ClassRedirect {
		t.Fatalf("got %s want redirect", f.Class)
	}
	if f.RedirectTo == "" {
		t.Fatal("redirect_to must record the location")
	}
}
