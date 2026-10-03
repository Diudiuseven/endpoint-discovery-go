package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Diudiuseven/endpoint-discovery-go/internal/checkpoint"
	"github.com/Diudiuseven/endpoint-discovery-go/internal/config"
)

// ---------- helpers ----------

type counters struct {
	mu sync.Mutex
	m  map[string]int
}

func newCounters() *counters { return &counters{m: map[string]int{}} }

func (c *counters) inc(path string) {
	c.mu.Lock()
	c.m[path]++
	c.mu.Unlock()
}

func (c *counters) get(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[path]
}

func (c *counters) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, v := range c.m {
		n += v
	}
	return n
}

func writeWordlist(t *testing.T, dir string, lines []string) string {
	t.Helper()
	p := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func baseConfig(target, wl, cp string) config.Config {
	cfg := config.Defaults()
	cfg.Targets = []string{target}
	cfg.Wordlist = wl
	cfg.Checkpoint = cp
	cfg.Output = ""
	cfg.RateLimit = 1000
	cfg.PerTargetConcurrency = 4
	cfg.MaxRetries = 3
	cfg.RetryBackoffMS = 5
	return cfg
}

func runEngine(t *testing.T, cfg config.Config) []checkpoint.Result {
	t.Helper()
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := eng.Run(ctx); err != nil {
		t.Fatal(err)
	}
	return eng.Results()
}

func gradeMap(results []checkpoint.Result) map[string]string {
	m := map[string]string{}
	for _, r := range results {
		m[r.Identity] = r.Grade
	}
	return m
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition timed out")
}

// ---------- tests ----------

func TestDiscoveryGrades(t *testing.T) {
	c := newCounters()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.inc(r.URL.Path)
		switch r.URL.Path {
		case "/real":
			fmt.Fprint(w, "real content")
		case "/go":
			http.Redirect(w, r, "/go2", http.StatusFound)
		case "/go2":
			http.Redirect(w, r, "/landing", http.StatusFound)
		case "/landing":
			fmt.Fprint(w, "landing page content")
		case "/links":
			fmt.Fprint(w, `<html><body>
				<a href="/discovered">d</a>
				<a href="child">c</a>
				<a href="http://127.0.0.1:9/elsewhere">x</a>
			</body></html>`)
		case "/discovered":
			fmt.Fprint(w, "discovered page")
		case "/child":
			fmt.Fprint(w, "child page")
		case "/secret":
			w.WriteHeader(http.StatusUnauthorized)
		case "/missing":
			http.NotFound(w, r)
		default:
			fmt.Fprint(w, "generic soft 404 page")
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	wl := writeWordlist(t, dir, []string{
		"/real", "/app/soft1", "/app/soft2", "/missing",
		"/go", "/secret", "/links",
	})
	cfg := baseConfig(srv.URL, wl, filepath.Join(dir, "cp.json"))
	results := runEngine(t, cfg)

	grades := gradeMap(results)
	want := map[string]string{
		"/real":     "available",
		"/app/soft1": "soft404",
		"/app/soft2": "soft404",
		"/missing":  "not_found",
		"/go":       "redirect",
		"/go2":      "redirect",
		"/landing":  "available",
		"/secret":   "auth_required",
		"/links":    "available",
		"/discovered": "available",
		"/child":    "available",
	}
	for path, grade := range want {
		id := srv.URL + path
		if got := grades[id]; got != grade {
			t.Errorf("grade for %s = %q, want %q (all: %v)", path, got, grade, grades)
		}
	}
}

func TestSoft404Baseline(t *testing.T) {
	c := newCounters()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.inc(r.URL.Path)
		fmt.Fprint(w, "same generic page for everything")
	}))
	defer srv.Close()

	dir := t.TempDir()
	wl := writeWordlist(t, dir, []string{"/app/aaa", "/app/bbb", "/app/ccc", "/nope"})
	cfg := baseConfig(srv.URL, wl, filepath.Join(dir, "cp.json"))
	results := runEngine(t, cfg)
	for _, r := range results {
		if r.Grade != "soft404" {
			t.Errorf("%s grade = %q, want soft404", r.URL, r.Grade)
		}
	}
}

func TestRateLimitRetry(t *testing.T) {
	c := newCounters()
	var mu sync.Mutex
	limited := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.inc(r.URL.Path)
		mu.Lock()
		n := limited
		limited++
		mu.Unlock()
		if n < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprintf(w, "ok-%s", r.URL.Path)
	}))
	defer srv.Close()

	dir := t.TempDir()
	wl := writeWordlist(t, dir, []string{"/a", "/b", "/c", "/d", "/e"})
	cfg := baseConfig(srv.URL, wl, filepath.Join(dir, "cp.json"))
	cfg.MaxRetries = 3
	results := runEngine(t, cfg)
	if len(results) != 6 {
		t.Fatalf("got %d results, want 6 (5 wordlist + target root)", len(results))
	}
	for _, r := range results {
		if r.Grade != "available" {
			t.Errorf("%s grade = %q, want available", r.URL, r.Grade)
		}
	}
	// Retries must be bounded: 5 tasks * (1 + 3 retries) max.
	if got := c.total(); got > 20 {
		t.Errorf("request count = %d, want <= 20 (no retry amplification)", got)
	}
	if got := c.total(); got < 5 {
		t.Errorf("request count = %d, want >= 5", got)
	}
}

func TestDedupByIdentity(t *testing.T) {
	c := newCounters()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.inc(r.URL.Path)
		fmt.Fprint(w, "admin panel")
	}))
	defer srv.Close()

	dir := t.TempDir()
	wl := writeWordlist(t, dir, []string{
		"/Admin", "/admin/", "/admin?x=1", "/admin#frag",
		"HTTP://" + srv.Listener.Addr().String() + "/admin",
	})
	cfg := baseConfig(srv.URL, wl, filepath.Join(dir, "cp.json"))
	results := runEngine(t, cfg)
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (root + /admin)", len(results))
	}
	if got := c.get("/Admin"); got != 1 {
		t.Errorf("/Admin requested %d times, want 1 (first-seen variant wins)", got)
	}
	for _, p := range []string{"/admin/", "/admin?x=1", "/admin"} {
		if got := c.get(p); got != 0 {
			t.Errorf("%s requested %d times, want 0 (dedup)", p, got)
		}
	}
}

func TestScopeRejectionNoRequest(t *testing.T) {
	c1, c2 := newCounters(), newCounters()
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c1.inc(r.URL.Path)
		fmt.Fprint(w, "ok")
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c2.inc(r.URL.Path)
		fmt.Fprint(w, "ok")
	}))
	defer srv2.Close()

	dir := t.TempDir()
	wl := writeWordlist(t, dir, []string{"/ok", srv2.URL + "/elsewhere"})
	cfg := baseConfig(srv1.URL, wl, filepath.Join(dir, "cp.json"))
	results := runEngine(t, cfg)
	if got := c2.total(); got != 0 {
		t.Errorf("out-of-scope host received %d requests, want 0", got)
	}
	foundRejected := false
	for _, r := range results {
		if strings.Contains(r.URL, "/elsewhere") && r.Grade == "rejected" {
			foundRejected = true
		}
	}
	if !foundRejected {
		t.Errorf("expected rejected result for /elsewhere, got %v", results)
	}
}

func TestUnauthorizedTargetRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should be issued for unauthorized target")
	}))
	defer srv.Close()
	cfg := baseConfig(srv.URL, "", filepath.Join(t.TempDir(), "cp.json"))
	cfg.Scope.AllowedHosts = []string{"10.0.0.99"}
	if _, err := New(cfg); err == nil {
		t.Fatal("expected error for unauthorized target")
	}
}

func TestAuthRequired(t *testing.T) {
	c := newCounters()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.inc(r.URL.Path)
		if r.Header.Get("X-Auth") != "letmein" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, "secret-%s", r.URL.Path)
	}))
	defer srv.Close()

	dir := t.TempDir()
	wl := writeWordlist(t, dir, []string{"/secret"})

	// Without credentials: auth_required, not "unavailable".
	cfg := baseConfig(srv.URL, wl, filepath.Join(dir, "cp1.json"))
	results := runEngine(t, cfg)
	var secret *checkpoint.Result
	for i := range results {
		if results[i].URL == srv.URL+"/secret" {
			secret = &results[i]
		}
	}
	if secret == nil || secret.Grade != "auth_required" {
		t.Fatalf("grade = %v, want /secret auth_required", results)
	}

	// With credentials: available.
	cfg2 := baseConfig(srv.URL, wl, filepath.Join(dir, "cp2.json"))
	cfg2.Headers = map[string]string{"X-Auth": "letmein"}
	results2 := runEngine(t, cfg2)
	var secret2 *checkpoint.Result
	for i := range results2 {
		if results2[i].URL == srv.URL+"/secret" {
			secret2 = &results2[i]
		}
	}
	if secret2 == nil || secret2.Grade != "available" {
		t.Fatalf("grade = %v, want /secret available", results2)
	}

	// Sensitive header values must never appear in results.
	for _, r := range results2 {
		if strings.Contains(r.URL, "letmein") {
			t.Error("sensitive value leaked into result")
		}
	}
}

func TestBasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "user" || p != "pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/" {
			fmt.Fprint(w, "root page")
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	dir := t.TempDir()
	wl := writeWordlist(t, dir, []string{"/"})
	cfg := baseConfig(srv.URL, wl, filepath.Join(dir, "cp.json"))
	cfg.Auth = config.AuthConfig{Type: "basic", Username: "user", Password: "pass"}
	results := runEngine(t, cfg)
	if len(results) != 1 || results[0].Grade != "available" {
		t.Fatalf("grade = %v, want available", results)
	}
}

func TestRedirectOutOfScope(t *testing.T) {
	c2 := newCounters()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c2.inc(r.URL.Path)
		fmt.Fprint(w, "ok")
	}))
	defer srv2.Close()
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/leave" {
			http.Redirect(w, r, srv2.URL+"/land", http.StatusFound)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv1.Close()

	dir := t.TempDir()
	wl := writeWordlist(t, dir, []string{"/leave"})
	cfg := baseConfig(srv1.URL, wl, filepath.Join(dir, "cp.json"))
	results := runEngine(t, cfg)
	if got := c2.total(); got != 0 {
		t.Errorf("out-of-scope redirect target received %d requests", got)
	}
	var leave *checkpoint.Result
	for i := range results {
		if results[i].URL == srv1.URL+"/leave" {
			leave = &results[i]
		}
	}
	if leave == nil || leave.Grade != "redirect_out_of_scope" {
		t.Fatalf("grade = %v, want /leave redirect_out_of_scope", results)
	}
}

func TestCheckpointResume(t *testing.T) {
	gate := make(chan struct{})
	c := newCounters()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.inc(r.URL.Path)
		if r.URL.Path == "/slow" {
			select {
			case <-gate:
			case <-r.Context().Done():
			}
		}
		switch r.URL.Path {
		case "/fast":
			fmt.Fprint(w, "fast page")
		case "/slow":
			fmt.Fprint(w, "slow page")
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	wl := writeWordlist(t, dir, []string{"/fast", "/slow"})
	cp := filepath.Join(dir, "cp.json")

	cfg := baseConfig(srv.URL, wl, cp)
	cfg.PerTargetConcurrency = 1
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		eng.Run(ctx)
		close(runDone)
	}()
	waitFor(t, func() bool { return len(eng.Results()) >= 1 })
	cancel()
	<-runDone

	// Progress file must exist and hold the pending slow task.
	raw, err := os.ReadFile(cp)
	if err != nil {
		t.Fatalf("checkpoint file not written: %v", err)
	}
	if !strings.Contains(string(raw), "/slow") {
		t.Error("checkpoint does not contain pending /slow task")
	}

	// Release the blocked request and resume with a fresh engine.
	close(gate)
	cfg2 := baseConfig(srv.URL, wl, cp)
	eng2, err := New(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()
	if err := eng2.Run(ctx2); err != nil {
		t.Fatal(err)
	}
	results := eng2.Results()
	grades := gradeMap(results)
	for _, p := range []string{"/fast", "/slow"} {
		id := srv.URL + p
		if grades[id] != "available" {
			t.Errorf("%s grade = %q, want available (all: %v)", p, grades[id], grades)
		}
	}
	// Discoveries must not be duplicated (root + /fast + /slow).
	if len(results) != 3 {
		t.Errorf("got %d results, want 3 unique discoveries", len(results))
	}
}

func TestErrorStaysPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	wl := writeWordlist(t, dir, []string{"/always-500"})
	cp := filepath.Join(dir, "cp.json")
	cfg := baseConfig(srv.URL, wl, cp)
	cfg.MaxRetries = 1
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eng.Run(ctx)
	if len(eng.Results()) != 0 {
		t.Errorf("unconfirmed error must not be marked done, got %v", eng.Results())
	}
	if eng.PendingCount() != 2 {
		t.Errorf("pending count = %d, want 2 (root + /always-500)", eng.PendingCount())
	}
}

func TestDeterminismAcrossConcurrency(t *testing.T) {
	c := newCounters()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.inc(r.URL.Path)
		if strings.HasPrefix(r.URL.Path, "/app/") {
			fmt.Fprint(w, "generic page")
			return
		}
		switch r.URL.Path {
		case "/real":
			fmt.Fprint(w, "real")
		case "/go":
			http.Redirect(w, r, "/landing", http.StatusFound)
		case "/landing":
			fmt.Fprint(w, "landing")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	wl := writeWordlist(t, dir, []string{"/real", "/app/a", "/app/b", "/go", "/missing"})

	cfg1 := baseConfig(srv.URL, wl, filepath.Join(dir, "cp1.json"))
	cfg1.RateLimit = 50
	cfg1.PerTargetConcurrency = 1
	m1 := gradeMap(runEngine(t, cfg1))

	cfg2 := baseConfig(srv.URL, wl, filepath.Join(dir, "cp2.json"))
	cfg2.RateLimit = 200
	cfg2.PerTargetConcurrency = 8
	m2 := gradeMap(runEngine(t, cfg2))

	if len(m1) != len(m2) {
		t.Fatalf("result set sizes differ: %d vs %d", len(m1), len(m2))
	}
	for id, g := range m1 {
		if m2[id] != g {
			t.Errorf("grade for %s differs: %q vs %q", id, g, m2[id])
		}
	}
}

func TestGlobalRateLimit(t *testing.T) {
	var mu sync.Mutex
	count := 0
	start := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	dir := t.TempDir()
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, fmt.Sprintf("/p%d", i))
	}
	wl := writeWordlist(t, dir, lines)
	cfg := baseConfig(srv.URL, wl, filepath.Join(dir, "cp.json"))
	cfg.RateLimit = 5
	cfg.PerTargetConcurrency = 8
	runEngine(t, cfg)
	elapsed := time.Since(start)
	// 20 requests at 5/s with a burst of 5 takes ~3s.
	if elapsed < 2500*time.Millisecond {
		t.Errorf("elapsed = %v, want >= ~3s (rate limit not enforced)", elapsed)
	}
}

func TestOutOfOrderResponsesDeterministic(t *testing.T) {
	c := newCounters()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.inc(r.URL.Path)
		// Random delay forces non-deterministic completion order.
		mu.Lock()
		n := c.total()
		mu.Unlock()
		time.Sleep(time.Duration(n%7) * 3 * time.Millisecond)
		if strings.HasPrefix(r.URL.Path, "/app/") {
			fmt.Fprint(w, "generic page")
			return
		}
		switch r.URL.Path {
		case "/real":
			fmt.Fprint(w, "real content")
		case "/go":
			http.Redirect(w, r, "/landing", http.StatusFound)
		case "/landing":
			fmt.Fprint(w, "landing content")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	wl := writeWordlist(t, dir, []string{
		"/real", "/app/a", "/app/b", "/app/c", "/app/d",
		"/go", "/missing", "/app/e", "/app/f",
	})

	run := func(rate float64, conc int) map[string]string {
		cfg := baseConfig(srv.URL, wl, filepath.Join(dir, fmt.Sprintf("cp-%v-%v.json", rate, conc)))
		cfg.RateLimit = rate
		cfg.PerTargetConcurrency = conc
		return gradeMap(runEngine(t, cfg))
	}

	m1 := run(100, 1)
	m2 := run(500, 16)
	if len(m1) != len(m2) {
		t.Fatalf("result set sizes differ: %d vs %d", len(m1), len(m2))
	}
	for id, g := range m1 {
		if m2[id] != g {
			t.Errorf("grade for %s differs across runs: %q vs %q", id, g, m2[id])
		}
	}
}
