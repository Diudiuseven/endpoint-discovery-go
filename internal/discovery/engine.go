package discovery

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// baselinePath is a fixed improbable path probed once to learn the target's
// not-found signature. Fixed (not random) so runs are reproducible.
const baselinePath = "/.endscan-baseline-3f9a1c7e"

const maxBodyBytes = 4 << 20

// Engine orchestrates a scan.
type Engine struct {
	cfg       Config
	scope     *Scope
	target    *url.URL
	client    *http.Client
	transport http.RoundTripper
	limiter   *Limiter
	state     *StateStore
	logger    *log.Logger
	inflight  sync.Map

	mu           sync.Mutex
	findings     []Finding
	seenFindings map[string]bool

	submitted atomic.Int64
	requested atomic.Int64
	retried   atomic.Int64
	rejected  atomic.Int64
	resumed   atomic.Int64
}

// NewEngine validates cfg, applies defaults and builds an Engine.
func NewEngine(cfg Config) (*Engine, error) {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = 20
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 100 * time.Millisecond
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 2 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxRedirects == 0 {
		cfg.MaxRedirects = 5
	} else if cfg.MaxRedirects < 0 {
		cfg.MaxRedirects = 0 // negative disables redirect following
	}
	if cfg.MaxExpansionDepth <= 0 {
		cfg.MaxExpansionDepth = 1
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}
	target, err := NormalizeURL(cfg.Target)
	if err != nil {
		return nil, err
	}
	scope, err := NewScope(&cfg)
	if err != nil {
		return nil, err
	}
	if !scope.Allow(target) {
		return nil, fmt.Errorf("target %s is outside the configured scope", target)
	}
	state, err := OpenStateStore(cfg.StateFile)
	if err != nil {
		return nil, err
	}
	// A dedicated Transport per engine: scans (including resumed runs in the
	// same process) never share a keep-alive pool, so a connection whose
	// response was abandoned by a cancelled scan cannot be reused by a
	// later run and poison its retries.
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{
		Timeout: cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // manual chain handling
		},
		Transport: transport,
	}
	return &Engine{
		cfg:       cfg,
		scope:     scope,
		target:    target,
		client:    client,
		transport: transport,
		limiter:   NewLimiter(cfg.RequestsPerSecond, cfg.Concurrency),
		state:     state,
		logger:    cfg.Logger,
	}, nil
}

// task is one unit of work.
type task struct {
	key   string // canonical dedup key
	url   string // normalized URL to request
	depth int
}

// workQueue is an unbounded blocking queue.
type workQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []task
	closed bool
}

func newWorkQueue() *workQueue {
	q := &workQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *workQueue) push(t task) {
	q.mu.Lock()
	q.items = append(q.items, t)
	q.mu.Unlock()
	q.cond.Signal()
}

func (q *workQueue) pop() (task, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.items) == 0 {
		return task{}, false
	}
	t := q.items[0]
	q.items = q.items[1:]
	return t, true
}

func (q *workQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.cond.Broadcast()
}

// Run executes the scan and returns a deterministic Result.
func (e *Engine) Run(ctx context.Context) (res *Result, err error) {
	defer func() {
		if cerr := e.state.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if tr, ok := e.transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}()
	bl := e.probeBaseline(ctx)

	// Preload findings persisted by previous interrupted runs so the final
	// result is complete (no omissions) and deduped by canonical key.
	seen := map[string]bool{}
	for _, f := range e.state.Findings() {
		seen[f.URL] = true
		e.findings = append(e.findings, f)
	}
	e.seenFindings = seen

	q := newWorkQueue()
	var wg sync.WaitGroup
	enqueue := func(t task) {
		wg.Add(1)
		q.push(t)
	}

	// Seed: wordlist plus anything discovered-but-unfinished from a
	// previous interrupted run. Pending is captured BEFORE seeding; a pending
	// key that the wordlist also covers is owned by the seed and must not be
	// enqueued a second time, so no duplicate task (or request) is possible.
	pending := e.state.Pending()
	seeded := map[string]bool{}
	e.seed(func(t task) {
		seeded[t.key] = true
		enqueue(t)
	}, e.cfg.Wordlist, 0)
	for _, key := range pending {
		if seeded[key] {
			continue // wordlist seed already enqueued it
		}
		u, perr := url.Parse(key)
		if perr != nil || !e.scope.Allow(u) {
			continue
		}
		if e.state.Done(key) {
			e.resumed.Add(1)
			continue
		}
		e.submitted.Add(1)
		enqueue(task{key: key, url: key, depth: 0})
	}

	go func() { wg.Wait(); q.close() }()

	workers := e.cfg.Concurrency
	var wwg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wwg.Add(1)
		go func() {
			defer wwg.Done()
			for t, ok := q.pop(); ok; t, ok = q.pop() {
				e.process(ctx, t, bl, enqueue)
				wg.Done()
			}
		}()
	}
	wwg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	e.mu.Lock()
	findings := make([]Finding, len(e.findings))
	copy(findings, e.findings)
	e.mu.Unlock()
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Class < findings[j].Class
	})
	return &Result{
		Target:   e.target.String(),
		Findings: findings,
		Stats: Stats{
			Submitted: int(e.submitted.Load()),
			Requested: int(e.requested.Load()),
			Retried:   int(e.retried.Load()),
			Rejected:  int(e.rejected.Load()),
			Resumed:   int(e.resumed.Load()),
		},
	}, nil
}

// seed normalizes, scope-checks, dedups and enqueues candidate paths.
func (e *Engine) seed(enqueue func(task), words []string, depth int) {
	for _, w := range words {
		u, err := NormalizeURL(joinPath(e.target, w))
		if err != nil {
			e.rejected.Add(1)
			continue
		}
		if !e.scope.Allow(u) {
			e.rejected.Add(1)
			e.logger.Printf("REJECT out-of-scope path=%q", w)
			continue
		}
		key := CanonicalKey(u)
		if e.state.Done(key) {
			e.resumed.Add(1)
			continue
		}
		isNew, err := e.state.MarkDiscoveredIfNew(key)
		if err != nil {
			e.logger.Printf("WARN state: %v", err)
			continue
		}
		if !isNew {
			continue
		}
		e.submitted.Add(1)
		enqueue(task{key: key, url: u.String(), depth: depth})
	}
}

// joinPath resolves a candidate word against the target base. Query
// strings and fragments in the candidate are always dropped: identity is
// defined solely by the normalized path, so "p?a=1" and "p?b=2" collapse
// to one target and are requested exactly once.
func joinPath(base *url.URL, word string) string {
	w := strings.TrimSpace(word)
	if w == "" {
		return base.String()
	}
	// Cut query/fragment off the raw word BEFORE it can be interpreted as
	// part of a URL struct: assigning "p?x=1" to url.URL.Path and calling
	// String() would percent-escape the '?' into %3F, smuggling the query
	// past normalization.
	if i := strings.IndexAny(w, "?#"); i >= 0 {
		w = w[:i]
	}
	if strings.Contains(w, "://") {
		return w // absolute URL candidate; scope check decides
	}
	if strings.HasPrefix(w, "/") {
		b := *base
		b.Path = w
		return b.String()
	}
	b := *base
	bp := b.Path
	if !strings.HasSuffix(bp, "/") {
		bp += "/"
	}
	b.Path = bp + w
	return b.String()
}

// process probes one task, records the finding and expands content links.
func (e *Engine) process(ctx context.Context, t task, bl *baseline, enqueue func(task)) {
	if e.state.Done(t.key) {
		e.resumed.Add(1)
		return
	}
	if _, loaded := e.inflight.LoadOrStore(t.key, struct{}{}); loaded {
		return // another worker is already probing this key
	}
	defer e.inflight.Delete(t.key)
	u, err := url.Parse(t.url)
	if err != nil || !e.scope.Allow(u) {
		e.rejected.Add(1)
		return
	}
	f := e.probeWithBaseline(ctx, u, bl)
	if ctx.Err() != nil {
		// Scan cancelled mid-probe: do not record or mark done, so the
		// path is retried on resume.
		return
	}
	f.Depth = t.depth
	if err := e.state.RecordFinding(t.key, f); err != nil {
		e.logger.Printf("WARN state: %v", err)
	}
	e.mu.Lock()
	if !e.seenFindings[f.URL] {
		e.seenFindings[f.URL] = true
		e.findings = append(e.findings, f)
	}
	e.mu.Unlock()
	e.logger.Printf("DONE path=%s class=%s status=%d", f.Path, f.Class, f.StatusCode)

	if e.cfg.ExpandFromContent && f.Class == ClassAvailable && t.depth < e.cfg.MaxExpansionDepth {
		for _, link := range extractLinks(f.body) {
			nu, nerr := NormalizeURL(resolveRef(f.URL, link))
			if nerr != nil || !e.scope.Allow(nu) {
				continue
			}
			key := CanonicalKey(nu)
			isNew, kerr := e.state.MarkDiscoveredIfNew(key)
			if kerr != nil || !isNew {
				continue
			}
			e.submitted.Add(1)
			enqueue(task{key: key, url: nu.String(), depth: t.depth + 1})
		}
	}
	if err := e.state.MarkDone(t.key); err != nil {
		e.logger.Printf("WARN state: %v", err)
	}
}

// probeWithBaseline fetches one URL with retries and redirect-chain
// handling, then classifies the outcome.
func (e *Engine) probeWithBaseline(ctx context.Context, u *url.URL, bl *baseline) Finding {
	f := Finding{Path: CanonicalPath(u.Path), URL: u.String(), Class: ClassError}
	final, chainOK := e.fetchChain(ctx, u, func(status int) bool {
		return isRedirectStatus(status)
	})
	if final.err != nil {
		f.Class = ClassError
		return f
	}
	f.StatusCode = final.status
	f.ContentLength = int64(len(final.body))
	f.Class = classifyResponse(final.status, final.body, final.location, bl)
	if !chainOK {
		// Chain left scope or hit the hop cap: the last response itself is
		// the verdict (ClassRedirect); record where it pointed.
		f.Class = ClassRedirect
		f.RedirectTo = final.location
		return f
	}
	if final.throughRedirect {
		// Chain was followed to a final non-redirect response; a chain that
		// ends on a hint page / hard 404 is classified from that final
		// response, identical to visiting it directly.
		f.RedirectTo = final.finalURL
	}
	if f.Class == ClassRedirect && final.location != "" {
		f.RedirectTo = final.location
	}
	f.body = final.body
	return f
}

// chainResult is the terminal response of a redirect-chain walk.
type chainResult struct {
	status          int
	body            []byte
	location        string // Location header of the terminal response
	finalURL        string // URL of the terminal response
	throughRedirect bool   // at least one hop was followed
	err             error
}

// fetchChain performs manual redirect following (the HTTP client is
// configured with ErrUseLastResponse). Every hop passes through retries,
// the rate limiter and scope checks. The returned bool is false when the
// chain could not be followed to a final non-redirect response (out-of-scope
// hop or hop cap reached); in that case chainResult holds the last
// response, which the caller reports as ClassRedirect.
func (e *Engine) fetchChain(ctx context.Context, start *url.URL, isRedirect func(int) bool) (chainResult, bool) {
	current := start.String()
	for hops := 0; ; hops++ {
		status, body, location, err := e.doWithRetries(ctx, current)
		if err != nil {
			return chainResult{err: err, finalURL: current}, true
		}
		if isRedirect(status) && location != "" && hops < e.cfg.MaxRedirects {
			next, rerr := NormalizeURL(resolveRef(current, location))
			if rerr != nil || !e.scope.Allow(next) {
				return chainResult{
					status:   status,
					body:     body,
					location: location,
					finalURL: current,
				}, false
			}
			current = next.String()
			continue
		}
		return chainResult{
			status:          status,
			body:            body,
			location:        location,
			finalURL:        current,
			throughRedirect: hops > 0,
		}, true
	}
}

// doWithRetries performs a single logical request, retrying 429/5xx and
// transport errors with exponential backoff. Every attempt passes through
// the limiter, so retries never amplify traffic.
func (e *Engine) doWithRetries(ctx context.Context, rawurl string) (int, []byte, string, error) {
	var lastErr error
	for attempt := 0; attempt <= e.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			e.retried.Add(1)
			delay := Backoff(e.cfg.BackoffBase, e.cfg.BackoffMax, attempt)
			select {
			case <-ctx.Done():
				return 0, nil, "", ctx.Err()
			case <-time.After(delay):
			}
		}
		if err := e.limiter.Acquire(ctx); err != nil {
			return 0, nil, "", err
		}
		status, body, location, retryable, err := e.doOnce(ctx, rawurl)
		e.limiter.Release()
		if err == nil && !retryable {
			return status, body, location, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("retryable status %d", status)
		}
		if err == nil {
			// Retries exhausted on a retryable status: return it so the
			// classifier maps it to ClassError deterministically.
			if attempt == e.cfg.MaxRetries {
				return status, body, location, nil
			}
		}
	}
	return 0, nil, "", lastErr
}

// doOnce issues one HTTP request with configured headers.
func (e *Engine) doOnce(ctx context.Context, rawurl string) (status int, body []byte, location string, retryable bool, err error) {
	e.requested.Add(1)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return 0, nil, "", false, err
	}
	for k, v := range e.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, nil, "", true, err // transport errors are retryable
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return resp.StatusCode, nil, "", true, err
	}
	location = resp.Header.Get("Location")
	retryable = resp.StatusCode == 429 || (resp.StatusCode >= 500 && resp.StatusCode <= 599)
	return resp.StatusCode, body, location, retryable, nil
}

// probeBaseline learns the not-found signature of the target. The fixed
// improbable path is fetched through the SAME redirect-chain logic as real
// probes, so targets that answer unknown paths with a redirect to a fixed
// hint page are learned correctly: the signature is the terminal response
// (status + exact body), and a chain landing on it is judged identically to
// a direct request.
func (e *Engine) probeBaseline(ctx context.Context) *baseline {
	bl := &baseline{}
	u := *e.target
	bp := e.target.Path
	if !strings.HasSuffix(bp, "/") {
		bp += "/"
	}
	u.Path = bp + strings.TrimPrefix(baselinePath, "/")
	if !e.scope.Allow(&u) {
		return bl // baseline path out of configured scope; skip detection
	}
	final, ok := e.fetchChain(ctx, &u, isRedirectStatus)
	if final.err != nil || !ok {
		return bl
	}
	bl.status = final.status
	bl.length = int64(len(final.body))
	bl.hash = sha256Sum(final.body)
	bl.set = true
	return bl
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

var linkRe = regexp.MustCompile(`(?i)(?:href|src)\s*=\s*["']([^"'#]+)["']`)

// extractLinks pulls href/src references from a body.
func extractLinks(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	matches := linkRe.FindAllSubmatch(body, 64)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, string(m[1]))
	}
	return out
}

// resolveRef resolves ref against base.
func resolveRef(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}
