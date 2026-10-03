// Package engine orchestrates concurrent endpoint discovery.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/Diudiuseven/endpoint-discovery-go/internal/checkpoint"
	"github.com/Diudiuseven/endpoint-discovery-go/internal/config"
	"github.com/Diudiuseven/endpoint-discovery-go/internal/httpx"
	"github.com/Diudiuseven/endpoint-discovery-go/internal/normalize"
	"github.com/Diudiuseven/endpoint-discovery-go/internal/scope"
)

// Engine runs a discovery scan.
type Engine struct {
	cfg    config.Config
	scope  *scope.Scope
	client *httpx.Client
	store  *checkpoint.Store

	queue   chan checkpoint.Task
	wg      sync.WaitGroup
	enqMu   sync.Mutex
	queued  map[string]bool
	workers int

	baselines map[string]*httpx.Fingerprint
}

// New builds an engine from configuration.
func New(cfg config.Config) (*Engine, error) {
	cfg.ApplyDefaults()
	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}
	for _, t := range cfg.Targets {
		if _, err := normalize.CanonicalURL(t); err != nil {
			return nil, fmt.Errorf("invalid target %q: %w", t, err)
		}
	}

	rule := scope.Rule{
		AllowedHosts:        append([]string{}, cfg.Scope.AllowedHosts...),
		AllowedPorts:        append([]int{}, cfg.Scope.AllowedPorts...),
		AllowedSchemes:      append([]string{}, cfg.Scope.AllowedSchemes...),
		PathPrefixes:        append([]string{}, cfg.Scope.PathPrefixes...),
		ExcludeHosts:        append([]string{}, cfg.Excludes.Hosts...),
		ExcludePathPrefixes: append([]string{}, cfg.Excludes.PathPrefixes...),
	}
	// Default the allowed host set to the union of target hosts.
	if len(rule.AllowedHosts) == 0 {
		seen := map[string]bool{}
		for _, t := range cfg.Targets {
			canon, _ := normalize.CanonicalURL(t)
			hp, _ := normalize.HostPort(canon)
			host := strings.Split(hp, ":")[0]
			if !seen[host] {
				seen[host] = true
				rule.AllowedHosts = append(rule.AllowedHosts, host)
			}
		}
	}

	sc, err := scope.New(rule, cfg.Targets[0])
	if err != nil {
		return nil, err
	}
	// Every target must itself be authorized; otherwise refuse before any
	// request is made.
	for _, t := range cfg.Targets {
		if ok, reason := sc.Allowed(t); !ok {
			return nil, fmt.Errorf("target %q is not authorized: %s", t, reason)
		}
	}

	store, err := checkpoint.Open(cfg.Checkpoint, cfg.Targets[0])
	if err != nil {
		return nil, fmt.Errorf("checkpoint: %w", err)
	}

	client := httpx.NewClient(httpx.ClientConfig{
		RateLimit:            cfg.RateLimit,
		PerTargetConcurrency: cfg.PerTargetConcurrency,
		MaxRetries:           cfg.MaxRetries,
		RetryBackoff:         cfg.RetryBackoff(),
		RequestTimeout:       cfg.RequestTimeout(),
		Headers:              cfg.Headers,
		Auth: httpx.Auth{
			Type:     cfg.Auth.Type,
			Username: cfg.Auth.Username,
			Password: cfg.Auth.Password,
			Token:    cfg.Auth.Token,
		},
		MaxRedirects: cfg.MaxRedirects,
	}, sc.Allowed)

	workers := cfg.PerTargetConcurrency
	if workers < 1 {
		workers = 4
	}

	return &Engine{
		cfg:       cfg,
		scope:     sc,
		client:    client,
		store:     store,
		queue:     make(chan checkpoint.Task, 4096),
		queued:    map[string]bool{},
		workers:   workers,
		baselines: map[string]*httpx.Fingerprint{},
	}, nil
}

// Run executes the scan until the queue drains or ctx is cancelled.
// Progress is committed to the checkpoint as tasks complete.
func (e *Engine) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// Fetch soft-404 baselines (one per target host) before probing.
	for _, t := range e.cfg.Targets {
		e.fetchBaseline(ctx, t)
	}

	// Seed tasks: target roots, wordlist, then resume pending work.
	for _, t := range e.cfg.Targets {
		e.seedTarget(ctx, t)
	}
	if e.cfg.Wordlist != "" {
		if err := e.seedWordlist(ctx, e.cfg.Wordlist); err != nil {
			return err
		}
	}
	for _, t := range e.store.Pending() {
		e.enqueue(t)
	}

	go func() {
		e.wg.Wait()
		close(e.queue)
	}()

	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < e.workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				e.worker(ctx)
			}()
		}
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("scan complete: %d confirmed results, %d pending",
			len(e.store.Done()), len(e.store.Pending()))
	case <-ctx.Done():
		log.Printf("interrupted: progress saved (%d done, %d pending)",
			len(e.store.Done()), len(e.store.Pending()))
	}
	return nil
}

func (e *Engine) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-e.queue:
			if !ok {
				return
			}
			e.process(ctx, task)
		}
	}
}

func (e *Engine) process(ctx context.Context, task checkpoint.Task) {
	if e.store.Has(task.Identity) {
		e.wg.Done()
		return
	}

	// Scope gate: out-of-scope tasks are recorded as rejected and never
	// requested.
	if ok, reason := e.scope.Allowed(task.URL); !ok {
		r := checkpoint.Result{
			Identity: task.Identity,
			URL:      task.URL,
			Grade:    string(httpx.GradeRejected),
			Source:   task.Source,
			Error:    reason,
		}
		if err := e.store.Complete(task, r); err != nil {
			log.Printf("checkpoint error: %v", err)
		}
		log.Printf("rejected (no request): %s (%s)", task.URL, reason)
		e.wg.Done()
		return
	}

	resp := e.client.Get(ctx, task.URL)

	host, _ := normalize.HostPort(task.URL)
	grade := httpx.Classify(resp, e.baselines[host])

	if grade == httpx.GradeError {
		// Not confirmed: keep pending and retry on the next run.
		if err := e.store.Fail(task, errString(resp.Err)); err != nil {
			log.Printf("checkpoint error: %v", err)
		}
		log.Printf("error (will retry): %s: %v", task.URL, errString(resp.Err))
		e.wg.Done()
		return
	}

	chain := make([]checkpoint.Hop, 0, len(resp.Chain))
	for _, h := range resp.Chain {
		chain = append(chain, checkpoint.Hop{URL: h.URL, StatusCode: h.StatusCode})
	}
	r := checkpoint.Result{
		Identity:   task.Identity,
		URL:        task.URL,
		Grade:      string(grade),
		StatusCode: resp.StatusCode,
		Chain:      chain,
		Source:     task.Source,
	}
	if resp.Err != nil {
		r.Error = resp.Err.Error()
	}
	if err := e.store.Complete(task, r); err != nil {
		log.Printf("checkpoint error: %v", err)
	}
	log.Printf("[%s] %s (status %d, source %s)", grade, task.URL, resp.StatusCode, task.Source)

	// Dynamic expansion: new paths from redirect hops and response bodies.
	// Every hop URL is enqueued (de-duplicated by identity) so redirect
	// targets are never missed, even when the final response is an error.
	if len(resp.Chain) > 0 && !resp.OutOfScope {
		for _, h := range resp.Chain {
			if h.URL != "" {
				e.enqueueURL(h.URL, "redirect")
			}
		}
		if resp.FinalURL != "" {
			e.enqueueURL(resp.FinalURL, "redirect")
		}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && len(resp.Body) > 0 {
		for _, link := range extractLinks(resp.Body) {
			e.enqueueLink(task.URL, link)
		}
	}
	e.wg.Done()
}

// enqueueLink resolves a found link relative to its parent and enqueues it.
func (e *Engine) enqueueLink(parent, link string) {
	resolved, err := normalize.ResolveReference(parent, link)
	if err != nil {
		return
	}
	if ok, _ := e.scope.Allowed(resolved); !ok {
		return
	}
	e.enqueueURL(resolved, "link")
}

func (e *Engine) enqueueURL(raw, source string) {
	canon, err := normalize.CanonicalURL(raw)
	if err != nil {
		return
	}
	id, err := normalize.Identity(canon)
	if err != nil {
		return
	}
	t := checkpoint.Task{Identity: id, URL: canon, Source: source}
	e.enqueue(t)
}

// enqueue adds a task to the queue, de-duplicating by identity and
// persisting it as pending before any request is issued.
func (e *Engine) enqueue(t checkpoint.Task) {
	e.enqMu.Lock()
	if e.queued[t.Identity] || e.store.Has(t.Identity) {
		e.enqMu.Unlock()
		return
	}
	e.queued[t.Identity] = true
	e.enqMu.Unlock()

	if err := e.store.AddPending(t); err != nil {
		log.Printf("checkpoint error: %v", err)
	}
	e.wg.Add(1)
	e.queue <- t
}

func (e *Engine) seedTarget(ctx context.Context, target string) {
	canon, err := normalize.CanonicalURL(target)
	if err != nil {
		return
	}
	e.enqueueURL(canon, "target")
}

func (e *Engine) seedWordlist(ctx context.Context, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("wordlist: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			e.enqueueURL(line, "wordlist")
			continue
		}
		// Resolve path against each target.
		for _, t := range e.cfg.Targets {
			base, err := normalize.CanonicalURL(t)
			if err != nil {
				continue
			}
			resolved, err := normalize.ResolveReference(base, line)
			if err != nil {
				continue
			}
			e.enqueueURL(resolved, "wordlist")
		}
	}
	return nil
}

// fetchBaseline probes a random nonexistent path to build the soft-404
// fingerprint for a target host.
func (e *Engine) fetchBaseline(ctx context.Context, target string) {
	canon, err := normalize.CanonicalURL(target)
	if err != nil {
		return
	}
	host, _ := normalize.HostPort(canon)
	if e.baselines[host] != nil {
		return
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	base := strings.TrimRight(canon, "/")
	probeURL := base + "/.discovery-baseline-" + hex.EncodeToString(b[:])
	resp := e.client.Get(ctx, probeURL)
	if resp.Err != nil {
		log.Printf("soft-404 baseline unavailable for %s: %v", host, resp.Err)
		return
	}
	fp := httpx.FingerprintOf(resp.StatusCode, resp.Body)
	e.baselines[host] = &fp
	log.Printf("soft-404 baseline for %s: status=%d len=%d", host, fp.StatusCode, fp.BodyLen)
}

// Results returns the confirmed, deterministically ordered results.
func (e *Engine) Results() []checkpoint.Result {
	return e.store.Done()
}

// PendingCount returns the number of not-yet-confirmed tasks.
func (e *Engine) PendingCount() int {
	return len(e.store.Pending())
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
