// Package httpx implements the rate-limited, retry-aware HTTP probe client
// and the deterministic response classification.
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Diudiuseven/endpoint-discovery-go/internal/normalize"
)

// Auth describes credentials attached to every probe.
type Auth struct {
	// Type is "basic" or "bearer".
	Type string
	// Username/Password for basic auth.
	Username string
	// Password for basic auth.
	Password string
	// Token for bearer auth.
	Token string
}

// ClientConfig groups all tunable probe parameters.
type ClientConfig struct {
	// RateLimit is the global maximum request rate in requests/second.
	// Zero means unlimited.
	RateLimit float64
	// PerTargetConcurrency caps in-flight requests per target host.
	PerTargetConcurrency int
	// MaxRetries is the number of retry attempts for rate-limiting (429/503)
	// and connection failures. Retries use exponential backoff and never
	// amplify traffic: the total attempt count is bounded.
	MaxRetries int
	// RetryBackoff is the base backoff duration; actual backoff is
	// base * 2^attempt plus jitter, capped by the Retry-After header.
	RetryBackoff time.Duration
	// RequestTimeout bounds a single request attempt.
	RequestTimeout time.Duration
	// Headers are attached to every request. Sensitive values are never
	// logged or copied into results.
	Headers map[string]string
	// Auth is attached to every request.
	Auth Auth
	// MaxRedirects caps the number of followed redirect hops.
	MaxRedirects int
}

// Hop is a single redirect step.
type Hop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

// Response is the outcome of probing a single URL (including retries and
// redirect hops).
type Response struct {
	// Requested is the original (normalized) URL.
	Requested string
	// FinalURL is the URL after the last followed hop.
	FinalURL string
	// StatusCode is the final response status code (0 on transport error).
	StatusCode int
	// Body is the final response body (truncated to a sane size).
	Body []byte
	// Chain records every redirect hop in order.
	Chain []Hop
	// OutOfScope is true when a redirect left the authorized scope.
	OutOfScope bool
	// Err is set when the probe failed after all retries.
	Err error
	// Attempts is the total number of request attempts issued.
	Attempts int
}

const maxBodyBytes = 1 << 20 // 1 MiB

// Client is the probe client.
type Client struct {
	cfg        ClientConfig
	http       *http.Client
	semMu      sync.Mutex
	sem        map[string]chan struct{}
	limiter    *tokenBucket
	scopeCheck func(string) (bool, string)
}

// NewClient builds a probe client. scopeCheck is consulted before every
// request (including redirect hops); a denied URL is never requested.
func NewClient(cfg ClientConfig, scopeCheck func(string) (bool, string)) *Client {
	if cfg.PerTargetConcurrency <= 0 {
		cfg.PerTargetConcurrency = 4
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 200 * time.Millisecond
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 15 * time.Second
	}
	if cfg.MaxRedirects <= 0 {
		cfg.MaxRedirects = 10
	}
	c := &Client{
		cfg:        cfg,
		sem:        make(map[string]chan struct{}),
		limiter:    newTokenBucket(cfg.RateLimit),
		scopeCheck: scopeCheck,
		http: &http.Client{
			Timeout: cfg.RequestTimeout,
			// We follow redirects manually so each hop can be scope-checked.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	return c
}

// Get probes rawURL, following redirects manually so every hop is
// scope-checked. Retries with backoff are applied for 429/503 and transport
// errors.
func (c *Client) Get(ctx context.Context, rawURL string) *Response {
	requested, err := normalize.CanonicalURL(rawURL)
	if err != nil {
		return &Response{Requested: rawURL, Err: err}
	}
	if c.scopeCheck != nil {
		if ok, reason := c.scopeCheck(requested); !ok {
			return &Response{Requested: requested, Err: fmt.Errorf("scope rejected: %s", reason)}
		}
	}

	host, _ := normalize.HostPort(requested)
	sem := c.targetSemaphore(host)
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return &Response{Requested: requested, Err: ctx.Err()}
	}

	resp := &Response{Requested: requested}
	current := requested
	for {
		hop, err := c.probeOnce(ctx, current, resp)
		if err != nil {
			resp.Err = err
			return resp
		}
		resp.Attempts++
		resp.StatusCode = hop.status
		resp.FinalURL = hop.url
		resp.Body = hop.body

		if isRedirect(hop.status) {
			loc := hop.location
			if loc == "" {
				return resp
			}
			next, err := normalize.ResolveReference(current, loc)
			if err != nil {
				resp.Err = fmt.Errorf("invalid redirect location %q: %w", loc, err)
				return resp
			}
			if c.scopeCheck != nil {
				if ok, reason := c.scopeCheck(next); !ok {
					resp.Chain = append(resp.Chain, Hop{URL: next, StatusCode: 0})
					resp.OutOfScope = true
					resp.FinalURL = next
					resp.Err = fmt.Errorf("redirect out of scope: %s", reason)
					return resp
				}
			}
			resp.Chain = append(resp.Chain, Hop{URL: next, StatusCode: hop.status})
			if len(resp.Chain) > c.cfg.MaxRedirects {
				resp.Err = errors.New("too many redirects")
				return resp
			}
			current = next
			continue
		}
		return resp
	}
}

type probeResult struct {
	status   int
	url      string
	body     []byte
	location string
}

// probeOnce performs a single request attempt with retries for rate limiting
// and transport errors.
func (c *Client) probeOnce(ctx context.Context, target string, resp *Response) (*probeResult, error) {
	var lastErr error
	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if err := c.limiter.wait(ctx); err != nil {
			return nil, err
		}
		res, retryAfter, err := c.doRequest(ctx, target)
		if err == nil && res.status != http.StatusTooManyRequests && res.status != http.StatusServiceUnavailable {
			return res, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("rate limited (status %d)", res.status)
		}
		// Retryable: 429/503 or transport error. Backoff and retry unless the
		// context is done or attempts are exhausted.
		if attempt == c.cfg.MaxRetries {
			break
		}
		if err := c.backoff(ctx, attempt+1, retryAfter); err != nil {
			return nil, err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("request failed after retries")
	}
	return nil, lastErr
}

func (c *Client) doRequest(ctx context.Context, target string) (*probeResult, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range c.cfg.Headers {
		req.Header.Set(k, v)
	}
	switch c.cfg.Auth.Type {
	case "basic":
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
			[]byte(c.cfg.Auth.Username+":"+c.cfg.Auth.Password)))
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+c.cfg.Auth.Token)
	}
	req.Header.Set("User-Agent", "endpoint-discovery/1.0")

	httpResp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer httpResp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(httpResp.Body, maxBodyBytes+1))
	retryAfter := parseRetryAfter(httpResp.Header.Get("Retry-After"))
	return &probeResult{
		status:   httpResp.StatusCode,
		url:      target,
		body:     body,
		location: httpResp.Header.Get("Location"),
	}, retryAfter, nil
}

func (c *Client) backoff(ctx context.Context, attempt int, retryAfter time.Duration) error {
	// Exponential backoff with jitter: base * 2^(attempt-1) * (0.5..1.5).
	base := c.cfg.RetryBackoff
	d := time.Duration(float64(base) * math.Pow(2, float64(attempt-1)))
	if retryAfter > 0 && retryAfter < d {
		d = retryAfter
	}
	if retryAfter > d {
		d = retryAfter
	}
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	jitter, _ := rand.Int(rand.Reader, big.NewInt(1000))
	d += time.Duration(jitter.Int64()) * time.Millisecond
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) targetSemaphore(host string) chan struct{} {
	c.semMu.Lock()
	defer c.semMu.Unlock()
	if ch, ok := c.sem[host]; ok {
		return ch
	}
	ch := make(chan struct{}, c.cfg.PerTargetConcurrency)
	c.sem[host] = ch
	return ch
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// tokenBucket is a global rate limiter.
type tokenBucket struct {
	rate   float64
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newTokenBucket(rate float64) *tokenBucket {
	if rate <= 0 {
		return nil
	}
	return &tokenBucket{rate: rate, tokens: rate, last: time.Now()}
}

func (tb *tokenBucket) wait(ctx context.Context) error {
	if tb == nil {
		return nil
	}
	for {
		tb.mu.Lock()
		now := time.Now()
		tb.tokens = math.Min(tb.rate, tb.tokens+now.Sub(tb.last).Seconds()*tb.rate)
		tb.last = now
		if tb.tokens >= 1 {
			tb.tokens--
			tb.mu.Unlock()
			return nil
		}
		wait := time.Duration((1-tb.tokens)/tb.rate*1000) * time.Millisecond
		tb.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

