// Package discovery implements a web endpoint discovery and content
// enumeration engine with scoping, rate limiting, soft-404 detection,
// resumable state and deterministic output.
package discovery

import (
	"log"
	"time"
)

// Classification is the deterministic verdict for a probed path.
type Classification string

const (
	ClassAvailable    Classification = "available"     // real, usable content
	ClassRedirect     Classification = "redirect"      // redirect chain to a final location
	ClassSoft404      Classification = "soft_404"      // 200-equivalent of the not-found baseline
	ClassNotFound     Classification = "not_found"     // hard 404/410 or equivalent
	ClassAuthRequired Classification = "auth_required" // 401: credentials missing/invalid
	ClassForbidden    Classification = "forbidden"     // 403: refused but exists
	ClassError        Classification = "error"         // 5xx or transport failure after retries
)

// Config controls a scan. Sensitive header values are never logged or
// emitted into results; see SensitiveHeaders.
type Config struct {
	Target              string            // base URL, e.g. http://127.0.0.1:8080/app
	AllowedSchemes      []string          // e.g. ["http","https"]; empty = derive from Target
	AllowedHosts        []string          // empty = host of Target only
	AllowedPorts        []int             // empty = port of Target only
	AllowedPathPrefixes []string          // empty = prefix of Target path
	ExcludePathPrefixes []string          // denied even if under an allowed prefix
	Wordlist            []string          // candidate paths
	Concurrency         int               // per-target in-flight cap (default 4)
	RequestsPerSecond   float64           // global rate cap (default 20)
	MaxRetries          int               // retries on 429/5xx/conn errors (default 3)
	BackoffBase         time.Duration     // first retry delay (default 100ms)
	BackoffMax          time.Duration     // retry delay cap (default 2s)
	Timeout             time.Duration     // per-request timeout (default 10s)
	MaxRedirects        int               // redirect chain depth recorded (default 5)
	ExpandFromContent   bool              // extract links from available responses
	MaxExpansionDepth   int               // depth for content expansion (default 1)
	Headers             map[string]string // extra request headers (may hold credentials)
	SensitiveHeaders    []string          // header names whose values must be redacted
	StateFile           string            // checkpoint file for resume; empty = in-memory only
	Logger              *log.Logger       // nil = discard
}

// Finding is one probed path outcome.
type Finding struct {
	Path          string         `json:"path"`           // canonical path (dedup key)
	URL           string         `json:"url"`            // full normalized URL requested
	Class         Classification `json:"class"`          // deterministic verdict
	StatusCode    int            `json:"status_code"`    // final status observed
	ContentLength int64          `json:"content_length"` // final body size
	RedirectTo    string         `json:"redirect_to,omitempty"`
	Depth         int            `json:"depth"` // expansion depth at which it was discovered

	body []byte // internal: response body for link extraction, never serialized
}

// Stats summarizes a run.
type Stats struct {
	Submitted int `json:"submitted"` // unique paths enqueued
	Requested int `json:"requested"` // HTTP requests sent (incl. retries)
	Retried   int `json:"retried"`
	Rejected  int `json:"rejected"` // out-of-scope, never requested
	Resumed   int `json:"resumed"`  // skipped because already done in checkpoint
}

// Result is the stable output of a scan.
type Result struct {
	Target   string    `json:"target"`
	Findings []Finding `json:"findings"` // sorted by Path, then Class
	Stats    Stats     `json:"stats"`
}
