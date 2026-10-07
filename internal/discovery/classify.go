package discovery

import (
	"crypto/sha256"
)

// baseline captures the target's not-found signature, probed once per scan
// with a random nonexistent path. Responses equivalent to the baseline are
// soft 404s.
type baseline struct {
	status int
	hash   [32]byte
	length int64
	set    bool
}

// matches reports whether a response is equivalent to the not-found
// baseline. Equivalence is strict: the status must be the same AND every
// body byte must be identical. Equal length with different content is
// deliberately NOT equivalent, because real sites commonly serve genuine
// pages whose size happens to equal the fixed-size hint page; matching on
// size alone would wrongly hide them as soft 404s.
func (b *baseline) matches(status int, body []byte) bool {
	if b == nil || !b.set {
		return false
	}
	if status != b.status {
		return false
	}
	// Cheap exactness guard: different length necessarily means different
	// bytes; only same-length bodies are worth hashing.
	if int64(len(body)) != b.length {
		return false
	}
	return sha256.Sum256(body) == b.hash
}

// isRedirectStatus reports whether status is an HTTP redirect.
func isRedirectStatus(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// classifyResponse maps an observed final response to a deterministic
// Classification. Retryable conditions (429, 5xx, transport errors) must be
// exhausted by the caller before classification; reaching here with such a
// status means the retries failed and the verdict is ClassError.
func classifyResponse(status int, body []byte, redirectTo string, bl *baseline) Classification {
	switch {
	case isRedirectStatus(status):
		return ClassRedirect
	case status == 401:
		// Auth failure is identified, not treated as target-unavailable.
		return ClassAuthRequired
	case status == 403:
		return ClassForbidden
	case status == 404 || status == 410:
		return ClassNotFound
	case status == 429 || (status >= 500 && status <= 599):
		return ClassError
	case status >= 200 && status <= 299:
		if bl.matches(status, body) {
			return ClassSoft404
		}
		return ClassAvailable
	case status >= 300 && status <= 399:
		return ClassRedirect
	}
	return ClassError
}
