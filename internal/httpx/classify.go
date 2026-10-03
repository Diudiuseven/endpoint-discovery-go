package httpx

import "crypto/sha256"

// Grade is the deterministic classification of a probe result.
type Grade string

const (
	// GradeAvailable: 2xx response that does not match the soft-404 baseline.
	GradeAvailable Grade = "available"
	// GradeSoft404: response equivalent to the soft-404 baseline.
	GradeSoft404 Grade = "soft404"
	// GradeNotFound: 404 status that does not match the baseline.
	GradeNotFound Grade = "not_found"
	// GradeRedirect: redirect chain ending at an in-scope final response.
	GradeRedirect Grade = "redirect"
	// GradeRedirectOOS: redirect left the authorized scope.
	GradeRedirectOOS Grade = "redirect_out_of_scope"
	// GradeAuthRequired: 401/403 response (credentials missing or rejected).
	GradeAuthRequired Grade = "auth_required"
	// GradeError: transport failure or 5xx after all retries.
	GradeError Grade = "error"
	// GradeRejected: URL denied by scope; no request was issued.
	GradeRejected Grade = "rejected"
)

// Fingerprint identifies a response for soft-404 equivalence checks.
type Fingerprint struct {
	StatusCode int    `json:"status_code"`
	BodyLen    int    `json:"body_len"`
	BodyHash   string `json:"body_hash"`
	Head       string `json:"head"`
	Tail       string `json:"tail"`
}

const chunkSize = 256

// FingerprintOf computes the fingerprint of a response.
func FingerprintOf(status int, body []byte) Fingerprint {
	h := sha256.Sum256(body)
	fp := Fingerprint{
		StatusCode: status,
		BodyLen:    len(body),
		BodyHash:   string(h[:]),
	}
	if len(body) > 0 {
		head := body
		if len(head) > chunkSize {
			head = head[:chunkSize]
		}
		tail := body
		if len(tail) > chunkSize {
			tail = tail[len(tail)-chunkSize:]
		}
		fp.Head = string(head)
		fp.Tail = string(tail)
	}
	return fp
}

// Matches reports whether two fingerprints are equivalent: same status code
// and same body hash, or same status, same length and identical head/tail
// chunks (deterministic soft-404 detection).
func (f Fingerprint) Matches(other Fingerprint) bool {
	if f.StatusCode != other.StatusCode {
		return false
	}
	if f.BodyLen == other.BodyLen && f.BodyHash == other.BodyHash {
		return true
	}
	if f.BodyLen == other.BodyLen && f.BodyLen > 0 &&
		f.Head == other.Head && f.Tail == other.Tail {
		return true
	}
	return false
}

// Classify turns a probe Response into a grade. baseline is the soft-404
// fingerprint (nil when no baseline could be obtained).
func Classify(resp *Response, baseline *Fingerprint) Grade {
	if resp.OutOfScope {
		return GradeRedirectOOS
	}
	if resp.Err != nil {
		return GradeError
	}
	switch resp.StatusCode {
	case 401, 403:
		return GradeAuthRequired
	}
	// Soft-404 equivalence only applies to 2xx/404 responses; a 5xx that
	// merely matches an error baseline must remain an error.
	if baseline != nil &&
		((resp.StatusCode >= 200 && resp.StatusCode < 300) || resp.StatusCode == 404) {
		fp := FingerprintOf(resp.StatusCode, resp.Body)
		if fp.Matches(*baseline) {
			return GradeSoft404
		}
	}
	switch {
	case resp.StatusCode == 404:
		return GradeNotFound
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if len(resp.Chain) > 0 {
			return GradeRedirect
		}
		return GradeAvailable
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return GradeRedirect
	case resp.StatusCode >= 500:
		return GradeError
	default:
		return GradeNotFound
	}
}
