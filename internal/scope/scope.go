// Package scope decides whether a normalized URL is allowed to be probed.
package scope

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/Diudiuseven/endpoint-discovery-go/internal/normalize"
)

// Rule describes the authorized target set and exclusion rules.
type Rule struct {
	// AllowedHosts are host patterns that may be probed. A pattern may be an
	// exact host or a wildcard such as "*.example.com". Empty means the
	// target host itself is allowed.
	AllowedHosts []string
	// AllowedPorts restricts ports; empty means the target port is allowed.
	AllowedPorts []int
	// AllowedSchemes restricts schemes ("http", "https"); empty means the
	// target scheme is allowed.
	AllowedSchemes []string
	// PathPrefixes restricts paths; empty means all paths are allowed.
	// Matching is performed on the normalized, lower-cased path.
	PathPrefixes []string

	// ExcludeHosts are host patterns that must never be probed.
	ExcludeHosts []string
	// ExcludePathPrefixes are path prefixes that must never be probed.
	ExcludePathPrefixes []string
}

// Scope is a compiled, ready-to-use authorization set.
type Scope struct {
	rule         Rule
	targetHost   string
	targetPort   int
	targetScheme string
}

// New compiles a Rule for the given normalized target URL.
func New(rule Rule, target string) (*Scope, error) {
	canon, err := normalize.CanonicalURL(target)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(canon)
	if err != nil {
		return nil, err
	}
	s := &Scope{
		rule:         rule,
		targetHost:   u.Hostname(),
		targetScheme: u.Scheme,
	}
	s.targetPort = effectivePort(u)
	return s, nil
}

func effectivePort(u *url.URL) int {
	if p := u.Port(); p != "" {
		n, _ := strconv.Atoi(p)
		return n
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

// Allowed reports whether rawURL may be probed. The URL is normalized before
// the decision. The second return value is a stable, human-readable reason
// suitable for audit logs. No HTTP request must ever be issued for a URL
// that is not allowed.
func (s *Scope) Allowed(rawURL string) (bool, string) {
	canon, err := normalize.CanonicalURL(rawURL)
	if err != nil {
		return false, "invalid URL: " + err.Error()
	}
	u, err := url.Parse(canon)
	if err != nil {
		return false, "invalid URL: " + err.Error()
	}

	host := u.Hostname()
	port := effectivePort(u)
	scheme := u.Scheme
	path := strings.ToLower(u.Path)

	// Exclusions take precedence over allow rules.
	if hostMatches(s.rule.ExcludeHosts, host) {
		return false, "excluded host"
	}
	if prefixMatches(s.rule.ExcludePathPrefixes, path) {
		return false, "excluded path prefix"
	}

	if len(s.rule.AllowedSchemes) > 0 {
		if !stringInSlice(scheme, s.rule.AllowedSchemes) {
			return false, "scheme not allowed"
		}
	} else if scheme != s.targetScheme {
		return false, "scheme not allowed"
	}

	if len(s.rule.AllowedPorts) > 0 {
		if !intInSlice(port, s.rule.AllowedPorts) {
			return false, "port not allowed"
		}
	} else if port != s.targetPort {
		return false, "port not allowed"
	}

	if len(s.rule.AllowedHosts) > 0 {
		if !hostMatches(s.rule.AllowedHosts, host) {
			return false, "host not allowed"
		}
	} else if host != s.targetHost {
		return false, "host not allowed"
	}

	if len(s.rule.PathPrefixes) > 0 {
		if !prefixMatches(s.rule.PathPrefixes, path) {
			return false, "path prefix not allowed"
		}
	}

	return true, ""
}

func hostMatches(patterns []string, host string) bool {
	host = strings.ToLower(host)
	for _, pat := range patterns {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat == "" {
			continue
		}
		if pat == host {
			return true
		}
		if strings.HasPrefix(pat, "*.") {
			domain := pat[2:]
			if host == domain || strings.HasSuffix(host, "."+domain) {
				return true
			}
		}
	}
	return false
}

func prefixMatches(prefixes []string, path string) bool {
	for _, p := range prefixes {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		p = strings.TrimRight(p, "/")
		if p == "" {
			return true
		}
		if path == p || strings.HasPrefix(path, p+"/") || strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func stringInSlice(v string, xs []string) bool {
	for _, x := range xs {
		if strings.EqualFold(v, x) {
			return true
		}
	}
	return false
}

func intInSlice(v int, xs []int) bool {
	for _, x := range xs {
		if v == x {
			return true
		}
	}
	return false
}
