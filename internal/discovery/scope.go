package discovery

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Scope decides which URLs may be requested. All rules are matched against
// normalized URLs so equivalent spellings cannot bypass policy.
type Scope struct {
	schemes   map[string]bool
	hosts     map[string]bool
	ports     map[int]bool
	prefixes  []string // normalized allowed path prefixes
	excludes  []string // normalized excluded path prefixes
	targetKey string   // canonical key of the scan root
}

// NewScope builds a Scope from cfg, normalizing the target first. Empty
// allow-lists default to the target's own scheme/host/port/path-prefix.
func NewScope(cfg *Config) (*Scope, error) {
	t, err := NormalizeURL(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}
	s := &Scope{
		schemes:   map[string]bool{},
		hosts:     map[string]bool{},
		ports:     map[int]bool{},
		targetKey: CanonicalKey(t),
	}
	if len(cfg.AllowedSchemes) == 0 {
		s.schemes[t.Scheme] = true
	} else {
		for _, sc := range cfg.AllowedSchemes {
			sc = strings.ToLower(strings.TrimSpace(sc))
			if sc != "http" && sc != "https" {
				return nil, fmt.Errorf("unsupported allowed scheme %q", sc)
			}
			s.schemes[sc] = true
		}
	}
	if len(cfg.AllowedHosts) == 0 {
		s.hosts[strings.ToLower(t.Hostname())] = true
	} else {
		for _, h := range cfg.AllowedHosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				return nil, fmt.Errorf("empty allowed host")
			}
			s.hosts[h] = true
		}
	}
	if len(cfg.AllowedPorts) == 0 {
		p, _ := strconv.Atoi(t.Port())
		s.ports[p] = true
	} else {
		for _, p := range cfg.AllowedPorts {
			if p <= 0 || p > 65535 {
				return nil, fmt.Errorf("invalid allowed port %d", p)
			}
			s.ports[p] = true
		}
	}
	if len(cfg.AllowedPathPrefixes) == 0 {
		// Default: the directory of the target path.
		base := CanonicalPath(t.Path)
		if base != "/" && !strings.HasSuffix(base, "/") {
			base += "/"
		}
		s.prefixes = []string{base}
	} else {
		for _, p := range cfg.AllowedPathPrefixes {
			s.prefixes = append(s.prefixes, ensureDirPrefix(CanonicalPath(p)))
		}
	}
	for _, p := range cfg.ExcludePathPrefixes {
		s.excludes = append(s.excludes, ensureDirPrefix(CanonicalPath(p)))
	}
	return s, nil
}

// ensureDirPrefix makes prefix matching segment-safe: "/app" matches
// "/app/x" but not "/apple".
func ensureDirPrefix(p string) string {
	if p != "/" && !strings.HasSuffix(p, "/") {
		return p + "/"
	}
	return p
}

// TargetKey returns the canonical key of the scan root.
func (s *Scope) TargetKey() string { return s.targetKey }

// Allow reports whether u is in scope. Out-of-scope URLs must never be
// requested.
func (s *Scope) Allow(u *url.URL) bool {
	if u == nil {
		return false
	}
	if !s.schemes[strings.ToLower(u.Scheme)] {
		return false
	}
	if !s.hosts[strings.ToLower(u.Hostname())] {
		return false
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	pn, err := strconv.Atoi(port)
	if err != nil || !s.ports[pn] {
		return false
	}
	path := CanonicalPath(u.Path)
	for _, ex := range s.excludes {
		if pathMatchesPrefix(path, ex) {
			return false
		}
	}
	for _, pre := range s.prefixes {
		if pathMatchesPrefix(path, pre) {
			return true
		}
	}
	return false
}

// pathMatchesPrefix reports whether path equals the prefix directory or
// lives under it. pre is dir-normalized (ends with "/" unless root).
func pathMatchesPrefix(path, pre string) bool {
	if pre == "/" {
		return true
	}
	return strings.HasPrefix(path, pre) || path+"/" == pre
}
