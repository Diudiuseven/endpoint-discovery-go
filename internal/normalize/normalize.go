// Package normalize provides URL canonicalization used for scope decisions
// and task de-duplication.
package normalize

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

var defaultPorts = map[string]string{"http": "80", "https": "443"}

// CanonicalURL parses raw and returns a normalized absolute URL string.
// Normalization rules:
//   - scheme is lower-cased and restricted to http/https
//   - host is lower-cased, trailing dot removed, default port stripped
//   - path is normalized (dot segments resolved), empty path becomes "/"
//   - query and fragment are removed
func CanonicalURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme == "" {
		return "", fmt.Errorf("missing scheme in %q", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q in %q", u.Scheme, raw)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("missing host in %q", raw)
	}
	host = strings.TrimSuffix(host, ".")
	port := u.Port()
	if port == defaultPorts[scheme] {
		port = ""
	}
	p := u.Path
	if p == "" {
		p = "/"
	}
	p = path.Clean(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	out := &url.URL{Scheme: scheme, Host: host, Path: p}
	if port != "" {
		out.Host = host + ":" + port
	}
	return out.String(), nil
}

// Identity returns the de-duplication key for a URL:
// scheme://host:port + lower-cased path without trailing slash.
// Query string, fragment, case differences and trailing-slash differences
// do not produce distinct identities.
func Identity(raw string) (string, error) {
	canon, err := CanonicalURL(raw)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(canon)
	if err != nil {
		return "", err
	}
	p := strings.ToLower(u.Path)
	p = strings.TrimRight(p, "/")
	if p == "" {
		p = "/"
	}
	u.Path = p
	u.RawPath = ""
	return u.String(), nil
}

// ResolveReference resolves a (possibly relative) link against base.
// The result is canonicalized.
func ResolveReference(base, ref string) (string, error) {
	baseU, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") {
		return "", errors.New("empty reference")
	}
	refU, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	resolved := baseU.ResolveReference(refU)
	return CanonicalURL(resolved.String())
}

// HostPort returns the normalized host:port (default port stripped).
func HostPort(raw string) (string, error) {
	canon, err := CanonicalURL(raw)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(canon)
	if err != nil {
		return "", err
	}
	return u.Host, nil
}
