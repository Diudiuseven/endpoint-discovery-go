package discovery

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// NormalizeURL parses raw and returns a canonical URL: lowercase scheme and
// host, explicit port, cleaned path with a single leading slash and no
// trailing slash (except root), query and fragment dropped.
func NormalizeURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", raw, err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil, fmt.Errorf("missing host in %q", raw)
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	u.Host = net.JoinHostPort(host, port)
	u.Path = CanonicalPath(u.Path)
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	return u, nil
}

// CanonicalPath normalizes a path for identity comparison: single leading
// slash, dot segments resolved, lowercased, no trailing slash (root is "/").
func CanonicalPath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// Resolve dot segments without importing path.Clean's trailing-slash
	// behavior surprises; path.Clean is exactly what we want here.
	p = cleanPath(p)
	p = strings.ToLower(p)
	if p != "/" {
		p = strings.TrimRight(p, "/")
		if p == "" {
			p = "/"
		}
	}
	return p
}

func cleanPath(p string) string {
	// Minimal RFC 3986 dot-segment removal on an already-absolute path.
	parts := strings.Split(p, "/")
	out := parts[:0]
	for _, seg := range parts {
		switch seg {
		case "", ".":
			// skip (also collapses repeated slashes)
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	if len(out) == 0 {
		return "/"
	}
	return "/" + strings.Join(out, "/")
}

// CanonicalKey returns the dedup identity of u: scheme://host:port + path.
// Case, trailing-slash and query differences collapse to the same key.
func CanonicalKey(u *url.URL) string {
	return u.Scheme + "://" + u.Host + CanonicalPath(u.Path)
}
