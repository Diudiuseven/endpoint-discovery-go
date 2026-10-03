package discovery

import "testing"

func scopeFor(t *testing.T, cfg Config) *Scope {
	t.Helper()
	s, err := NewScope(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func allow(t *testing.T, s *Scope, raw string) bool {
	t.Helper()
	u, err := NormalizeURL(raw)
	if err != nil {
		t.Fatalf("normalize %q: %v", raw, err)
	}
	return s.Allow(u)
}

func TestScopeDefaultsToTarget(t *testing.T) {
	s := scopeFor(t, Config{Target: "http://127.0.0.1:8080/app"})
	if !allow(t, s, "http://127.0.0.1:8080/app/admin") {
		t.Error("same-prefix path should be allowed")
	}
	if allow(t, s, "http://127.0.0.1:8080/other") {
		t.Error("different prefix should be denied")
	}
	if allow(t, s, "http://127.0.0.1:9090/app/admin") {
		t.Error("different port should be denied")
	}
	if allow(t, s, "http://evil.example.com/app/admin") {
		t.Error("unauthorized host should be denied")
	}
	if allow(t, s, "https://127.0.0.1:8080/app/admin") {
		t.Error("different scheme should be denied")
	}
}

func TestScopePrefixSegmentSafety(t *testing.T) {
	s := scopeFor(t, Config{Target: "http://h:80/", AllowedPathPrefixes: []string{"/app"}})
	if !allow(t, s, "http://h:80/app/x") {
		t.Error("/app/x should be allowed")
	}
	if !allow(t, s, "http://h:80/app") {
		t.Error("/app itself should be allowed")
	}
	if allow(t, s, "http://h:80/apple") {
		t.Error("/apple must not match prefix /app")
	}
}

func TestScopeExcludeWins(t *testing.T) {
	s := scopeFor(t, Config{
		Target:              "http://h:80/",
		AllowedPathPrefixes: []string{"/app"},
		ExcludePathPrefixes: []string{"/app/admin"},
	})
	if allow(t, s, "http://h:80/app/admin/panel") {
		t.Error("excluded prefix should be denied")
	}
	if !allow(t, s, "http://h:80/app/public") {
		t.Error("non-excluded path should be allowed")
	}
}

func TestScopeNormalizationEquivalence(t *testing.T) {
	s := scopeFor(t, Config{Target: "http://h:80/", AllowedPathPrefixes: []string{"/APP"}})
	// Rules and URLs are normalized, so case/trailing-slash variants of a
	// denied or allowed path behave identically.
	if !allow(t, s, "http://h:80/app/x") {
		t.Error("normalized prefix should match case-insensitively")
	}
}
