package scope

import "testing"

func TestScopeDefaultTarget(t *testing.T) {
	s, err := New(Rule{}, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	allowed := []string{
		"http://example.com/",
		"http://example.com:80/a",
		"https://example.com/", // different scheme
	}
	// Note: https vs http — default rule locks scheme to target scheme.
	for _, u := range allowed[:2] {
		if ok, _ := s.Allowed(u); !ok {
			t.Errorf("expected allowed: %s", u)
		}
	}
	denied := []string{
		"http://other.com/",
		"http://example.com:8080/",
		"https://example.com/",
	}
	for _, u := range denied {
		if ok, _ := s.Allowed(u); ok {
			t.Errorf("expected denied: %s", u)
		}
	}
}

func TestScopeWildcardHost(t *testing.T) {
	s, err := New(Rule{AllowedHosts: []string{"*.example.com"}}, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"http://example.com/", "http://a.example.com/", "http://b.a.example.com/"} {
		if ok, _ := s.Allowed(u); !ok {
			t.Errorf("expected allowed: %s", u)
		}
	}
	if ok, _ := s.Allowed("http://notexample.com/"); ok {
		t.Error("expected denied: notexample.com")
	}
}

func TestScopeExclusions(t *testing.T) {
	s, err := New(Rule{
		AllowedHosts:        []string{"example.com"},
		ExcludeHosts:        []string{"admin.example.com"},
		ExcludePathPrefixes: []string{"/logout"},
	}, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Allowed("http://admin.example.com/"); ok {
		t.Error("excluded host should be denied")
	}
	if ok, _ := s.Allowed("http://example.com/logout"); ok {
		t.Error("excluded path should be denied")
	}
	if ok, _ := s.Allowed("http://example.com/logout/confirm"); ok {
		t.Error("excluded sub-path should be denied")
	}
	if ok, _ := s.Allowed("http://example.com/login"); !ok {
		t.Error("login should be allowed")
	}
}

func TestScopePathPrefix(t *testing.T) {
	s, err := New(Rule{PathPrefixes: []string{"/app"}}, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Allowed("http://example.com/app/dashboard"); !ok {
		t.Error("/app/dashboard should be allowed")
	}
	if ok, _ := s.Allowed("http://example.com/other"); ok {
		t.Error("/other should be denied")
	}
}

func TestScopeNormalizationBeforeDecision(t *testing.T) {
	s, err := New(Rule{}, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Case / trailing slash / default port variants must all be allowed.
	for _, u := range []string{"HTTP://EXAMPLE.COM/Admin/", "http://example.com:80/admin"} {
		if ok, _ := s.Allowed(u); !ok {
			t.Errorf("expected allowed after normalization: %s", u)
		}
	}
}

func TestScopeRejectsBeforeRequest(t *testing.T) {
	// The engine must not issue requests for denied URLs; verify the gate
	// decision is available and stable.
	s, err := New(Rule{}, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	ok1, reason1 := s.Allowed("http://other.com/")
	ok2, reason2 := s.Allowed("http://other.com/")
	if ok1 || ok2 {
		t.Error("out-of-scope host must be denied")
	}
	if reason1 != reason2 {
		t.Error("decision must be stable across calls")
	}
}
