package normalize

import "testing"

func TestCanonicalURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"HTTP://EXAMPLE.COM", "http://example.com/"},
		{"http://example.com:80/", "http://example.com/"},
		{"https://example.com:443/", "https://example.com/"},
		{"http://example.com/a/../b", "http://example.com/b"},
		{"http://example.com//a//b", "http://example.com/a/b"},
		{"http://example.com/path?q=1#frag", "http://example.com/path"},
		{"http://example.com", "http://example.com/"},
		{"http://example.com./x", "http://example.com/x"},
	}
	for _, c := range cases {
		got, err := CanonicalURL(c.in)
		if err != nil {
			t.Errorf("CanonicalURL(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("CanonicalURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCanonicalURLErrors(t *testing.T) {
	for _, in := range []string{"", "ftp://example.com", "http://", "://bad"} {
		if _, err := CanonicalURL(in); err == nil {
			t.Errorf("CanonicalURL(%q) expected error", in)
		}
	}
}

func TestIdentityDedup(t *testing.T) {
	variants := []string{
		"http://example.com/Admin",
		"http://example.com/admin/",
		"http://example.com/admin?x=1",
		"http://example.com/admin#frag",
		"HTTP://EXAMPLE.COM/admin",
		"http://example.com:80/admin",
	}
	first, err := Identity(variants[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range variants[1:] {
		got, err := Identity(v)
		if err != nil {
			t.Fatal(err)
		}
		if got != first {
			t.Errorf("Identity(%q) = %q, want %q", v, got, first)
		}
	}
}

func TestIdentityDistinct(t *testing.T) {
	a, _ := Identity("http://example.com/a")
	b, _ := Identity("http://example.com/b")
	if a == b {
		t.Errorf("distinct paths should have distinct identities: %q", a)
	}
}

func TestResolveReference(t *testing.T) {
	cases := []struct {
		base, ref, want string
	}{
		{"http://example.com/dir/page", "other", "http://example.com/dir/other"},
		{"http://example.com/dir/page", "/abs", "http://example.com/abs"},
		{"http://example.com/dir/page", "http://other.com/x", "http://other.com/x"},
		{"http://example.com/", "#frag", ""},
	}
	for _, c := range cases {
		got, err := ResolveReference(c.base, c.ref)
		if c.want == "" {
			if err == nil {
				t.Errorf("ResolveReference(%q,%q) expected error", c.base, c.ref)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveReference(%q,%q) error: %v", c.base, c.ref, err)
			continue
		}
		if got != c.want {
			t.Errorf("ResolveReference(%q,%q) = %q, want %q", c.base, c.ref, got, c.want)
		}
	}
}
