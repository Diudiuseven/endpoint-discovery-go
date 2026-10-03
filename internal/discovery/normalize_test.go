package discovery

import "testing"

func TestNormalizeURL(t *testing.T) {
	u, err := NormalizeURL("HTTP://Example.COM:8080/App/")
	if err != nil {
		t.Fatal(err)
	}
	if got := u.String(); got != "http://example.com:8080/app" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeURLDefaultPort(t *testing.T) {
	u, err := NormalizeURL("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.Port() != "443" {
		t.Fatalf("port = %q", u.Port())
	}
	if u.Path != "/" {
		t.Fatalf("path = %q", u.Path)
	}
}

func TestCanonicalKeyDedup(t *testing.T) {
	variants := []string{
		"http://example.com:80/Admin/Panel",
		"http://example.com/admin/panel/",
		"http://example.com/admin/panel?a=1",
		"http://example.com/admin/panel?b=2&a=1",
		"http://example.com//admin/./panel",
		"http://EXAMPLE.com/admin/panel#frag",
	}
	var key string
	for i, v := range variants {
		u, err := NormalizeURL(v)
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		k := CanonicalKey(u)
		if i == 0 {
			key = k
			continue
		}
		if k != key {
			t.Fatalf("variant %q key %q != %q", v, k, key)
		}
	}
}

func TestCanonicalPathDotSegments(t *testing.T) {
	cases := map[string]string{
		"/a/b/../c":  "/a/c",
		"/a//b/":     "/a/b",
		"/":          "/",
		"":           "/",
		"admin":      "/admin",
		"/a/./b":     "/a/b",
		"/../secret": "/secret",
		"/UP/Case/":  "/up/case",
	}
	for in, want := range cases {
		if got := CanonicalPath(in); got != want {
			t.Errorf("CanonicalPath(%q) = %q, want %q", in, got, want)
		}
	}
}
