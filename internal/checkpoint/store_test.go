package checkpoint

import (
	"path/filepath"
	"testing"
)

func TestStoreLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cp.json")

	s, err := Open(path, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	t1 := Task{Identity: "http://example.com/a", URL: "http://example.com/a", Source: "wordlist"}
	if err := s.AddPending(t1); err != nil {
		t.Fatal(err)
	}
	if got := len(s.Pending()); got != 1 {
		t.Fatalf("pending = %d, want 1", got)
	}

	// Reopen: pending must survive.
	s2, err := Open(path, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(s2.Pending()); got != 1 {
		t.Fatalf("after reopen pending = %d, want 1", got)
	}

	// Complete: moves to done.
	r := Result{Identity: t1.Identity, URL: t1.URL, Grade: "available", StatusCode: 200}
	if err := s2.Complete(t1, r); err != nil {
		t.Fatal(err)
	}
	if s2.Has(t1.Identity) != true {
		t.Error("completed task should be marked done")
	}
	if got := len(s2.Pending()); got != 0 {
		t.Errorf("pending after complete = %d, want 0", got)
	}

	// Reopen again: done must survive.
	s3, err := Open(path, "http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !s3.Has(t1.Identity) {
		t.Error("done result must survive restart")
	}
	if got := len(s3.Done()); got != 1 {
		t.Errorf("done = %d, want 1", got)
	}
}

func TestFailStaysPending(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cp.json")
	s, _ := Open(path, "http://example.com")
	t1 := Task{Identity: "http://example.com/a", URL: "http://example.com/a", Source: "wordlist"}
	s.AddPending(t1)
	if err := s.Fail(t1, "connection refused"); err != nil {
		t.Fatal(err)
	}
	if s.Has(t1.Identity) {
		t.Error("failed task must not be marked done")
	}
	if got := len(s.Pending()); got != 1 {
		t.Errorf("pending = %d, want 1", got)
	}
}

func TestDifferentTargetStartsFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cp.json")
	s, _ := Open(path, "http://a.example.com")
	t1 := Task{Identity: "http://a.example.com/x", URL: "http://a.example.com/x", Source: "wordlist"}
	s.AddPending(t1)
	s.Complete(t1, Result{Identity: t1.Identity, URL: t1.URL, Grade: "available", StatusCode: 200})

	s2, err := Open(path, "http://b.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Done()) != 0 || len(s2.Pending()) != 0 {
		t.Error("checkpoint for a different target must start fresh")
	}
}

func TestAddPendingDedup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cp.json")
	s, _ := Open(path, "http://example.com")
	t1 := Task{Identity: "http://example.com/a", URL: "http://example.com/a", Source: "wordlist"}
	s.AddPending(t1)
	s.AddPending(t1) // duplicate
	if got := len(s.Pending()); got != 1 {
		t.Errorf("pending = %d, want 1 (dedup)", got)
	}
}
