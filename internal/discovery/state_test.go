package discovery

import (
	"path/filepath"
	"sync"
	"testing"
)

// TestStateStoreDiscoverIfNewAtomic hammers one key from many goroutines:
// exactly one caller must win, and reopening the checkpoint must show the
// key exactly once as discovered.
func TestStateStoreDiscoverIfNewAtomic(t *testing.T) {
	st, err := OpenStateStore(filepath.Join(t.TempDir(), "s.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	const goroutines = 64
	var wg sync.WaitGroup
	var wins int64
	var mu sync.Mutex
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			isNew, err := st.MarkDiscoveredIfNew("http://h:80/one")
			if err != nil {
				t.Errorf("MarkDiscoveredIfNew: %v", err)
				return
			}
			if isNew {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("winners = %d, want exactly 1", wins)
	}
	path := st.path
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: durable view agrees — one discovered key, not done.
	st2, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if !st2.Known("http://h:80/one") {
		t.Fatal("key not persisted as discovered")
	}
	if st2.Done("http://h:80/one") {
		t.Fatal("key must not be done before MarkDone")
	}
	if p := st2.Pending(); len(p) != 1 || p[0] != "http://h:80/one" {
		t.Fatalf("pending = %v, want [http://h:80/one]", p)
	}
}

// TestStateStoreCompletionIsExplicit verifies that a key only becomes done
// after finding + done events, and that a reopen never promotes a key that
// only has a finding (crash between finding and done) to completed.
func TestStateStoreCompletionIsExplicit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")

	st, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	key := "http://h:80/p"
	if err := st.MarkDiscovered(key); err != nil {
		t.Fatal(err)
	}
	f := Finding{Path: "/p", URL: key, Class: ClassAvailable, StatusCode: 200}
	if err := st.RecordFinding(key, f); err != nil {
		t.Fatal(err)
	}
	// Crash window: finding persisted but done not yet. Still pending.
	st.Close()
	st, err = OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Done(key) {
		t.Fatal("key with finding but no done event must remain uncompleted")
	}
	if got := st.Pending(); len(got) != 1 || got[0] != key {
		t.Fatalf("pending = %v", got)
	}
	// Completing now survives a subsequent reopen.
	if err := st.MarkDone(key); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if !st.Done(key) {
		t.Fatal("done key must stay done after reopen")
	}
	if len(st.Pending()) != 0 {
		t.Fatalf("pending = %v, want empty", st.Pending())
	}
	fs := st.Findings()
	if len(fs) != 1 || fs[0].Path != "/p" || fs[0].Class != ClassAvailable {
		t.Fatalf("findings = %+v", fs)
	}
}

// TestStateStoreFindingsDedupByKey records the same key twice and verifies
// the finding set stays unique (later record replaces, never duplicates).
func TestStateStoreFindingsDedupByKey(t *testing.T) {
	st, _ := OpenStateStore("")
	defer st.Close()
	f1 := Finding{Path: "/x", URL: "http://h:80/x", Class: ClassNotFound, StatusCode: 404}
	f2 := Finding{Path: "/x", URL: "http://h:80/x", Class: ClassAvailable, StatusCode: 200}
	if err := st.RecordFinding("http://h:80/x", f1); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordFinding("http://h:80/x", f2); err != nil {
		t.Fatal(err)
	}
	fs := st.Findings()
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	if fs[0].Class != ClassAvailable {
		t.Fatalf("class = %s, want latest available", fs[0].Class)
	}
}
