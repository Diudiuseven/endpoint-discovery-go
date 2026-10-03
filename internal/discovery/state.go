package discovery

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
)

// stateEvent is one append-only checkpoint record.
type stateEvent struct {
	Op      string   `json:"op"` // "discover" | "finding" | "done"
	Key     string   `json:"key"`
	Finding *Finding `json:"finding,omitempty"`
}

// StateStore persists scan progress as an append-only JSONL log so
// interrupted runs resume without duplicates or omissions. A key is marked
// done only after its result is fully determined; keys discovered but not
// done are re-enqueued on resume.
type StateStore struct {
	mu         sync.Mutex
	path       string
	file       *os.File // nil for in-memory
	discovered map[string]bool
	done       map[string]bool
	findings   map[string]Finding
}

// OpenStateStore loads existing progress from path (empty path = in-memory
// only). Corrupt trailing lines (e.g. from a crash mid-write) are ignored.
func OpenStateStore(path string) (*StateStore, error) {
	s := &StateStore{
		path:       path,
		discovered: map[string]bool{},
		done:       map[string]bool{},
		findings:   map[string]Finding{},
	}
	if path == "" {
		return s, nil
	}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			var ev stateEvent
			if json.Unmarshal(sc.Bytes(), &ev) != nil {
				continue // tolerate torn tail
			}
			s.apply(ev)
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("open state file: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open state file for append: %w", err)
	}
	s.file = f
	return s, nil
}

func (s *StateStore) apply(ev stateEvent) {
	switch ev.Op {
	case "discover":
		s.discovered[ev.Key] = true
	case "finding":
		if ev.Finding != nil {
			s.discovered[ev.Key] = true
			s.findings[ev.Key] = *ev.Finding
		}
	case "done":
		s.discovered[ev.Key] = true
		s.done[ev.Key] = true
	}
}

func (s *StateStore) record(ev stateEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		if _, err := s.file.Write(append(b, '\n')); err != nil {
			return fmt.Errorf("write state: %w", err)
		}
		if err := s.file.Sync(); err != nil {
			return fmt.Errorf("sync state: %w", err)
		}
	}
	s.apply(ev)
	return nil
}

// Done reports whether a canonical key is confirmed complete.
func (s *StateStore) Done(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.done[key]
}

// Known reports whether a key was ever discovered (enqueued).
func (s *StateStore) Known(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.discovered[key]
}

// MarkDone durably records a key as complete.
func (s *StateStore) MarkDone(key string) error {
	return s.record(stateEvent{Op: "done", Key: key})
}

// MarkDiscovered durably records a key as known (enqueued but not done).
func (s *StateStore) MarkDiscovered(key string) error {
	return s.record(stateEvent{Op: "discover", Key: key})
}

// MarkDiscoveredIfNew atomically checks-and-records a key, reporting whether
// it was new. This makes dynamic expansion race-free: exactly one caller
// wins and enqueues the key.
func (s *StateStore) MarkDiscoveredIfNew(key string) (bool, error) {
	s.mu.Lock()
	if s.discovered[key] {
		s.mu.Unlock()
		return false, nil
	}
	s.mu.Unlock()
	if err := s.record(stateEvent{Op: "discover", Key: key}); err != nil {
		return false, err
	}
	return true, nil
}

// Discovered returns all known keys, sorted for deterministic output.
func (s *StateStore) Discovered() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.discovered))
	for k := range s.discovered {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Pending returns discovered-but-not-done keys, sorted.
func (s *StateStore) Pending() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []string{}
	for k := range s.discovered {
		if !s.done[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// RecordFinding durably stores the finding for a key. It is recorded before
// the key is marked done; a crash in between simply re-records it on retry.
func (s *StateStore) RecordFinding(key string, f Finding) error {
	f.body = nil // never persist response bodies
	return s.record(stateEvent{Op: "finding", Key: key, Finding: &f})
}

// Findings returns all persisted findings, sorted by path for determinism.
func (s *StateStore) Findings() []Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Finding, 0, len(s.findings))
	for _, f := range s.findings {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Class < out[j].Class
	})
	return out
}

// Close flushes and closes the store.
func (s *StateStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		err := s.file.Close()
		s.file = nil
		return err
	}
	return nil
}
