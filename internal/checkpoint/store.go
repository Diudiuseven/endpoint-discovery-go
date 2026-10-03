// Package checkpoint persists engine progress so scans can resume.
package checkpoint

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Task is a discoverable unit of work.
type Task struct {
	Identity string `json:"identity"`
	URL      string `json:"url"`
	Source   string `json:"source"`
}

// Result is a confirmed, classified discovery.
type Result struct {
	Identity   string `json:"identity"`
	URL        string `json:"url"`
	Grade      string `json:"grade"`
	StatusCode int    `json:"status_code"`
	Chain      []Hop  `json:"chain"`
	Source     string `json:"source"`
	Error      string `json:"error,omitempty"`
}

// Hop mirrors httpx.Hop for persistence.
type Hop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

// Data is the on-disk checkpoint state.
type Data struct {
	Version int             `json:"version"`
	Target  string          `json:"target"`
	Pending map[string]Task `json:"pending"`
	Done    map[string]Result `json:"done"`
}

// Store manages checkpoint persistence.
type Store struct {
	mu   sync.Mutex
	path string
	data *Data
}

// Open loads an existing checkpoint or initializes a fresh one.
func Open(path, target string) (*Store, error) {
	s := &Store{
		path: path,
		data: &Data{
			Version: 1,
			Target:  target,
			Pending: make(map[string]Task),
			Done:    make(map[string]Result),
		},
	}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	var loaded Data
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return nil, err
	}
	if loaded.Target != target {
		// Checkpoint belongs to a different target; start fresh.
		return s, nil
	}
	if loaded.Pending == nil {
		loaded.Pending = make(map[string]Task)
	}
	if loaded.Done == nil {
		loaded.Done = make(map[string]Result)
	}
	s.data = &loaded
	return s, nil
}

// Save atomically writes the checkpoint to disk.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".checkpoint-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, s.path)
}

// AddPending records a task as pending (not confirmed). Already-confirmed or
// already-pending identities are ignored.
func (s *Store) AddPending(t Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data.Done[t.Identity]; ok {
		return nil
	}
	if _, ok := s.data.Pending[t.Identity]; ok {
		return nil
	}
	s.data.Pending[t.Identity] = t
	return s.saveLocked()
}

// Complete moves a task from pending to done.
func (s *Store) Complete(t Task, r Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.Pending, t.Identity)
	s.data.Done[t.Identity] = r
	return s.saveLocked()
}

// Fail records that a task exhausted retries without confirmation: it stays
// pending and will be retried on the next run.
func (s *Store) Fail(t Task, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.data.Pending[t.Identity]; ok {
		s.data.Pending[t.Identity] = existing
	} else {
		s.data.Pending[t.Identity] = t
	}
	return s.saveLocked()
}

// Pending returns all pending tasks, sorted by identity for determinism.
func (s *Store) Pending() []Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Task, 0, len(s.data.Pending))
	for _, t := range s.data.Pending {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out
}

// Done returns all confirmed results, sorted by identity for determinism.
func (s *Store) Done() []Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Result, 0, len(s.data.Done))
	for _, r := range s.data.Done {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out
}

// Has reports whether an identity is already confirmed.
func (s *Store) Has(identity string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data.Done[identity]
	return ok
}

// saveLocked writes without locking (caller holds the lock).
func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".checkpoint-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, s.path)
}
