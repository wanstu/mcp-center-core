package mcpcenter

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type state struct {
	Version int          `json:"version"`
	MCPs    []Definition `json:"mcps"`
}

type FileStore struct {
	path string
	mu   sync.Mutex
}

func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("mcp-center-core: store path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mcp-center-core: create store directory: %w", err)
	}
	s := &FileStore{path: path}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	if st.Version == 0 {
		st.Version = 1
		return s, s.saveLocked(st)
	}
	return s, nil
}

func (s *FileStore) Path() string { return s.path }

func (s *FileStore) List() ([]Definition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	out := make([]Definition, len(st.MCPs))
	for i := range st.MCPs {
		out[i] = cloneDefinition(st.MCPs[i])
	}
	return out, nil
}

func (s *FileStore) Get(id string) (Definition, error) {
	items, err := s.List()
	if err != nil {
		return Definition{}, err
	}
	for _, item := range items {
		if item.ID == id {
			return item, nil
		}
	}
	return Definition{}, fmt.Errorf("mcp %q not found", id)
}

func (s *FileStore) Put(def Definition) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return err
	}
	for i := range st.MCPs {
		if st.MCPs[i].ID == def.ID {
			st.MCPs[i] = cloneDefinition(def)
			return s.saveLocked(st)
		}
	}
	st.MCPs = append(st.MCPs, cloneDefinition(def))
	return s.saveLocked(st)
}

func (s *FileStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return err
	}
	for i := range st.MCPs {
		if st.MCPs[i].ID == id {
			st.MCPs = append(st.MCPs[:i], st.MCPs[i+1:]...)
			return s.saveLocked(st)
		}
	}
	return fmt.Errorf("mcp %q not found", id)
}

func (s *FileStore) loadLocked() (state, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return state{Version: 1, MCPs: []Definition{}}, nil
	}
	if err != nil {
		return state{}, fmt.Errorf("mcp-center-core: read store: %w", err)
	}
	if len(data) == 0 {
		return state{Version: 1, MCPs: []Definition{}}, nil
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return state{}, fmt.Errorf("mcp-center-core: decode store: %w", err)
	}
	if st.MCPs == nil {
		st.MCPs = []Definition{}
	}
	return st, nil
}

func (s *FileStore) saveLocked(st state) error {
	if st.Version == 0 {
		st.Version = 1
	}
	if st.MCPs == nil {
		st.MCPs = []Definition{}
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("mcp-center-core: encode store: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".mcp-center-*.tmp")
	if err != nil {
		return fmt.Errorf("mcp-center-core: create temp store: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		_ = os.Remove(s.path)
		if err2 := os.Rename(tmpName, s.path); err2 != nil {
			return fmt.Errorf("mcp-center-core: replace store: %w", err2)
		}
	}
	return nil
}

func cloneDefinition(in Definition) Definition {
	in.Args = append([]string(nil), in.Args...)
	in.HeaderRefs = cloneMap(in.HeaderRefs)
	in.EnvRefs = cloneMap(in.EnvRefs)
	return in
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
