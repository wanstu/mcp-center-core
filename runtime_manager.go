package mcpcenter

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type RuntimeState string

const (
	RuntimeDisconnected RuntimeState = "disconnected"
	RuntimeConnected    RuntimeState = "connected"
	RuntimeError        RuntimeState = "error"
)

type RuntimeStatus struct {
	MCPID       string       `json:"mcp_id"`
	State       RuntimeState `json:"state"`
	ConnectedAt *time.Time   `json:"connected_at,omitempty"`
	LastUsedAt  *time.Time   `json:"last_used_at,omitempty"`
	ToolCount   int          `json:"tool_count"`
	ErrorKind   string       `json:"error_kind,omitempty"`
	LastError   string       `json:"last_error,omitempty"`
}

type runtimeEntry struct {
	mu sync.Mutex

	session       *mcp.ClientSession
	sessionCancel context.CancelFunc
	connectedAt   time.Time
	lastUsedAt    time.Time
	tools         []Tool
	toolsLoaded   bool
	errorKind     string
	lastError     string
}

func (s *Service) runtimeEntry(id string) *runtimeEntry {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	if s.runtime == nil {
		s.runtime = map[string]*runtimeEntry{}
	}
	entry := s.runtime[id]
	if entry == nil {
		entry = &runtimeEntry{}
		s.runtime[id] = entry
	}
	return entry
}

func (s *Service) RuntimeStatus(id string) (RuntimeStatus, error) {
	if _, err := s.Get(id); err != nil {
		return RuntimeStatus{}, err
	}
	s.runtimeMu.Lock()
	entry := s.runtime[id]
	s.runtimeMu.Unlock()
	if entry == nil {
		return RuntimeStatus{MCPID: id, State: RuntimeDisconnected}, nil
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return runtimeStatusLocked(id, entry), nil
}

func (s *Service) RuntimeStatuses() ([]RuntimeStatus, error) {
	definitions, err := s.List()
	if err != nil {
		return nil, err
	}
	out := make([]RuntimeStatus, 0, len(definitions))
	for _, def := range definitions {
		status, err := s.RuntimeStatus(def.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, status)
	}
	return out, nil
}

func (s *Service) Refresh(ctx context.Context, id string) ([]Tool, error) {
	entry := s.runtimeEntry(id)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	session, err := s.ensureSessionLocked(ctx, id, entry)
	if err != nil {
		return nil, err
	}
	tools, err := listToolsFromSession(ctx, session)
	entry.lastUsedAt = s.now().UTC()
	if err != nil {
		s.failSessionLocked(entry, err)
		return nil, err
	}
	entry.tools = cloneTools(tools)
	entry.toolsLoaded = true
	entry.errorKind = ""
	entry.lastError = ""
	return cloneTools(tools), nil
}

func (s *Service) Disconnect(id string) error {
	if _, err := s.Get(id); err != nil {
		return err
	}
	s.invalidateRuntime(id)
	return nil
}

func (s *Service) DisconnectAll() {
	s.runtimeMu.Lock()
	entries := s.runtime
	s.runtime = map[string]*runtimeEntry{}
	s.runtimeMu.Unlock()
	for _, entry := range entries {
		entry.mu.Lock()
		closeRuntimeSessionLocked(entry)
		entry.tools = nil
		entry.toolsLoaded = false
		entry.errorKind = ""
		entry.lastError = ""
		entry.mu.Unlock()
	}
}

func (s *Service) invalidateRuntime(id string) {
	s.runtimeMu.Lock()
	entry := s.runtime[id]
	delete(s.runtime, id)
	s.runtimeMu.Unlock()
	if entry == nil {
		return
	}
	entry.mu.Lock()
	closeRuntimeSessionLocked(entry)
	entry.tools = nil
	entry.toolsLoaded = false
	entry.errorKind = ""
	entry.lastError = ""
	entry.mu.Unlock()
}

func (s *Service) ensureSessionLocked(ctx context.Context, id string, entry *runtimeEntry) (*mcp.ClientSession, error) {
	if entry.session != nil {
		return entry.session, nil
	}
	session, sessionCancel, err := s.connectFresh(ctx, id)
	if err != nil {
		entry.errorKind = ClassifyError(err)
		entry.lastError = err.Error()
		return nil, err
	}
	now := s.now().UTC()
	entry.session = session
	entry.sessionCancel = sessionCancel
	entry.connectedAt = now
	entry.lastUsedAt = now
	entry.errorKind = ""
	entry.lastError = ""
	return session, nil
}

func (s *Service) failSessionLocked(entry *runtimeEntry, err error) {
	entry.errorKind = ClassifyError(err)
	entry.lastError = err.Error()
	closeRuntimeSessionLocked(entry)
	entry.tools = nil
	entry.toolsLoaded = false
}

func closeRuntimeSessionLocked(entry *runtimeEntry) {
	if entry.sessionCancel != nil {
		entry.sessionCancel()
		entry.sessionCancel = nil
	}
	if entry.session != nil {
		_ = entry.session.Close()
		entry.session = nil
	}
	entry.connectedAt = time.Time{}
}

func runtimeStatusLocked(id string, entry *runtimeEntry) RuntimeStatus {
	status := RuntimeStatus{
		MCPID:     id,
		State:     RuntimeDisconnected,
		ToolCount: len(entry.tools),
		ErrorKind: entry.errorKind,
		LastError: entry.lastError,
	}
	if !entry.connectedAt.IsZero() {
		value := entry.connectedAt.UTC()
		status.ConnectedAt = &value
	}
	if !entry.lastUsedAt.IsZero() {
		value := entry.lastUsedAt.UTC()
		status.LastUsedAt = &value
	}
	switch {
	case entry.session != nil:
		status.State = RuntimeConnected
	case entry.lastError != "":
		status.State = RuntimeError
	}
	return status
}

func cloneTools(input []Tool) []Tool {
	if len(input) == 0 {
		return nil
	}
	out := make([]Tool, len(input))
	copy(out, input)
	return out
}

func listToolsFromSession(ctx context.Context, session *mcp.ClientSession) ([]Tool, error) {
	if session == nil {
		return nil, errors.New("runtime session is not connected")
	}
	result, err := session.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	tools := make([]Tool, 0, len(result.Tools))
	for _, tool := range result.Tools {
		tools = append(tools, Tool{
			Name: tool.Name, Title: tool.Title, Description: tool.Description, InputSchema: tool.InputSchema,
		})
	}
	return tools, nil
}
