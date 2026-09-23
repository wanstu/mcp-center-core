package mcpcenter

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type AuditContext struct {
	RequestID     string `json:"request_id,omitempty"`
	Source        string `json:"source,omitempty"`
	PrincipalID   string `json:"principal_id,omitempty"`
	PrincipalName string `json:"principal_name,omitempty"`
	AuthChannel   string `json:"auth_channel,omitempty"`
}

type AuditEvent struct {
	RequestID     string         `json:"request_id"`
	Source        string         `json:"source,omitempty"`
	PrincipalID   string         `json:"principal_id,omitempty"`
	PrincipalName string         `json:"principal_name,omitempty"`
	AuthChannel   string         `json:"auth_channel,omitempty"`
	MCPID         string         `json:"mcp_id"`
	ToolName      string         `json:"tool_name"`
	StartedAt     time.Time      `json:"started_at"`
	DurationMS    int64          `json:"duration_ms"`
	Status        string         `json:"status"`
	ErrorKind     string         `json:"error_kind,omitempty"`
	InputMeta     map[string]any `json:"input_meta,omitempty"`
	OutputMeta    map[string]any `json:"output_meta,omitempty"`
}

type AuditSink interface {
	Record(context.Context, AuditEvent) error
}

type auditContextKey struct{}

func WithAuditContext(ctx context.Context, value AuditContext) context.Context {
	return context.WithValue(ctx, auditContextKey{}, value)
}

func AuditContextFrom(ctx context.Context) AuditContext {
	if ctx == nil {
		return AuditContext{}
	}
	value, _ := ctx.Value(auditContextKey{}).(AuditContext)
	return value
}

func (s *Service) SetAuditSink(sink AuditSink) {
	s.auditMu.Lock()
	s.auditSink = sink
	s.auditMu.Unlock()
}

func (s *Service) emitAudit(ctx context.Context, event AuditEvent) {
	s.auditMu.RLock()
	sink := s.auditSink
	s.auditMu.RUnlock()
	if sink != nil {
		_ = sink.Record(ctx, event)
	}
}

func newAuditEvent(ctx context.Context, mcpID, toolName string, started time.Time, arguments map[string]any, result *mcp.CallToolResult, callErr error) AuditEvent {
	meta := AuditContextFrom(ctx)
	if meta.RequestID == "" {
		if id, err := newID("req"); err == nil {
			meta.RequestID = id
		}
	}
	event := AuditEvent{
		RequestID: meta.RequestID, Source: meta.Source,
		PrincipalID: meta.PrincipalID, PrincipalName: meta.PrincipalName, AuthChannel: meta.AuthChannel,
		MCPID: mcpID, ToolName: toolName, StartedAt: started.UTC(),
		DurationMS: time.Since(started).Milliseconds(), Status: "success",
		InputMeta: summarizeArguments(arguments), OutputMeta: summarizeCallResult(result),
	}
	if callErr != nil {
		event.Status = "error"
		event.ErrorKind = ClassifyError(callErr)
	} else if result != nil && result.IsError {
		event.Status = "error"
		event.ErrorKind = "tool_error"
	}
	return event
}

func summarizeArguments(arguments map[string]any) map[string]any {
	if len(arguments) == 0 {
		return map[string]any{"key_count": 0, "keys": []string{}}
	}
	keys := make([]string, 0, len(arguments))
	types := make(map[string]string, len(arguments))
	for key, value := range arguments {
		keys = append(keys, key)
		types[key] = valueType(value)
	}
	sort.Strings(keys)
	return map[string]any{"key_count": len(keys), "keys": keys, "value_types": types}
}

func summarizeCallResult(result *mcp.CallToolResult) map[string]any {
	if result == nil {
		return nil
	}
	return map[string]any{
		"content_count":          len(result.Content),
		"is_error":               result.IsError,
		"has_structured_content": result.StructuredContent != nil,
	}
}

func valueType(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "bool"
	case float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "number"
	case []any:
		return fmt.Sprintf("array(%d)", len(v))
	case map[string]any:
		return fmt.Sprintf("object(%d)", len(v))
	default:
		return fmt.Sprintf("%T", value)
	}
}
