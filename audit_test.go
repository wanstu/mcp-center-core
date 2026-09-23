package mcpcenter

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type captureAuditSink struct {
	events []AuditEvent
}

func (s *captureAuditSink) Record(_ context.Context, event AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func TestAuditEventSummarizesArgumentsWithoutValues(t *testing.T) {
	ctx := WithAuditContext(context.Background(), AuditContext{
		RequestID: "req_test", Source: "proxy", PrincipalID: "cred_1",
		PrincipalName: "ci-agent", AuthChannel: "header",
	})
	event := newAuditEvent(ctx, "mcp_1", "query", time.Now(), map[string]any{
		"password": "super-secret-value",
		"limit":    10,
	}, nil, nil)

	if event.RequestID != "req_test" || event.PrincipalName != "ci-agent" || event.Status != "success" {
		t.Fatalf("unexpected event: %#v", event)
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret-value") {
		t.Fatalf("audit leaked argument value: %s", raw)
	}
	if !strings.Contains(string(raw), "password") || !strings.Contains(string(raw), "number") {
		t.Fatalf("audit summary missing keys/types: %s", raw)
	}
}

func TestAuditErrorClassificationAndSink(t *testing.T) {
	event := newAuditEvent(context.Background(), "mcp_1", "tool", time.Now(), nil, nil, errors.New("connection refused"))
	if event.Status != "error" || event.ErrorKind != "connection_refused" {
		t.Fatalf("unexpected error event: %#v", event)
	}
	toolError := newAuditEvent(context.Background(), "mcp_1", "tool", time.Now(), nil, &mcp.CallToolResult{IsError: true}, nil)
	if toolError.Status != "error" || toolError.ErrorKind != "tool_error" {
		t.Fatalf("unexpected tool error event: %#v", toolError)
	}

	sink := &captureAuditSink{}
	svc := &Service{}
	svc.SetAuditSink(sink)
	svc.emitAudit(context.Background(), event)
	if len(sink.events) != 1 || sink.events[0].ErrorKind != "connection_refused" {
		t.Fatalf("sink did not receive event: %#v", sink.events)
	}
}
