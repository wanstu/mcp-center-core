package mcpcenter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRuntimeSessionReuseRefreshDisconnectAndUpdate(t *testing.T) {
	upstream := mcp.NewServer(&mcp.Implementation{Name: "runtime-test", Version: "1.0.0"}, nil)
	upstream.AddTool(&mcp.Tool{Name: "echo", Description: "echo test", InputSchema: map[string]any{"type": "object", "properties": map[string]any{}}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
	})

	var requests atomic.Int64
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return upstream
	}, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
	})
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		handler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()

	store, err := NewFileStore(t.TempDir() + "/mcps.json")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(store)
	def, err := svc.Add(Config{
		Name:      "runtime",
		Transport: TransportStreamableHTTP,
		AuthMode:  AuthNone,
		Endpoint:  httpServer.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	tools, err := svc.ListTools(context.Background(), def.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0].Name != "echo" {
		t.Fatalf("unexpected tools: %#v", tools)
	}
	firstRequests := requests.Load()
	if firstRequests == 0 {
		t.Fatal("expected upstream requests")
	}

	tools, err = svc.ListTools(context.Background(), def.ID)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != firstRequests {
		t.Fatalf("cached tools/list contacted upstream again: before=%d after=%d", firstRequests, requests.Load())
	}

	status, err := svc.RuntimeStatus(def.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != RuntimeConnected || status.ToolCount != 1 || status.ConnectedAt == nil {
		t.Fatalf("unexpected connected status: %#v", status)
	}

	beforeCall := requests.Load()
	result, err := svc.CallTool(context.Background(), def.ID, "echo", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Content) != 1 || requests.Load() <= beforeCall {
		t.Fatalf("tool call did not use upstream: result=%#v requests=%d", result, requests.Load())
	}
	statusAfterCall, _ := svc.RuntimeStatus(def.ID)
	if statusAfterCall.State != RuntimeConnected {
		t.Fatalf("tool call should keep session connected: %#v", statusAfterCall)
	}

	beforeRefresh := requests.Load()
	tools, err = svc.Refresh(context.Background(), def.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || requests.Load() <= beforeRefresh {
		t.Fatalf("refresh did not contact upstream: tools=%#v requests=%d", tools, requests.Load())
	}

	if err := svc.Disconnect(def.ID); err != nil {
		t.Fatal(err)
	}
	status, err = svc.RuntimeStatus(def.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != RuntimeDisconnected || status.ToolCount != 0 {
		t.Fatalf("unexpected disconnected status: %#v", status)
	}

	beforeReconnect := requests.Load()
	if _, err := svc.ListTools(context.Background(), def.ID); err != nil {
		t.Fatal(err)
	}
	if requests.Load() <= beforeReconnect {
		t.Fatal("expected a new connection after disconnect")
	}

	updated, err := svc.Update(def.ID, Config{
		Name:      "runtime",
		Transport: TransportStreamableHTTP,
		AuthMode:  AuthNone,
		Endpoint:  httpServer.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != def.ID {
		t.Fatalf("update changed identity: before=%s after=%s", def.ID, updated.ID)
	}
	status, err = svc.RuntimeStatus(def.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != RuntimeDisconnected {
		t.Fatalf("update should invalidate runtime session: %#v", status)
	}

	statuses, err := svc.RuntimeStatuses()
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].MCPID != def.ID {
		t.Fatalf("unexpected runtime statuses: %#v", statuses)
	}
}

func TestRuntimeFailureIsVisibleAndNextCallCanRetry(t *testing.T) {
	store, err := NewFileStore(t.TempDir() + "/mcps.json")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(store)
	def, err := svc.Add(Config{
		Name:      "offline",
		Transport: TransportStreamableHTTP,
		AuthMode:  AuthNone,
		Endpoint:  "http://127.0.0.1:1/mcp",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.ListTools(context.Background(), def.ID); err == nil {
		t.Fatal("expected connection failure")
	}
	status, err := svc.RuntimeStatus(def.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != RuntimeError || status.LastError == "" || status.ErrorKind == "" {
		t.Fatalf("unexpected error status: %#v", status)
	}

	if err := svc.Disconnect(def.ID); err != nil {
		t.Fatal(err)
	}
	status, _ = svc.RuntimeStatus(def.ID)
	if status.State != RuntimeDisconnected || status.LastError != "" {
		t.Fatalf("disconnect should clear runtime error: %#v", status)
	}
}
