package mcpcenter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestLegacySSEConnectionAndImportExport(t *testing.T) {
	upstream := mcp.NewServer(&mcp.Implementation{Name: "legacy-sse", Version: "1"}, nil)
	mcp.AddTool(upstream, &mcp.Tool{Name: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "sse-ok"}}}, nil, nil
	})
	handler := mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return upstream }, nil)
	server := httptest.NewServer(handler)
	defer server.Close()
	store, err := NewFileStore(t.TempDir() + "/mcps.json")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(store)
	def, err := svc.Add(Config{Name: "legacy", Transport: TransportSSE, Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	tools, err := svc.ListTools(ctx, def.ID)
	if err != nil {
		t.Fatalf("SSE tools/list: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "echo" {
		t.Fatalf("tools %#v", tools)
	}
	result, err := svc.CallTool(ctx, def.ID, "echo", map[string]any{})
	if err != nil {
		t.Fatalf("SSE tools/call: %v", err)
	}
	if len(result.Content) != 1 || result.Content[0].(*mcp.TextContent).Text != "sse-ok" {
		t.Fatalf("result %#v", result)
	}
	if err := svc.Disconnect(def.ID); err != nil {
		t.Fatal(err)
	}
	exported, err := svc.ExportJSON(ImportFormatMCPServers)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(exported), `"type": "sse"`) {
		t.Fatalf("SSE type lost: %s", exported)
	}
	other, err := NewFileStore(t.TempDir() + "/other.json")
	if err != nil {
		t.Fatal(err)
	}
	replacement := New(other)
	if _, err = replacement.ImportJSON(exported, ImportFormatMCPServers, ConflictError); err != nil {
		t.Fatal(err)
	}
	loaded, _ := replacement.List()
	if len(loaded) != 1 || loaded[0].Transport != TransportSSE {
		t.Fatalf("round trip: %#v", loaded)
	}
	var obj map[string]any
	if err = json.Unmarshal(exported, &obj); err != nil {
		t.Fatal(err)
	}
}

func TestSSEHeadersAndValidation(t *testing.T) {
	upstream := mcp.NewServer(&mcp.Implementation{Name: "sse-auth", Version: "1"}, nil)
	mcp.AddTool(upstream, &mcp.Tool{Name: "auth_ok"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{}, nil, nil
	})
	handler := mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return upstream }, nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	store, err := NewFileStore(t.TempDir() + "/auth.json")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(store)
	svc.SetVariableLookup(func(name string) (string, bool) { return "test-key", name == "TOKEN" })
	cfg := Config{Name: "header-auth", Transport: TransportSSE, AuthMode: AuthHeaders, Endpoint: server.URL, HeaderRefs: map[string]string{"Authorization": "Bearer ${TOKEN}"}}
	def, err := svc.Add(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Disconnect(def.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	tools, err := svc.ListTools(ctx, def.ID)
	if err != nil || len(tools) != 1 {
		t.Fatalf("authorized SSE tools=%v error=%v", tools, err)
	}
	for _, invalid := range []Config{
		{Name: "bad", Transport: TransportSSE, Endpoint: "not-a-url"},
		{Name: "bad", Transport: TransportSSE, Endpoint: server.URL, Executable: "node"},
		{Name: "bad", Transport: TransportSSE, Endpoint: server.URL, AuthMode: AuthHeaders, HeaderRefs: map[string]string{"Authorization": "Bearer plaintext"}},
	} {
		if _, err := Validate(invalid); err == nil {
			t.Fatalf("must reject %#v", invalid)
		}
	}
}
