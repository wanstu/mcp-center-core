package mcpcenter

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const stdioTestServerEnv = "_MCP_CENTER_CORE_STDIO_TEST_SERVER"

type stdioEchoArgs struct {
	Message string `json:"message"`
}

func TestMain(m *testing.M) {
	if os.Getenv(stdioTestServerEnv) == "1" {
		server := mcp.NewServer(&mcp.Implementation{Name: "core-stdio-test", Version: "1.0.0"}, nil)
		mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "echo a message"}, func(ctx context.Context, req *mcp.CallToolRequest, args stdioEchoArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + args.Message}}}, nil, nil
		})
		if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			log.Printf("stdio test server failed: %v", err)
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStdioSessionOutlivesCreatingRequestContext(t *testing.T) {
	t.Setenv(stdioTestServerEnv, "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(t.TempDir() + "/mcps.json")
	if err != nil {
		t.Fatal(err)
	}
	svc := New(store)
	def, err := svc.Add(Config{
		Name:       "stdio-runtime",
		Transport:  TransportStdio,
		AuthMode:   AuthNone,
		Executable: executable,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Disconnect(def.ID) })

	firstCtx, cancel := context.WithCancel(context.Background())
	tools, err := svc.ListTools(firstCtx, def.ID)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if len(tools) != 1 || tools[0].Name != "echo" {
		cancel()
		t.Fatalf("unexpected tools: %#v", tools)
	}

	// Simulate the HTTP/admin request that created the reusable session ending.
	cancel()
	time.Sleep(150 * time.Millisecond)

	result, err := svc.CallTool(context.Background(), def.ID, "echo", map[string]any{"message": "after-request"})
	if err != nil {
		t.Fatalf("stdio session died with creating request context: %v", err)
	}
	if len(result.Content) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok || textContent.Text != "echo:after-request" {
		t.Fatalf("unexpected echo result: %#v", result.Content)
	}

	status, err := svc.RuntimeStatus(def.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != RuntimeConnected {
		t.Fatalf("stdio session should remain connected: %#v", status)
	}
}
