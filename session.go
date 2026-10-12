package mcpcenter

import (
	"context"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Session is a Core-owned MCP client connection. Callers retain their own
// authorization and catalog policies while delegating protocol and lifetime
// handling to Core.
type Session struct {
	client    *mcp.ClientSession
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

// OpenSession connects to an activated stdio, Streamable HTTP, or legacy SSE
// MCP endpoint. The session lives until Close; request cancellation stops
// only connection establishment, not a successfully established SSE stream.
func OpenSession(ctx context.Context, activation Activation) (*Session, error) {
	transport, err := transportFor(activation)
	if err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-center-core", Version: "0.1.0"}, nil)
	connected, cancel, err := connectSessionWithLifetime(ctx, client, transport)
	if err != nil {
		return nil, err
	}
	return &Session{client: connected, cancel: cancel}, nil
}

func (s *Session) InitializeResult() *mcp.InitializeResult {
	return s.client.InitializeResult()
}

func (s *Session) Ping(ctx context.Context, params *mcp.PingParams) error {
	outgoing, release := isolatedMCPContext(ctx)
	defer release()
	// 2026-07-28 removed ping. Use protocol-neutral tools/list on that version.
	if init := s.client.InitializeResult(); init != nil && init.ProtocolVersion >= "2026-07-28" {
		_, err := s.client.ListTools(outgoing, nil)
		return err
	}
	return s.client.Ping(outgoing, params)
}
func (s *Session) ListTools(ctx context.Context, params *mcp.ListToolsParams) (*mcp.ListToolsResult, error) {
	outgoing, release := isolatedMCPContext(ctx)
	defer release()
	return s.client.ListTools(outgoing, params)
}
func (s *Session) CallTool(ctx context.Context, params *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	outgoing, release := isolatedMCPContext(ctx)
	defer release()
	return s.client.CallTool(outgoing, params)
}
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.client != nil {
			s.closeErr = s.client.Close()
		}
	})
	return s.closeErr
}
