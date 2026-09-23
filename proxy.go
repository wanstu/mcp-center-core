package mcpcenter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// NewProxyServer mirrors one configured upstream MCP as an MCP server. The
// returned server is intentionally authorization-agnostic: callers such as
// MCP Center wrap its HTTP handler with their own OAuth/Credential policy.
func (s *Service) NewProxyServer(ctx context.Context, id string) (*mcp.Server, error) {
	def, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	tools, err := s.ListTools(ctx, id)
	if err != nil {
		return nil, err
	}
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "mcp-center-proxy-" + def.Name,
		Version: "0.1.0",
	}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{},
	})

	for _, discovered := range tools {
		tool := &mcp.Tool{
			Name:        discovered.Name,
			Title:       discovered.Title,
			Description: discovered.Description,
			InputSchema: discovered.InputSchema,
		}
		toolName := discovered.Name
		server.AddTool(tool, func(callCtx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := map[string]any{}
			if request != nil && request.Params != nil && len(request.Params.Arguments) != 0 {
				if err := json.Unmarshal(request.Params.Arguments, &args); err != nil {
					return nil, fmt.Errorf("decode arguments for %s: %w", toolName, err)
				}
			}
			return s.CallTool(callCtx, id, toolName, args)
		})
	}
	return server, nil
}

// NewProxyHTTPHandler exposes one upstream through Streamable HTTP. It uses a
// stateless MCP transport so MCP Center can independently authenticate each
// request before it reaches the protocol handler.
func (s *Service) NewProxyHTTPHandler(ctx context.Context, id string) (http.Handler, error) {
	server, err := s.NewProxyServer(ctx, id)
	if err != nil {
		return nil, err
	}
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{
		Stateless:                    true,
		JSONResponse:                 true,
		SessionTimeout:               5 * time.Minute,
		PropagateRequestCancellation: true,
		MaxRequestBodyBytes:          4 << 20,
	}), nil
}
