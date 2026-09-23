package mcpcenter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const defaultProbeTimeout = 10 * time.Second

type Activation struct {
	MCPID      string
	Transport  string
	Endpoint   string
	Headers    map[string]string
	Executable string
	Args       []string
	Env        map[string]string
}

func (s *Service) Resolve(id string) (Activation, error) {
	def, err := s.Get(id)
	if err != nil {
		return Activation{}, err
	}
	endpoint, missingEndpoint := s.expand(def.Endpoint)
	headers, missingHeaders := s.resolveMap(def.HeaderRefs)
	env, missingEnv := s.resolveMap(def.EnvRefs)
	if missingEndpoint || missingHeaders || missingEnv {
		return Activation{}, fmt.Errorf("mcp %q has unresolved environment references", id)
	}
	return Activation{
		MCPID: id, Transport: def.Transport, Endpoint: endpoint, Headers: headers,
		Executable: def.Executable, Args: append([]string(nil), def.Args...), Env: env,
	}, nil
}

func (s *Service) Probe(ctx context.Context, id string) (HealthStatus, error) {
	def, err := s.Get(id)
	if err != nil {
		return HealthStatus{}, err
	}
	timeout := defaultProbeTimeout
	if def.HealthPolicy.ProbeTimeoutSeconds > 0 {
		timeout = time.Duration(def.HealthPolicy.ProbeTimeoutSeconds) * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tools, err := s.ListTools(probeCtx, id)
	if err != nil {
		kind := ClassifyError(err)
		return HealthStatus{
			MCPID: id, State: HealthError, ErrorKind: kind,
			Message: healthMessage(kind), CheckedAt: time.Now().UTC(),
		}, nil
	}
	return HealthStatus{
		MCPID: id, State: HealthHealthy, Tools: tools, CheckedAt: time.Now().UTC(),
	}, nil
}

func (s *Service) ListTools(ctx context.Context, id string) ([]Tool, error) {
	session, err := s.connect(ctx, id)
	if err != nil {
		return nil, err
	}
	defer session.Close()
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

func (s *Service) CallTool(ctx context.Context, id, name string, arguments map[string]any) (*mcp.CallToolResult, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("tool name is required")
	}
	session, err := s.connect(ctx, id)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	return session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
}

func (s *Service) connect(ctx context.Context, id string) (*mcp.ClientSession, error) {
	activation, err := s.Resolve(id)
	if err != nil {
		return nil, err
	}
	transport, err := transportFor(ctx, activation)
	if err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-center-core", Version: "0.1.0"}, nil)
	return client.Connect(ctx, transport, nil)
}

func transportFor(ctx context.Context, activation Activation) (mcp.Transport, error) {
	switch activation.Transport {
	case TransportStreamableHTTP:
		transport := &mcp.StreamableClientTransport{
			Endpoint: activation.Endpoint, MaxRetries: -1, DisableStandaloneSSE: true,
		}
		if len(activation.Headers) > 0 {
			transport.HTTPClient = &http.Client{
				Transport: headerRoundTripper{base: http.DefaultTransport, headers: activation.Headers},
			}
		}
		return transport, nil
	case TransportStdio:
		cmd := exec.CommandContext(ctx, activation.Executable, activation.Args...)
		cmd.Env = os.Environ()
		for k, v := range activation.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		return &mcp.CommandTransport{Command: cmd}, nil
	default:
		return nil, fmt.Errorf("unsupported mcp transport %q", activation.Transport)
	}
}

func ClassifyError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "deadline exceeded"), strings.Contains(text, "i/o timeout"), strings.Contains(text, "timed out"):
		return "timeout"
	case strings.Contains(text, "connection refused"), strings.Contains(text, "actively refused"):
		return "connection_refused"
	case strings.Contains(text, "401"), strings.Contains(text, "403"), strings.Contains(text, "unauthorized"), strings.Contains(text, "forbidden"):
		return "auth_failure"
	default:
		return "connection_failed"
	}
}

func healthMessage(kind string) string {
	switch kind {
	case "timeout":
		return "MCP 探测超时，请检查服务响应或提高 probe timeout。"
	case "connection_refused":
		return "MCP Endpoint 拒绝连接，请确认服务已启动且端口可访问。"
	case "auth_failure":
		return "MCP 鉴权失败，请检查 Header 引用及其环境变量。"
	default:
		return "MCP 协议连接失败，请检查 Endpoint、Transport、TLS 和网络。"
	}
}

type headerRoundTripper struct {
	base    http.RoundTripper
	headers map[string]string
}

func (r headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	for k, v := range r.headers {
		clone.Header.Set(k, v)
	}
	return r.base.RoundTrip(clone)
}
