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
	if def.Disabled {
		return Activation{}, fmt.Errorf("mcp %q is disabled", def.Name)
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
	tools, err := s.Refresh(probeCtx, id)
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
	entry := s.runtimeEntry(id)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.toolsLoaded {
		entry.lastUsedAt = s.now().UTC()
		return cloneTools(entry.tools), nil
	}
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

func (s *Service) CallTool(ctx context.Context, id, name string, arguments map[string]any) (result *mcp.CallToolResult, err error) {
	started := time.Now().UTC()
	defer func() {
		s.emitAudit(ctx, newAuditEvent(ctx, id, name, started, arguments, result, err))
	}()

	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("tool name is required")
	}
	entry := s.runtimeEntry(id)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	session, err := s.ensureSessionLocked(ctx, id, entry)
	if err != nil {
		return nil, err
	}
	entry.lastUsedAt = s.now().UTC()
	outboundCtx, release := isolatedMCPContext(ctx)
	defer release()
	result, err = session.CallTool(outboundCtx, &mcp.CallToolParams{Name: name, Arguments: arguments})
	entry.lastUsedAt = s.now().UTC()
	if err != nil {
		s.failSessionLocked(entry, err)
		return nil, err
	}
	entry.errorKind = ""
	entry.lastError = ""
	return result, nil
}

func (s *Service) connectFresh(ctx context.Context, id string) (*mcp.ClientSession, context.CancelFunc, error) {
	activation, err := s.Resolve(id)
	if err != nil {
		return nil, nil, err
	}
	session, err := OpenSession(ctx, activation)
	if err != nil {
		return nil, nil, err
	}
	return session.client, session.cancel, nil
}

func transportFor(activation Activation) (mcp.Transport, error) {
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
	case TransportSSE:
		transport := &mcp.SSEClientTransport{Endpoint: activation.Endpoint}
		if len(activation.Headers) > 0 {
			transport.HTTPClient = &http.Client{Transport: headerRoundTripper{base: http.DefaultTransport, headers: activation.Headers}}
		}
		return transport, nil
	case TransportStdio:
		// The stdio process belongs to the reusable runtime session, not to
		// the HTTP/admin request that happened to create that session.
		// CommandTransport terminates the child when the session closes.
		cmd := exec.Command(activation.Executable, activation.Args...)
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
