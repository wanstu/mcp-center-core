package mcpcenter

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const defaultConnectTimeout = 20 * time.Second

// connectSessionWithLifetime gives long-lived MCP transports (notably legacy
// SSE) an independent lifetime. The admin HTTP request that initiated the
// connection may finish while the runtime session continues to serve calls.
func connectSessionWithLifetime(requestCtx context.Context, client *mcp.Client, transport mcp.Transport) (*mcp.ClientSession, context.CancelFunc, error) {
	if requestCtx == nil {
		requestCtx = context.Background()
	}
	attemptCtx, stopAttempt := context.WithTimeout(requestCtx, defaultConnectTimeout)
	defer stopAttempt()
	lifetimeCtx, cancelLifetime := context.WithCancel(context.Background())
	type outcome struct {
		session *mcp.ClientSession
		err     error
	}
	ready := make(chan outcome, 1)
	go func() {
		session, err := client.Connect(lifetimeCtx, transport, nil)
		ready <- outcome{session: session, err: err}
	}()
	select {
	case result := <-ready:
		if result.err != nil {
			cancelLifetime()
			return nil, nil, result.err
		}
		return result.session, cancelLifetime, nil
	case <-attemptCtx.Done():
		cancelLifetime()
		go func() {
			result := <-ready
			if result.session != nil {
				_ = result.session.Close()
			}
		}()
		return nil, nil, attemptCtx.Err()
	}
}
