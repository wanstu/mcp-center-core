package mcpcenter

import "context"

// isolatedMCPContext prevents outer MCP protocol metadata from leaking into an
// independent upstream session. It preserves deadlines and cancellation.
func isolatedMCPContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		return context.WithCancel(context.Background())
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if deadline, ok := parent.Deadline(); ok {
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	stop := context.AfterFunc(parent, cancel)
	return ctx, func() { stop(); cancel() }
}
