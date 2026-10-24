package util

import "context"

type gatewayVouchedClaudeCodeContextKey struct{}

// WithGatewayVouchedClaudeCode marks ctx as a request an authenticated
// gateway has checked is Claude Code's own (see
// handlers.ClaudeCodeVouchHeader).
func WithGatewayVouchedClaudeCode(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, gatewayVouchedClaudeCodeContextKey{}, true)
}

// GatewayVouchedClaudeCode reports whether ctx was marked by
// WithGatewayVouchedClaudeCode.
func GatewayVouchedClaudeCode(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(gatewayVouchedClaudeCodeContextKey{}).(bool)
	return v
}
