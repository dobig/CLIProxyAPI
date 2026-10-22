package handlers

import (
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/context"
)

type pinnedAuthContextKey struct{}

type barredAuthContextKey struct{}

// PinnedAuthHeader names the credential (its auth ID) a gateway in front of
// this instance wants a request run on. It is honoured only on requests that
// passed API-key authentication, and is removed from every request before a
// handler sees it, so it never reaches an upstream.
const PinnedAuthHeader = "X-Fwai-Pinned-Auth"

// BarredAuthHeader lists credentials (auth IDs, comma-separated) a gateway
// in front of this instance keeps for requests pinned to them: any other
// request skips them. Like PinnedAuthHeader it is honoured only on
// authenticated requests and never reaches an upstream.
const BarredAuthHeader = "X-Fwai-Barred-Auth"

// CallerScopeHeader names the end user a gateway in front of this instance
// is relaying for. Every user of one gateway shares its API key, so without
// it inferred sessions (the LCP matcher, derived session IDs) are matched
// across users and one user's request can follow another's binding. The
// value narrows the API key's caller scope; like PinnedAuthHeader it is
// honoured only on authenticated requests and never reaches an upstream.
const CallerScopeHeader = "X-Fwai-Caller-Scope"

const (
	pinnedAuthGinKey  = "fwaiPinnedAuth"
	barredAuthGinKey  = "fwaiBarredAuth"
	callerScopeGinKey = "fwaiCallerScope"
)

// TakePinnedAuthHeader removes PinnedAuthHeader, BarredAuthHeader and
// CallerScopeHeader from the request and, when the caller is trusted, keeps
// their values for GetContextWithCancel and the execution metadata to apply
// to the request's execution.
func TakePinnedAuthHeader(c *gin.Context, trusted bool) {
	if c == nil || c.Request == nil {
		return
	}
	authID := strings.TrimSpace(c.Request.Header.Get(PinnedAuthHeader))
	c.Request.Header.Del(PinnedAuthHeader)
	if trusted && authID != "" {
		c.Set(pinnedAuthGinKey, authID)
	}
	var barred []string
	for _, value := range c.Request.Header.Values(BarredAuthHeader) {
		for _, id := range strings.Split(value, ",") {
			if id = strings.TrimSpace(id); id != "" {
				barred = append(barred, id)
			}
		}
	}
	c.Request.Header.Del(BarredAuthHeader)
	if trusted && len(barred) > 0 {
		c.Set(barredAuthGinKey, barred)
	}
	scope := strings.TrimSpace(c.Request.Header.Get(CallerScopeHeader))
	c.Request.Header.Del(CallerScopeHeader)
	if trusted && scope != "" {
		c.Set(callerScopeGinKey, scope)
	}
}

func callerScopeFromGin(c *gin.Context) string {
	if c == nil {
		return ""
	}
	raw, _ := c.Get(callerScopeGinKey)
	value, _ := raw.(string)
	return value
}

func barredAuthIDsFromGin(c *gin.Context) []string {
	if c == nil {
		return nil
	}
	raw, _ := c.Get(barredAuthGinKey)
	ids, _ := raw.([]string)
	return ids
}

func pinnedAuthIDFromGin(c *gin.Context) string {
	if c == nil {
		return ""
	}
	authID, _ := c.Get(pinnedAuthGinKey)
	value, _ := authID.(string)
	return value
}

type selectedAuthCallbackContextKey struct{}

type preparedModelRouteContextKey struct{}

type executionSessionContextKey struct{}

type disallowFreeAuthContextKey struct{}

type nestedExecutionTrackerKey struct{}

type nestedExecutionTracker struct {
	mu     sync.Mutex
	called bool
}

func (t *nestedExecutionTracker) mark() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.called = true
	t.mu.Unlock()
}

func (t *nestedExecutionTracker) hasNestedExecution() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.called
}

func withNestedExecutionTracker(ctx context.Context) (context.Context, *nestedExecutionTracker) {
	if ctx == nil {
		ctx = context.Background()
	}
	if existing, ok := ctx.Value(nestedExecutionTrackerKey{}).(*nestedExecutionTracker); ok && existing != nil {
		return ctx, existing
	}
	tracker := &nestedExecutionTracker{}
	return context.WithValue(ctx, nestedExecutionTrackerKey{}, tracker), tracker
}

func markNestedExecution(ctx context.Context) {
	if ctx == nil {
		return
	}
	if tracker, ok := ctx.Value(nestedExecutionTrackerKey{}).(*nestedExecutionTracker); ok && tracker != nil {
		tracker.mark()
	}
}

// WithPinnedAuthID returns a child context that requests execution on a specific auth ID.
func WithPinnedAuthID(ctx context.Context, authID string) context.Context {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, pinnedAuthContextKey{}, authID)
}

// WithBarredAuthIDs returns a child context whose execution skips the given
// auth IDs unless it is pinned to one of them.
func WithBarredAuthIDs(ctx context.Context, authIDs []string) context.Context {
	if len(authIDs) == 0 {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, barredAuthContextKey{}, append([]string(nil), authIDs...))
}

func barredAuthIDsFromContext(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}
	ids, _ := ctx.Value(barredAuthContextKey{}).([]string)
	return ids
}

// WithSelectedAuthIDCallback returns a child context that receives the selected auth ID.
func WithSelectedAuthIDCallback(ctx context.Context, callback func(string)) context.Context {
	if callback == nil {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, selectedAuthCallbackContextKey{}, callback)
}

// PrepareStreamModelRoute resolves a stream route once and stores it on the returned context for execution.
// The boolean reports whether the route overrides normal model-to-provider resolution.
func (h *BaseAPIHandler) PrepareStreamModelRoute(ctx context.Context, handlerType string, modelName string, rawJSON []byte) (context.Context, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	decision := h.applyModelRouter(ctx, handlerType, modelName, rawJSON, true, modelExecutionOptions{})
	ctx = context.WithValue(ctx, preparedModelRouteContextKey{}, decision)
	hasOverride := strings.TrimSpace(decision.ExecutorPluginID) != "" || strings.TrimSpace(decision.Provider) != ""
	return ctx, hasOverride
}

func preparedModelRouteFromContext(ctx context.Context, skipRouterPluginID string) (modelRouteDecision, bool) {
	// A host.model.execute_stream callback is a nested execution. Its caller is
	// excluded from model routing, so an outer prepared route cannot be reused:
	// it may point straight back at that caller.
	if ctx == nil || strings.TrimSpace(skipRouterPluginID) != "" {
		return modelRouteDecision{}, false
	}
	decision, ok := ctx.Value(preparedModelRouteContextKey{}).(modelRouteDecision)
	return decision, ok
}

// PreparedStreamPluginExecutor returns the executor plugin ID if the prepared route targets a plugin executor.
func PreparedStreamPluginExecutor(ctx context.Context) string {
	decision, ok := preparedModelRouteFromContext(ctx, "")
	if !ok {
		return ""
	}
	return strings.TrimSpace(decision.ExecutorPluginID)
}

// PreparedStreamProviderRoute returns the provider and target model if the prepared route targets a provider route override.
func PreparedStreamProviderRoute(ctx context.Context) (string, string) {
	decision, ok := preparedModelRouteFromContext(ctx, "")
	if !ok {
		return "", ""
	}
	return strings.TrimSpace(decision.Provider), strings.TrimSpace(decision.Model)
}

// WithExecutionSessionID returns a child context tagged with a long-lived execution session ID.
func WithExecutionSessionID(ctx context.Context, sessionID string) context.Context {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, executionSessionContextKey{}, sessionID)
}

// WithDisallowFreeAuth returns a child context that requests skipping known free-tier credentials.
func WithDisallowFreeAuth(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, disallowFreeAuthContextKey{}, true)
}

// headersFromContext extracts the original HTTP request headers from the gin context
// embedded in the provided context. This allows session affinity selectors to read
// client-provided session headers.
func headersFromContext(ctx context.Context) http.Header {
	if ctx == nil {
		return nil
	}
	if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		return ginCtx.Request.Header.Clone()
	}
	return nil
}

// queryFromContext extracts the original HTTP request query parameters from the
// gin context embedded in the provided context. Mirrors headersFromContext so
// model routers can observe inbound query parameters for plain HTTP requests,
// where execOptions.Query is not populated by callers.
func queryFromContext(ctx context.Context) url.Values {
	if ctx == nil {
		return nil
	}
	if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil && ginCtx.Request.URL != nil {
		return ginCtx.Request.URL.Query()
	}
	return nil
}

func pinnedAuthIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	raw := ctx.Value(pinnedAuthContextKey{})
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case []byte:
		return strings.TrimSpace(string(v))
	default:
		return ""
	}
}

func selectedAuthIDCallbackFromContext(ctx context.Context) func(string) {
	if ctx == nil {
		return nil
	}
	raw := ctx.Value(selectedAuthCallbackContextKey{})
	if callback, ok := raw.(func(string)); ok && callback != nil {
		return callback
	}
	return nil
}

func executionSessionIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	raw := ctx.Value(executionSessionContextKey{})
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case []byte:
		return strings.TrimSpace(string(v))
	default:
		return ""
	}
}

func disallowFreeAuthFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	raw, ok := ctx.Value(disallowFreeAuthContextKey{}).(bool)
	return ok && raw
}
