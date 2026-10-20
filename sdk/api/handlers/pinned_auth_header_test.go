package handlers

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestPinnedAuthHeaderPinsTrustedRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name    string
		trusted bool
		want    string
	}{
		{"trusted caller", true, "claude-a@example.com.json"},
		{"untrusted caller", false, ""},
	} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", "/v1/messages", nil)
		c.Request.Header.Set(PinnedAuthHeader, " claude-a@example.com.json ")

		TakePinnedAuthHeader(c, tc.trusted)
		if got := c.Request.Header.Get(PinnedAuthHeader); got != "" {
			t.Fatalf("%s: header left on the request: %q", tc.name, got)
		}
		h := &BaseAPIHandler{}
		// The cancel func logs through the handler's config, which this bare
		// handler has none of; the context is all that is under test.
		ctx, _ := h.GetContextWithCancel(nil, c, context.Background())
		if got := pinnedAuthIDFromContext(ctx); got != tc.want {
			t.Fatalf("%s: pinned %q, want %q", tc.name, got, tc.want)
		}
	}
}
