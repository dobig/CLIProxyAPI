package handlers

import (
	"context"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
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

func TestBarredAuthHeaderBarsTrustedRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name    string
		trusted bool
		want    []string
	}{
		{"trusted caller", true, []string{"a.json", "b.json", "c.json"}},
		{"untrusted caller", false, nil},
	} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", "/v1/messages", nil)
		c.Request.Header.Add(BarredAuthHeader, " a.json , b.json,")
		c.Request.Header.Add(BarredAuthHeader, "c.json")

		TakePinnedAuthHeader(c, tc.trusted)
		if got := c.Request.Header.Values(BarredAuthHeader); len(got) != 0 {
			t.Fatalf("%s: header left on the request: %q", tc.name, got)
		}
		h := &BaseAPIHandler{}
		ctx, _ := h.GetContextWithCancel(nil, c, context.Background())
		if got := barredAuthIDsFromContext(ctx); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s: barred %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestCallerScopeHeaderNarrowsTrustedCallerScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	scopeFor := func(trusted bool, header string) string {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", "/v1/messages", nil)
		if header != "" {
			c.Request.Header.Set(CallerScopeHeader, header)
		}
		TakePinnedAuthHeader(c, trusted)
		if got := c.Request.Header.Get(CallerScopeHeader); got != "" {
			t.Fatalf("header left on the request: %q", got)
		}
		c.Set("userApiKey", "gateway-key")
		return requestCallerScope(c)
	}

	keyOnly := scopeFor(true, "")
	if keyOnly == "" {
		t.Fatal("no caller scope for an authenticated request")
	}
	userA := scopeFor(true, " user-a ")
	userB := scopeFor(true, "user-b")
	if userA == keyOnly || userB == keyOnly || userA == userB {
		t.Fatalf("users not separated: key %q, a %q, b %q", keyOnly, userA, userB)
	}
	if again := scopeFor(true, "user-a"); again != userA {
		t.Fatalf("same user scoped differently: %q then %q", userA, again)
	}
	if untrusted := scopeFor(false, "user-a"); untrusted != keyOnly {
		t.Fatalf("untrusted header changed the scope: %q, want %q", untrusted, keyOnly)
	}
}

func TestClaudeCodeVouchHeaderMarksTrustedRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name    string
		trusted bool
		want    bool
	}{
		{"trusted caller", true, true},
		{"untrusted caller", false, false},
	} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", "/v1/messages", nil)
		c.Request.Header.Set(ClaudeCodeVouchHeader, "1")

		TakePinnedAuthHeader(c, tc.trusted)
		if got := c.Request.Header.Get(ClaudeCodeVouchHeader); got != "" {
			t.Fatalf("%s: header left on the request: %q", tc.name, got)
		}
		h := &BaseAPIHandler{}
		ctx, _ := h.GetContextWithCancel(nil, c, context.Background())
		if got := util.GatewayVouchedClaudeCode(ctx); got != tc.want {
			t.Fatalf("%s: vouched %v, want %v", tc.name, got, tc.want)
		}
	}
}
