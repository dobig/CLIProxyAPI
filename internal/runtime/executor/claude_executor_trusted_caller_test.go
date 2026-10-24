package executor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// A Claude Code auto-mode classifier request as an API-key Claude Code client
// sends it: its own system prompt top-level, then two consecutive user turns
// (CLAUDE.md, then the transcript). Native Claude Code over OAuth sends exactly
// this layout, with every breakpoint at ttl 1h.
const trustedCallerClassifierPayload = `{
	"model": "claude-sonnet-5",
	"max_tokens": 64,
	"stop_sequences": ["</block>"],
	"thinking": {"type": "disabled"},
	"metadata": {"user_id": "{\"device_id\":\"cb2ff65c739549a9c8709324c2665d5e2d5785e3b195ee30c082752de7263185\",\"account_uuid\":\"\",\"session_id\":\"54edeed8-e47f-4b67-9c97-900e641c4e50\"}"},
	"system": [
		{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.296.b99; cc_entrypoint=sdk-cli;"},
		{"type": "text", "text": "You are a security monitor for autonomous AI coding agents.", "cache_control": {"type": "ephemeral"}}
	],
	"messages": [
		{"role": "user", "content": [{"type": "text", "text": "The following is the user's CLAUDE.md configuration.", "cache_control": {"type": "ephemeral"}}]},
		{"role": "user", "content": [
			{"type": "text", "text": "<transcript>\n"},
			{"type": "text", "text": "{\"user\":\"run it\"}\n", "cache_control": {"type": "ephemeral"}},
			{"type": "text", "text": "</transcript>\n"}
		]}
	]
}`

func trustedCallerHeaders() http.Header {
	h := http.Header{}
	h.Set("User-Agent", "claude-cli/2.1.296 (external, sdk-cli)")
	h.Set("X-App", "cli")
	h.Set("Anthropic-Beta", "claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05")
	h.Set("X-Claude-Code-Session-Id", "54edeed8-e47f-4b67-9c97-900e641c4e50")
	return h
}

func runTrustedCallerRequest(t *testing.T, trust bool, apiKey string, headers http.Header) (http.Header, []byte) {
	t.Helper()
	return runTrustedCallerRequestContext(t, context.Background(), trust, apiKey, headers)
}

func runTrustedCallerRequestContext(t *testing.T, ctx context.Context, trust bool, apiKey string, headers http.Header) (http.Header, []byte) {
	t.Helper()
	var seenHeaders http.Header
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"<block>no"}],"stop_reason":"stop_sequence"}`))
	}))
	defer server.Close()

	cfg := &config.Config{ClaudeKey: []config.ClaudeKey{{APIKey: apiKey}}, ClaudeTrustNativeCallerSystem: trust}
	auth := &cliproxyauth.Auth{
		ID:         "auth-trusted-caller-test",
		Metadata:   claudeOAuthTestMetadata(),
		Attributes: map[string]string{"api_key": apiKey, "base_url": server.URL},
	}
	_, err := NewClaudeExecutor(cfg).Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: []byte(trustedCallerClassifierPayload),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude, Headers: headers})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	return seenHeaders, seenBody
}

func TestClaudeExecutor_TrustedCallerKeepsClaudeCodeSystemTopLevel(t *testing.T) {
	headers, body := runTrustedCallerRequest(t, true, "sk-ant-oat-trusted-caller", trustedCallerHeaders())

	system := gjson.GetBytes(body, "system").Array()
	if len(system) != 2 {
		t.Fatalf("system blocks = %d, want billing header + caller prompt: %s", len(system), body)
	}
	billing := system[0].Get("text").String()
	if !strings.HasPrefix(billing, "x-anthropic-billing-header:") || strings.Contains(billing, "2.1.296") {
		t.Fatalf("system[0] = %q, want the cloak's re-signed billing header, not the caller's", billing)
	}
	if got := system[1].Get("text").String(); got != "You are a security monitor for autonomous AI coding agents." {
		t.Fatalf("system[1] = %q, want the caller's own prompt kept top-level", got)
	}
	if got := system[1].Get("cache_control.ttl").String(); got != "1h" {
		t.Fatalf("caller system ttl = %q, want 1h as native sends over OAuth", got)
	}
	if strings.Contains(string(body), "You are Claude Code, Anthropic's official CLI") {
		t.Fatalf("trusted caller must not get the cloak identity block: %s", body)
	}

	roles := gjson.GetBytes(body, "messages.#.role").Array()
	if len(roles) != 2 || roles[0].String() != "user" || roles[1].String() != "user" {
		t.Fatalf("messages roles = %v, want the caller's two user turns unchanged", roles)
	}
	if got := gjson.GetBytes(body, "messages.0.content.#").Int(); got != 1 {
		t.Fatalf("first user turn has %d blocks, want only the caller's CLAUDE.md block", got)
	}
	if got := gjson.GetBytes(body, "messages.1.content.2.cache_control").Exists(); got {
		t.Fatalf("cloak must not add breakpoints for a trusted caller: %s", body)
	}
	if got := countCacheControls(body); got != 3 {
		t.Fatalf("cache_control count = %d, want the caller's 3", got)
	}

	if ua := headers.Get("User-Agent"); strings.Contains(ua, "2.1.296") {
		t.Fatalf("User-Agent = %q, want the cloak's normalized fingerprint", ua)
	}
	if strings.Contains(gjson.GetBytes(body, "metadata.user_id").String(), "cb2ff65c7395") {
		t.Fatalf("caller device_id leaked upstream: %s", gjson.GetBytes(body, "metadata.user_id").String())
	}
}

func TestClaudeExecutor_TrustedCallerOffKeepsUpstreamPassthrough(t *testing.T) {
	headers, body := runTrustedCallerRequest(t, false, "sk-ant-oat-trusted-caller", trustedCallerHeaders())
	// Upstream behavior: a confirmed Claude Code client is passed through.
	if ua := headers.Get("User-Agent"); !strings.Contains(ua, "2.1.296") {
		t.Fatalf("User-Agent = %q, want the caller's own when the option is off", ua)
	}
	if got := gjson.GetBytes(body, "messages.#").Int(); got != 2 {
		t.Fatalf("messages = %d, want passthrough: %s", got, body)
	}
}

func TestClaudeExecutor_TrustedCallerWithoutSignalsStillRelocates(t *testing.T) {
	h := http.Header{}
	h.Set("X-Claude-Code-Session-Id", "54edeed8-e47f-4b67-9c97-900e641c4e50")
	_, body := runTrustedCallerRequest(t, true, "sk-ant-oat-trusted-caller", h)
	if !strings.Contains(gjson.GetBytes(body, "system").Raw, "You are Claude Code, Anthropic's official CLI") {
		t.Fatalf("unrecognized caller must keep the full cloak: %s", body)
	}
	roles := gjson.GetBytes(body, "messages.#.role").Array()
	if roles[len(roles)-1].String() != "system" {
		t.Fatalf("unrecognized caller's system must still be relocated, roles = %v", roles)
	}
}

// A release this build does not recognize (2.2.x, details after the
// entrypoint, no claude-code beta) keeps its system prompt top-level when the
// gateway vouches for it, and is relocated like any other caller when not.
func TestClaudeExecutor_GatewayVouchedCallerKeepsSystemTopLevel(t *testing.T) {
	h := http.Header{}
	h.Set("User-Agent", "claude-cli/2.2.0 (external, claude-desktop-3p, app/1.4.2)")
	h.Set("X-App", "cli")
	h.Set("Anthropic-Beta", "interleaved-thinking-2025-05-14,context-management-2025-06-27")
	h.Set("X-Claude-Code-Session-Id", "54edeed8-e47f-4b67-9c97-900e641c4e50")

	headers, body := runTrustedCallerRequestContext(t, util.WithGatewayVouchedClaudeCode(context.Background()), true, "sk-ant-oat-trusted-caller", h.Clone())
	if ua := headers.Get("User-Agent"); strings.Contains(ua, "2.2.0") || strings.Contains(ua, "app/") {
		t.Fatalf("User-Agent = %q, want the cloak's normalized fingerprint", ua)
	}
	if got := gjson.GetBytes(body, "system.1.text").String(); got != "You are a security monitor for autonomous AI coding agents." {
		t.Fatalf("vouched caller's system[1] = %q, want its own prompt kept top-level: %s", got, body)
	}
	if got := gjson.GetBytes(body, "messages.#").Int(); got != 2 {
		t.Fatalf("vouched caller has %d messages, want its two user turns unchanged: %s", got, body)
	}

	_, body = runTrustedCallerRequest(t, true, "sk-ant-oat-trusted-caller", h.Clone())
	roles := gjson.GetBytes(body, "messages.#.role").Array()
	if roles[len(roles)-1].String() != "system" {
		t.Fatalf("unvouched caller's system must still be relocated, roles = %v", roles)
	}
}

func TestResolveTrustedClaudeCodeCaller(t *testing.T) {
	strong := helps.ClaudeCodeRequestDetection{StrongSignals: true, NativeClient: true, Confirmed: true}
	weak := helps.ClaudeCodeRequestDetection{}
	on := &config.Config{ClaudeTrustNativeCallerSystem: true}
	off := &config.Config{}
	oauth := claudeFingerprintPolicy{AuthIsOAuthToken: true}
	apiKey := claudeFingerprintPolicy{}
	plain := context.Background()
	vouched := util.WithGatewayVouchedClaudeCode(plain)

	cases := []struct {
		name          string
		ctx           context.Context
		cfg           *config.Config
		fp            claudeFingerprintPolicy
		det           helps.ClaudeCodeRequestDetection
		wantConfirmed bool
		wantTrusted   bool
	}{
		{"off keeps upstream confirmation", plain, off, oauth, strong, true, false},
		{"on cloaks a recognized OAuth caller as trusted", plain, on, oauth, strong, false, true},
		{"on trusts a strong non-whitelisted entrypoint", plain, on, oauth, helps.ClaudeCodeRequestDetection{StrongSignals: true}, false, true},
		{"on ignores API-key credentials", plain, on, apiKey, strong, true, false},
		{"on without signals is untrusted", plain, on, oauth, weak, false, false},
		{"nil config", plain, nil, oauth, strong, true, false},
		{"vouched without signals is trusted", vouched, on, oauth, weak, false, true},
		{"vouched ignores API-key credentials", vouched, on, apiKey, weak, false, false},
		{"vouched with the option off changes nothing", vouched, off, oauth, weak, false, false},
	}
	for _, tc := range cases {
		confirmed, trusted := resolveTrustedClaudeCodeCaller(tc.ctx, tc.cfg, tc.fp, tc.det)
		if confirmed != tc.wantConfirmed || trusted != tc.wantTrusted {
			t.Errorf("%s: got (%v,%v), want (%v,%v)", tc.name, confirmed, trusted, tc.wantConfirmed, tc.wantTrusted)
		}
	}
}

// Main-conversation shape on the streaming path: the caller's system blocks
// stay top-level and its mid-conversation system turn stays where it was.
func TestClaudeExecutor_TrustedCallerKeepsSystemTopLevel_Stream(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-opus-5-5\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
	}))
	defer server.Close()

	apiKey := "sk-ant-oat-trusted-caller-stream"
	cfg := &config.Config{ClaudeKey: []config.ClaudeKey{{APIKey: apiKey}}, ClaudeTrustNativeCallerSystem: true}
	auth := &cliproxyauth.Auth{
		ID:         "auth-trusted-caller-stream-test",
		Metadata:   claudeOAuthTestMetadata(),
		Attributes: map[string]string{"api_key": apiKey, "base_url": server.URL},
	}
	payload := []byte(`{
		"model": "claude-opus-5-5",
		"stream": true,
		"max_tokens": 64000,
		"metadata": {"user_id": "{\"device_id\":\"cb2ff65c739549a9c8709324c2665d5e2d5785e3b195ee30c082752de7263185\",\"account_uuid\":\"\",\"session_id\":\"54edeed8-e47f-4b67-9c97-900e641c4e50\"}"},
		"system": [
			{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.296.aaa; cc_entrypoint=sdk-cli;"},
			{"type": "text", "text": "You are a Claude agent, built on Anthropic's Claude Agent SDK.", "cache_control": {"type": "ephemeral"}},
			{"type": "text", "text": "Agent instructions.", "cache_control": {"type": "ephemeral"}}
		],
		"messages": [
			{"role": "user", "content": [{"type": "text", "text": "do the thing"}]},
			{"role": "system", "content": [{"type": "text", "text": "environment details", "cache_control": {"type": "ephemeral"}}]}
		]
	}`)
	result, err := NewClaudeExecutor(cfg).ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-opus-5-5",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude, Headers: trustedCallerHeaders()})
	if err != nil {
		t.Fatalf("ExecuteStream error = %v", err)
	}
	if result != nil && result.Chunks != nil {
		for range result.Chunks {
		}
	}

	system := gjson.GetBytes(seenBody, "system").Array()
	if len(system) != 3 || system[1].Get("text").String() != "You are a Claude agent, built on Anthropic's Claude Agent SDK." || system[2].Get("text").String() != "Agent instructions." {
		t.Fatalf("system = %s, want billing header + the caller's two blocks", gjson.GetBytes(seenBody, "system").Raw)
	}
	roles := gjson.GetBytes(seenBody, "messages.#.role").Array()
	if len(roles) != 2 || roles[0].String() != "user" || roles[1].String() != "system" {
		t.Fatalf("messages roles = %v, want the caller's user + system turns unchanged", roles)
	}
	if got := gjson.GetBytes(seenBody, "messages.1.content.0.cache_control.ttl").String(); got != "1h" {
		t.Fatalf("mid-conversation system ttl = %q, want 1h", got)
	}
}
