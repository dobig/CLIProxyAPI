package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// barredRecordingExecutor answers every request and records which auth ran it.
type barredRecordingExecutor struct {
	mu   sync.Mutex
	used []string
}

func (e *barredRecordingExecutor) Identifier() string { return "barred-test" }

func (e *barredRecordingExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.mu.Lock()
	e.used = append(e.used, auth.ID)
	e.mu.Unlock()
	return cliproxyexecutor.Response{Payload: []byte(`{}`)}, nil
}

func (e *barredRecordingExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e *barredRecordingExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) { return auth, nil }

func (e *barredRecordingExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *barredRecordingExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

// A barred credential is skipped by requests not pinned to it, and still
// serves the ones that are; with every credential barred, nothing runs.
func TestBarredAuthIsSkippedUnlessPinned(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	exec := &barredRecordingExecutor{}
	manager.RegisterExecutor(exec)
	for _, id := range []string{"barred-a", "barred-b"} {
		registry.GetGlobalRegistry().RegisterClient(id, "barred-test", []*registry.ModelInfo{{ID: "barred-model"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		if _, err := manager.Register(context.Background(), &Auth{ID: id, Provider: "barred-test", Status: StatusActive}); err != nil {
			t.Fatalf("Register %s: %v", id, err)
		}
	}
	run := func(meta map[string]any) (string, error) {
		exec.mu.Lock()
		exec.used = nil
		exec.mu.Unlock()
		_, err := manager.Execute(context.Background(), []string{"barred-test"}, cliproxyexecutor.Request{Model: "barred-model"}, cliproxyexecutor.Options{Metadata: meta})
		exec.mu.Lock()
		defer exec.mu.Unlock()
		if len(exec.used) == 0 {
			return "", err
		}
		return exec.used[len(exec.used)-1], err
	}
	for i := 0; i < 6; i++ {
		got, err := run(map[string]any{cliproxyexecutor.BarredAuthMetadataKey: []string{"barred-a"}})
		if err != nil || got != "barred-b" {
			t.Fatalf("barred-a barred: ran on %q, err %v", got, err)
		}
	}
	got, err := run(map[string]any{
		cliproxyexecutor.BarredAuthMetadataKey: []string{"barred-a"},
		cliproxyexecutor.PinnedAuthMetadataKey: "barred-a",
	})
	if err != nil || got != "barred-a" {
		t.Fatalf("pinned to barred-a: ran on %q, err %v", got, err)
	}
	if got, err := run(map[string]any{cliproxyexecutor.BarredAuthMetadataKey: []string{"barred-a", "barred-b"}}); err == nil || got != "" {
		t.Fatalf("all barred: ran on %q, err %v", got, err)
	}
}
