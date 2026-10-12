package config

import "testing"

func TestParseConfigBytes_TrustNativeCallerSystem(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"legacy top-level key", "port: 8317\nclaude-trust-native-caller-system: true\n", true},
		{"upstream.claude key", "port: 8317\nupstream:\n  claude:\n    trust-native-caller-system: true\n", true},
		{"absent defaults off", "port: 8317\n", false},
	} {
		cfg, err := ParseConfigBytes([]byte(tc.raw))
		if err != nil {
			t.Fatalf("%s: ParseConfigBytes error = %v", tc.name, err)
		}
		if cfg.ClaudeTrustNativeCallerSystem != tc.want {
			t.Errorf("%s: ClaudeTrustNativeCallerSystem = %v, want %v", tc.name, cfg.ClaudeTrustNativeCallerSystem, tc.want)
		}
	}
}
