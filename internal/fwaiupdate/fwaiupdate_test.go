package fwaiupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func releaseArchive(t *testing.T, binary string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"README.md": "readme", binaryName: binary} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func serveRelease(t *testing.T, archive []byte) *string {
	t.Helper()
	var asked string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		_, _ = w.Write(archive)
	}))
	t.Cleanup(s.Close)
	oldURL, oldPlatform := releaseURL, platform
	releaseURL = s.URL + "/v%s/CLIProxyAPI_%s_linux_%s_no-plugin.tar.gz"
	platform = func() (string, string) { return "linux", "arm64" }
	t.Cleanup(func() { releaseURL, platform = oldURL, oldPlatform })
	return &asked
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestApplyInstallsTheReleaseAndKeepsThePrevious(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(binDirEnv, dir)
	t.Setenv(imageVersionEnv, "8.0.20-fwai.1")
	archive := releaseArchive(t, "new binary")
	sum := sha256.Sum256(archive)
	asked := serveRelease(t, archive)
	_ = os.WriteFile(filepath.Join(dir, installedFile), []byte("old binary"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, bootsFile), []byte("2"), 0o644)

	if err := Apply(context.Background(), nil, "8.0.20-fwai.2", hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if *asked != "/v8.0.20-fwai.2/CLIProxyAPI_8.0.20-fwai.2_linux_aarch64_no-plugin.tar.gz" {
		t.Fatalf("downloaded %s", *asked)
	}
	if read(t, filepath.Join(dir, installedFile)) != "new binary" || read(t, filepath.Join(dir, previousFile)) != "old binary" {
		t.Fatal("binary not installed over the previous one")
	}
	if read(t, filepath.Join(dir, versionFile)) != "8.0.20-fwai.2" || read(t, filepath.Join(dir, baseFile)) != "8.0.20-fwai.1" {
		t.Fatal("version or base not recorded")
	}
	if _, err := os.Stat(filepath.Join(dir, bootsFile)); !os.IsNotExist(err) {
		t.Fatal("start count not reset for the new binary")
	}
	if s := Current(); !s.Available || s.Installed != "8.0.20-fwai.2" || s.Image != "8.0.20-fwai.1" {
		t.Fatalf("status = %+v", s)
	}
}

func TestApplyRefusesWhatItCannotTrust(t *testing.T) {
	dir := t.TempDir()
	archive := releaseArchive(t, "binary")
	serveRelease(t, archive)
	good := sha256.Sum256(archive)

	t.Setenv(binDirEnv, "")
	if err := Apply(context.Background(), nil, "8.0.20-fwai.2", hex.EncodeToString(good[:])); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("without a bin dir: %v", err)
	}
	t.Setenv(binDirEnv, dir)
	for _, version := range []string{"8.0.20", "../../x", "v8.0.20-fwai.2"} {
		if err := Apply(context.Background(), nil, version, hex.EncodeToString(good[:])); !errors.Is(err, ErrInvalid) {
			t.Fatalf("version %q: %v", version, err)
		}
	}
	if err := Apply(context.Background(), nil, "8.0.20-fwai.2", strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("wrong checksum: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, installedFile)); !os.IsNotExist(err) {
		t.Fatal("a binary that failed its checksum was installed")
	}
}
