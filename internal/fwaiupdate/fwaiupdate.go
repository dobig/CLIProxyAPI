// Package fwaiupdate lets the gateway in front of an instance move it to
// another release of this fork without anyone logging in to its machine.
//
// The container image (llm_gateway's deploy/cliproxyapi/Dockerfile) ships a
// binary and an entrypoint, and mounts a volume at CLIPROXY_BIN_DIR. Apply
// downloads the requested release's binary from this fork's GitHub releases
// — the only source — checks it against the SHA-256 the caller names, and
// installs it there beside the one it replaces; the process then stops, the
// container restarts, and the entrypoint runs the installed binary.
//
// The entrypoint is what keeps that safe:
//
//   - it runs the installed binary only while the image is still the one it
//     was installed over (BASE): a newer image, deployed the usual way,
//     always wins;
//   - it counts starts in BOOTS, which ConfirmBoot clears once the binary has
//     run for confirmAfter; at three starts without that it goes back to the
//     previous binary, so one that cannot start undoes itself.
package fwaiupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	// binDirEnv names the volume the binary is installed on; unset, the
	// instance cannot update itself.
	binDirEnv = "CLIPROXY_BIN_DIR"
	// imageVersionEnv is the image's own version, which the entrypoint sets.
	imageVersionEnv = "CLIPROXY_IMAGE_VERSION"

	binaryName = "cli-proxy-api"
	// maxArchive bounds the download; a release archive is ~20 MB.
	maxArchive    = 200 << 20
	fetchTimeout  = 3 * time.Minute
	confirmAfter  = time.Minute
	installedFile = "cli-proxy-api"
	previousFile  = "cli-proxy-api.prev"
	versionFile   = "VERSION"
	baseFile      = "BASE"
	bootsFile     = "BOOTS"
)

var (
	// releaseURL is this fork's release asset; a variable for tests only.
	releaseURL = "https://github.com/dobig/CLIProxyAPI/releases/download/v%s/CLIProxyAPI_%s_linux_%s_no-plugin.tar.gz"
	// platform is the running OS and architecture; a variable for tests.
	platform = func() (string, string) { return runtime.GOOS, runtime.GOARCH }

	// assetArch is the release assets' name for each GOARCH they are built for.
	assetArch = map[string]string{"amd64": "amd64", "arm64": "aarch64"}

	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-fwai\.[0-9]+$`)
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)

	// ErrUnavailable: this instance has no volume to install on.
	ErrUnavailable = errors.New("self-update is not set up on this instance")
	// ErrInvalid: the version or checksum is malformed.
	ErrInvalid = errors.New("version must be <upstream>-fwai.<n> and sha256 64 hex digits")
)

// downloadURL is the release asset for this machine's architecture.
func downloadURL(version string) (string, error) {
	goos, goarch := platform()
	if goos != "linux" {
		return "", fmt.Errorf("%w: only linux instances update themselves", ErrUnavailable)
	}
	arch := assetArch[goarch]
	if arch == "" {
		return "", fmt.Errorf("%w: unsupported architecture %s", ErrUnavailable, goarch)
	}
	return fmt.Sprintf(releaseURL, version, version, arch), nil
}

// Status is what an instance can say about its updates.
type Status struct {
	Available bool   `json:"available"`
	Installed string `json:"installed,omitempty"`
	Image     string `json:"image,omitempty"`
	// Arch is the release asset's architecture name for this machine
	// (amd64, aarch64): which line of checksums.txt applies to it.
	Arch string `json:"arch,omitempty"`
}

// Current reports whether updates are set up, and what is installed.
func Current() Status {
	dir := os.Getenv(binDirEnv)
	_, goarch := platform()
	s := Status{Available: dir != "", Image: os.Getenv(imageVersionEnv), Arch: assetArch[goarch]}
	if dir != "" {
		if v, err := os.ReadFile(filepath.Join(dir, versionFile)); err == nil {
			s.Installed = strings.TrimSpace(string(v))
		}
	}
	return s
}

// Apply installs release version, whose archive must hash to sha. It does not
// restart anything; the caller stops the process once the answer is out.
func Apply(ctx context.Context, client *http.Client, version, sha string) error {
	dir := os.Getenv(binDirEnv)
	if dir == "" {
		return ErrUnavailable
	}
	version, sha = strings.TrimSpace(version), strings.ToLower(strings.TrimSpace(sha))
	if !versionPattern.MatchString(version) || !sha256Pattern.MatchString(sha) {
		return ErrInvalid
	}
	url, err := downloadURL(version)
	if err != nil {
		return err
	}
	archive, err := fetch(ctx, client, url)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(archive)
	if got := hex.EncodeToString(sum[:]); got != sha {
		return fmt.Errorf("checksum mismatch: release archive is %s, expected %s", got, sha)
	}
	binary, err := extract(archive)
	if err != nil {
		return err
	}
	return install(dir, binary, version, os.Getenv(imageVersionEnv))
}

func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download release: %s answered %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxArchive+1))
	if err != nil {
		return nil, fmt.Errorf("download release: %w", err)
	}
	if len(body) > maxArchive {
		return nil, fmt.Errorf("download release: larger than %d bytes", maxArchive)
	}
	return body, nil
}

// extract is the binary inside a release archive.
func extract(archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("read release archive: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("release archive has no %s", binaryName)
		}
		if err != nil {
			return nil, fmt.Errorf("read release archive: %w", err)
		}
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == binaryName {
			return io.ReadAll(io.LimitReader(tr, maxArchive))
		}
	}
}

// install puts binary in dir, keeping the one it replaces as the previous,
// and records its version and the image it was installed over. Each file is
// written aside and renamed in, so a crash leaves either the old state or the
// new one.
func install(dir string, binary []byte, version, image string) error {
	tmp := filepath.Join(dir, installedFile+".new")
	if err := os.WriteFile(tmp, binary, 0o755); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	current := filepath.Join(dir, installedFile)
	if _, err := os.Stat(current); err == nil {
		if err := os.Rename(current, filepath.Join(dir, previousFile)); err != nil {
			return fmt.Errorf("install: keep previous: %w", err)
		}
	} else {
		// Nothing installed yet: the previous is the image's own binary.
		_ = os.Remove(filepath.Join(dir, previousFile))
	}
	if err := os.Rename(tmp, current); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	for name, value := range map[string]string{versionFile: version, baseFile: image} {
		if err := writeFile(filepath.Join(dir, name), value); err != nil {
			return err
		}
	}
	_ = os.Remove(filepath.Join(dir, bootsFile))
	return nil
}

func writeFile(path, value string) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(value+"\n"), 0o644); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return os.Rename(tmp, path)
}

// ConfirmBoot clears the entrypoint's start count once the process has been
// up for confirmAfter, the sign that an installed binary works.
func ConfirmBoot(ctx context.Context) {
	dir := os.Getenv(binDirEnv)
	if dir == "" {
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(confirmAfter):
		_ = os.Remove(filepath.Join(dir, bootsFile))
	}
}
