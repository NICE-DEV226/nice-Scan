// Package update implements the CLI's self-update flow: resolve the
// latest release tag, tell the operator when the running binary is
// behind, download the platform asset, verify it against the release's
// published checksums (fail-closed), and atomically replace the
// running executable (previous binary kept as a .old backup).
//
// Honest verification boundary: sha256 against the checksums published
// in the release. The GPG-signed checksum chain (fingerprint pinned in
// SECURITY.md) remains on the installer path; the update command says
// so instead of claiming more than it verifies.
package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	releaseAPI    = "https://api.github.com/repos/NICE-DEV226/nice-Scan/releases/latest"
	userAgent     = "nice_scan-self-update (https://github.com/NICE-DEV226/nice-Scan)"
	checkInterval = 24 * time.Hour
	binaryName    = "nice_scan"
)

// ErrNotNewer reports that the running binary is already the latest.
var ErrNotNewer = errors.New("nice_scan is up to date")

// release is the API subset the flow needs (assets included).
type release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Client points at configurable endpoints so the flow can be exercised
// end-to-end against a fixture server in tests. DefaultClient ships
// with the public GitHub endpoints.
type Client struct {
	HTTP   *http.Client
	scheme string
	host   string // API host (api.github.com)
	repo   string
	domain string // download host (github.com)
}

// DefaultClient points at the public GitHub endpoints.
func DefaultClient() *Client {
	return &Client{
		HTTP:   &http.Client{Timeout: 30 * time.Second},
		scheme: "https",
		host:   "api.github.com",
		repo:   "NICE-DEV226/nice-Scan",
		domain: "github.com",
	}
}

func (c *Client) assetURLBase() string {
	return fmt.Sprintf("%s://%s/%s/releases/download", c.scheme, c.domain, c.repo)
}

// FetchRelease retrieves the latest release document (tag + assets).
func (c *Client) FetchRelease(ctx context.Context) (release, error) {
	url := fmt.Sprintf("%s://%s/repos/%s/releases/latest", c.scheme, c.host, c.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return release{}, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return release{}, fmt.Errorf("update check failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return release{}, fmt.Errorf("update check failed: HTTP %d (%s)", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rel release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return release{}, fmt.Errorf("update check failed: bad JSON: %w", err)
	}
	if !strings.HasPrefix(rel.TagName, "v") {
		return release{}, fmt.Errorf("update check failed: unexpected tag %q", rel.TagName)
	}
	return rel, nil
}

// Latest returns the latest published release tag ("v0.2.2").
func (c *Client) Latest(ctx context.Context) (string, error) {
	rel, err := c.FetchRelease(ctx)
	if err != nil {
		return "", err
	}
	return rel.TagName, nil
}

// Asset is one download candidate of a release.
type Asset struct {
	Name string
	SHA  string // published sha256
	URL  string
}

// Assets builds the platform candidates for tag from the release JSON
// and the published checksums file. Asset names follow the GoReleaser
// convention nice_scan_<tag>_<os>_<arch>.tar.gz (zip on windows), but
// only entries cross-checked against the checksums file survive.
func (c *Client) Assets(ctx context.Context, rel release, goos, goarch string) ([]Asset, error) {
	sums, err := c.fetchChecksums(ctx, rel.TagName)
	if err != nil {
		return nil, err
	}

	wantSuffix := "_" + goos + "_" + goarch + "." + archiveExt(goos)

	var candidates []Asset
	for _, a := range rel.Assets {
		if !strings.HasSuffix(a.Name, wantSuffix) {
			continue
		}
		if !strings.HasPrefix(a.Name, binaryName+"_") {
			continue
		}
		sha, ok := sums[a.Name]
		if !ok {
			// Fail-closed: an asset without a published checksum is
			// not installed.
			continue
		}
		candidates = append(candidates, Asset{
			Name: a.Name,
			SHA:  sha,
			URL:  assetURL(c, rel.TagName, a.Name, a.URL),
		})
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("release %s has no checksummed asset for %s/%s", rel.TagName, goos, goarch)
	}
	return candidates, nil
}

func assetURL(c *Client, tag, name, browserURL string) string {
	if browserURL != "" {
		return browserURL
	}
	return fmt.Sprintf("%s/%s/%s", c.assetURLBase(), tag, name)
}

func archiveExt(goos string) string {
	if goos == "windows" {
		return "zip"
	}
	return "tar.gz"
}

func (c *Client) fetchChecksums(ctx context.Context, tag string) (map[string]string, error) {
	// The checksums file ships next to the platform archives:
	// <repo>/releases/download/<tag>/nice_scan_<tag>_checksums.txt
	url := fmt.Sprintf("%s/%s/%s_%s_checksums.txt",
		c.assetURLBase(), tag, binaryName, strings.TrimPrefix(tag, "v"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("checksum download failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checksum download failed: HTTP %d", resp.StatusCode)
	}
	return parseChecksums(resp.Body)
}

func parseChecksums(r io.Reader) (map[string]string, error) {
	data, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return nil, err
	}
	sums := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// "<sha256>  <filename>" (shasum double-space style).
		parts := strings.Fields(line)
		if len(parts) != 2 || len(parts[0]) != 64 {
			return nil, fmt.Errorf("unexpected checksums line: %q", line)
		}
		if _, err := hex.DecodeString(parts[0]); err != nil {
			return nil, fmt.Errorf("non-hex checksum: %q", line)
		}
		sums[parts[1]] = parts[0]
	}
	if len(sums) == 0 {
		return nil, errors.New("empty checksums file")
	}
	return sums, nil
}

// Download fetches the archive to a temp file and verifies its sha256.
// A mismatching download is never extracted — the error names the
// mismatch explicitly.
func (c *Client) Download(ctx context.Context, asset Asset) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("binary download failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("binary download failed: HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "nice_scan-dl-*.archive")
	if err != nil {
		return "", err
	}
	// Ownership transfers to the caller: the archive must survive for
	// extraction and the caller cleans it up.

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), resp.Body)
	if err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("binary download failed: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if n == 0 {
		return "", errors.New("binary download failed: empty response")
	}

	got := hex.EncodeToString(h.Sum(nil))
	if got != asset.SHA {
		return "", fmt.Errorf("checksum MISMATCH for %s: got %s, published %s — refusing to install",
			asset.Name, got, asset.SHA)
	}
	return tmp.Name(), nil
}

// Extract pulls the platform binary out of the downloaded archive,
// refusing traversal entries outright.
func Extract(archivePath, goos string) (string, error) {
	dest, err := os.MkdirTemp("", "nice_scan-extract-")
	if err != nil {
		return "", err
	}
	if goos == "windows" {
		if err := extractZip(archivePath, dest); err != nil {
			return "", err
		}
	} else if err := extractTar(archivePath, dest); err != nil {
		return "", err
	}
	bin := filepath.Join(dest, binaryName)
	fi, err := os.Stat(bin)
	if err != nil {
		return "", fmt.Errorf("archive without %s entry: %w", binaryName, err)
	}
	if fi.IsDir() {
		return "", errors.New("archive binary entry is a directory")
	}
	return bin, nil
}

func safeRel(name string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean(name))
	if name == "" || filepath.IsAbs(name) ||
		strings.HasPrefix(clean, "../") || clean == ".." || strings.HasPrefix(clean, "~/") {
		return "", fmt.Errorf("unsafe archive entry %q", name)
	}
	return clean, nil
}

func extractTar(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	// The GoReleaser asset is a gzip-compressed tarball: unwrap the gzip
	// layer FIRST, tar parses the decompressed stream.
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("bad archive: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		// io.EOF is the normal archive end; anything else means a
		// truncated or corrupt stream.
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("bad archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		rel, err := safeRel(hdr.Name)
		if err != nil {
			return err
		}
		if filepath.Base(rel) != binaryName {
			continue
		}
		out, err := os.Create(filepath.Join(dest, binaryName))
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			_ = out.Close()
			return err
		}
		_ = out.Close()
		if err := os.Chmod(filepath.Join(dest, binaryName), 0o755); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("no %s entry in archive", binaryName)
}

func extractZip(path, dest string) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		rel, err := safeRel(zf.Name)
		if err != nil {
			return err
		}
		if filepath.Base(rel) != binaryName {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(filepath.Join(dest, binaryName), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			_ = rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		_ = rc.Close()
		_ = out.Close()
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("no %s entry in archive", binaryName)
}

// ReplaceSelf atomically moves the new binary over the running one and
// keeps the previous binary as <path>.old for rollback. replaceAt holds
// the mechanics; ReplaceSelf resolves the live executable path and
// delegates (keeps the mechanics testable without replacing the test
// binary itself).
func ReplaceSelf(newBin string) (installed, backup string, err error) {
	self, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return "", "", err
	}
	return replaceAt(self, newBin)
}

// replaceAt installs newBin over self.
//
// The staged copy deliberately lands in self's own directory: os.Rename is
// atomic only within one filesystem, and the download/extract directory is
// /tmp — frequently tmpfs — so renaming from there failed outright with
// "invalid cross-device link" on a normal Linux layout. The previous
// fallback then copied over the running executable, which Linux refuses
// (ETXTBSY "text file busy") and Windows locks: update could never install
// anything, on either platform, from any release.
func replaceAt(self, newBin string) (installed, backup string, err error) {
	stagedPath, err := stageNewBinary(filepath.Dir(self), newBin)
	if err != nil {
		return "", "", err
	}
	// The staged file survives only a completed install.
	swapped := false
	defer func() {
		if !swapped {
			_ = os.Remove(stagedPath)
		}
	}()

	backup = self + ".old"
	// Preserve the CURRENT binary before replacing it — not the downloaded
	// one (the operator rolls back to what ran until now). Copying a
	// running executable is allowed; writing over it is not.
	if err := copyFile(self, backup); err != nil {
		return "", "", fmt.Errorf("backup failed: %w", err)
	}

	if err := os.Rename(stagedPath, self); err != nil {
		// Windows cannot replace a running image, but renaming it aside is
		// permitted: swap through the backup name and undo on failure.
		if swapErr := swapThroughBackup(self, stagedPath, backup); swapErr != nil {
			return "", "", fmt.Errorf("install failed: %w (swap fallback: %w)", err, swapErr)
		}
	}
	swapped = true
	return self, backup, nil
}

// stageNewBinary copies src into a temp file inside dir and marks it
// executable, so the final rename is same-directory and atomic.
func stageNewBinary(dir, src string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("new binary missing: %s", src)
	}
	defer func() { _ = in.Close() }()
	if fi, err := in.Stat(); err != nil || fi.IsDir() {
		return "", fmt.Errorf("new binary missing: %s", src)
	}

	out, err := os.CreateTemp(dir, ".nice_scan-new-*")
	if err != nil {
		return "", fmt.Errorf("staging failed: %w", err)
	}
	path := out.Name()
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("staging failed: %w", err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("staging failed: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("staging failed: %w", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

// swapThroughBackup is the Windows path: move the running binary to the
// backup name, rename the staged file into place, and put the original back
// if that second rename fails so the operator is never left without a
// working binary.
func swapThroughBackup(self, stagedPath, backup string) error {
	_ = os.Remove(backup)
	if err := os.Rename(self, backup); err != nil {
		return err
	}
	if err := os.Rename(stagedPath, self); err != nil {
		_ = os.Rename(backup, self)
		return err
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// --- version comparison & check cache ---

// IsNewer compares two "vX.Y.Z" tags numerically; malformed tags never
// count as newer (no nags from parse garbage), so demanded "ok" is
// explicit.
func IsNewer(latest, current string) bool {
	l, lok := parseTriple(latest)
	c, cok := parseTriple(current)
	if !lok || !cok {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// parseTriple accepts exactly vMAJOR.MINOR.PATCH (numeric triple,
// no pre-release noise): any other shape is reported malformed.
func parseTriple(tag string) ([3]int, bool) {
	var t [3]int
	tag = strings.TrimPrefix(tag, "v")
	if tag == "" || strings.Trim(tag, "0123456789.") != "" {
		return t, false
	}
	parts := strings.Split(tag, ".")
	if len(parts) != 3 {
		return t, false
	}
	for i, p := range parts {
		if len(p) == 0 || (len(p) > 1 && p[0] == '0') {
			return t, false
		}
		if len(p) > 9 {
			return t, false
		}
		n := 0
		for j := 0; j < len(p); j++ {
			n = n*10 + int(p[j]-'0')
		}
		t[i] = n
	}
	return t, true
}

// IsComparable reports whether v is a strict vX.Y.Z tag — the only
// shape the registry supports. Pseudo-versions (dev trees stamp
// v0.2.3-0.<ts>-<hash>+dirty via BuildInfo) and pre-releases carry no
// comparable meaning and must be treated like "dev".
func IsComparable(v string) bool {
	_, ok := parseTriple(v)
	return ok
}

// cacheEntry is the persisted update-check record.
type cacheEntry struct {
	Checked time.Time `json:"checked"`
	Latest  string    `json:"latest"`
}

// CachePath exposes where the last-check record lives (UserCacheDir).
// cacheTestDir is the test hook: non-empty overrides the base directory.
var cacheTestDir string

func CachePath() (string, error) {
	base := cacheTestDir
	if base == "" {
		b, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		base = b
	}
	return filepath.Join(base, binaryName, "update-check.json"), nil
}

// CachedLatest returns (latest, fresh) from the persisted record; the
// record rate-limits startup checks to one per checkInterval (24 h).
func CachedLatest() (latest string, fresh bool, last time.Time) {
	path, err := CachePath()
	if err != nil {
		return "", false, time.Time{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, time.Time{}
	}
	var e cacheEntry
	if json.Unmarshal(data, &e) != nil {
		return "", false, time.Time{}
	}
	return e.Latest, time.Since(e.Checked) < checkInterval, e.Checked
}

// StoreCheck persists a successful check; failures are silent — the
// record is an optimization (fresh caches skip the network), not a
// requirement.
func StoreCheck(tag string) {
	path, err := CachePath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	data, err := json.Marshal(cacheEntry{Checked: time.Now(), Latest: tag})
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}
