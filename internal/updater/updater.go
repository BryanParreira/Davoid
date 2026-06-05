package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const releaseAPI = "https://api.github.com/repos/BryanParreira/Davoid/releases/latest"
const downloadBase = "https://github.com/BryanParreira/Davoid/releases/download"

type Release struct {
	TagName string `json:"tag_name"`
}

// CheckLatest returns the latest release tag (e.g. "v2.0.2") or "" on failure.
// Retries once on transient failure — VM networks can be slow/flaky on first connect.
func CheckLatest() string {
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(2 * time.Second)
		}
		tag := fetchLatestTag()
		if tag != "" {
			return tag
		}
	}
	return ""
}

func fetchLatestTag() string {
	req, err := http.NewRequest("GET", releaseAPI, nil)
	if err != nil {
		return ""
	}
	// GitHub API requires a User-Agent; without one, shared-IP VMs get rate-limited or 403'd
	req.Header.Set("User-Agent", "davoid-updater/"+runtime.GOOS+"-"+runtime.GOARCH)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var r Release
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return ""
	}
	return r.TagName
}

// IsNewer returns true if latest tag is semver-newer than current.
func IsNewer(current, latest string) bool {
	if latest == "" {
		return false
	}
	cur := parseSemver(strings.TrimPrefix(current, "v"))
	lat := parseSemver(strings.TrimPrefix(latest, "v"))
	if lat[0] != cur[0] {
		return lat[0] > cur[0]
	}
	if lat[1] != cur[1] {
		return lat[1] > cur[1]
	}
	return lat[2] > cur[2]
}

func parseSemver(v string) [3]int {
	parts := strings.SplitN(v, ".", 3)
	var out [3]int
	for i, p := range parts {
		if i >= 3 {
			break
		}
		if fields := strings.FieldsFunc(p, func(r rune) bool { return r == '-' }); len(fields) > 0 {
			p = fields[0]
		} else {
			continue
		}
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

// canWriteDir returns true if we can create files in the directory containing path.
func canWriteDir(path string) bool {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".davoid-write-test-*")
	if err != nil {
		return false
	}
	tmp.Close()
	os.Remove(tmp.Name())
	return true
}

// progressReader wraps an io.Reader and reports download progress.
type progressReader struct {
	r        io.Reader
	total    int64
	read     int64
	onUpdate func(pct int)
	lastPct  int
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	if p.total > 0 {
		pct := int(p.read * 100 / p.total)
		if pct != p.lastPct {
			p.lastPct = pct
			p.onUpdate(pct)
		}
	}
	return n, err
}

// Update downloads the latest binary for the current platform, verifies the
// checksum, and atomically replaces the running executable.
// If the install path is not writable, downloads to /tmp and prints a sudo command.
// Progress messages are sent on the returned channel (closed when done).
func Update(latest string) <-chan string {
	ch := make(chan string, 16)
	go func() {
		defer close(ch)
		send := func(s string) { ch <- s }

		os_ := runtime.GOOS
		arch := runtime.GOARCH
		asset := fmt.Sprintf("davoid-%s-%s", os_, arch)
		tag := latest

		binaryURL := fmt.Sprintf("%s/%s/%s", downloadBase, tag, asset)
		checksumURL := fmt.Sprintf("%s/%s/checksums.txt", downloadBase, tag)
		ua := "davoid-updater/" + os_ + "-" + arch
		client := &http.Client{Timeout: 180 * time.Second}

		doGet := func(url string) (*http.Response, error) {
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("User-Agent", ua)
			return client.Do(req)
		}

		// Resolve install path
		exePath, err := os.Executable()
		if err != nil {
			send("Error: cannot locate current binary: " + err.Error())
			return
		}
		// Resolve any symlinks so we write the real file
		if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
			exePath = resolved
		}

		needsSudo := !canWriteDir(exePath)
		fallbackPath := filepath.Join(os.TempDir(), "davoid-update")

		if needsSudo {
			send(fmt.Sprintf("⚠  No write access to %s", exePath))
			send("   Downloading to temp — will attempt sudo install.")
		} else {
			send(fmt.Sprintf("Downloading %s...", asset))
		}

		// Download binary
		resp, err := doGet(binaryURL)
		if err != nil {
			send("Error: download failed: " + err.Error())
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			send(fmt.Sprintf("Error: HTTP %d — asset not found for %s", resp.StatusCode, asset))
			send("  Try: curl -fsSL https://raw.githubusercontent.com/BryanParreira/Davoid/main/install.sh | bash")
			return
		}

		tmp, err := os.CreateTemp("", "davoid-update-*")
		if err != nil {
			send("Error: " + err.Error())
			return
		}
		tmpPath := tmp.Name()
		defer os.Remove(tmpPath)

		contentLength := resp.ContentLength
		h := sha256.New()
		pr := &progressReader{
			r:     resp.Body,
			total: contentLength,
			onUpdate: func(pct int) {
				send(fmt.Sprintf("Downloading... %d%%", pct))
			},
		}

		if _, err := io.Copy(io.MultiWriter(tmp, h), pr); err != nil {
			tmp.Close()
			send("Error: download error: " + err.Error())
			return
		}
		tmp.Close()
		actualSum := hex.EncodeToString(h.Sum(nil))

		send("Verifying checksum...")

		csResp, err := doGet(checksumURL)
		if err != nil {
			send("Error: checksum fetch failed: " + err.Error())
			return
		}
		defer csResp.Body.Close()
		csData, _ := io.ReadAll(csResp.Body)

		expectedSum := ""
		for _, line := range strings.Split(string(csData), "\n") {
			if strings.Contains(line, asset) {
				parts := strings.Fields(line)
				if len(parts) >= 1 {
					expectedSum = parts[0]
				}
				break
			}
		}

		if expectedSum == "" {
			send("Error: checksum not found for " + asset)
			return
		}
		if actualSum != expectedSum {
			send("Error: checksum mismatch — update aborted (file may be corrupt)")
			return
		}

		if err := os.Chmod(tmpPath, 0755); err != nil {
			send("Error: chmod failed: " + err.Error())
			return
		}

		// Save current binary as .bak for rollback before replacing
		backupPath := exePath + ".bak"
		if copyErr := copyFile(exePath, backupPath); copyErr == nil {
			os.Chmod(backupPath, 0755)
			send(fmt.Sprintf("Backup saved: %s.bak", filepath.Base(exePath)))
		}

		if needsSudo {
			// Copy verified binary to fallback path
			if err := copyFile(tmpPath, fallbackPath); err != nil {
				send("Error: could not write to temp: " + err.Error())
				return
			}
			os.Chmod(fallbackPath, 0755)

			// Try non-interactive sudo (works on Kali and any NOPASSWD sudo config)
			sudoInstalled := func() bool {
				_, err := exec.LookPath("sudo")
				return err == nil
			}
			if sudoInstalled() {
				send("Trying sudo install...")
				sudoCmd := exec.Command("sudo", "mv", fallbackPath, exePath)
				if err := sudoCmd.Run(); err == nil {
					send(fmt.Sprintf("✓ Updated to %s — restart davoid.", latest))
					send(fmt.Sprintf("  Rollback: sudo mv %s.bak %s", filepath.Base(exePath), exePath))
					return
				}
			}
			// sudo failed or not available — show manual command
			send("⚠  Sudo required. Run this to finish install:")
			send(fmt.Sprintf("  sudo mv %s %s", fallbackPath, exePath))
			send("Then relaunch davoid.")
		} else {
			send("Installing...")
			if err := os.Rename(tmpPath, exePath); err != nil {
				if err2 := copyFile(tmpPath, exePath); err2 != nil {
					send("Error: install failed: " + err2.Error())
					send(fmt.Sprintf("  Try manually: sudo mv %s %s", tmpPath, exePath))
					return
				}
			}
			send(fmt.Sprintf("✓ Updated to %s — restart davoid.", latest))
			send(fmt.Sprintf("  Rollback anytime: mv %s.bak %s", exePath, exePath))
		}
	}()
	return ch
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
