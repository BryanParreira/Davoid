package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

const releaseAPI = "https://api.github.com/repos/BryanParreira/Davoid/releases/latest"
const downloadBase = "https://github.com/BryanParreira/Davoid/releases/download"

type Release struct {
	TagName string `json:"tag_name"`
}

// CheckLatest returns the latest release tag (e.g. "v2.0.2") or "" on failure.
func CheckLatest() string {
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(releaseAPI)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var r Release
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return ""
	}
	return r.TagName
}

// IsNewer returns true if latest tag is newer than current version string.
func IsNewer(current, latest string) bool {
	cur := strings.TrimPrefix(current, "v")
	lat := strings.TrimPrefix(latest, "v")
	return lat != "" && lat != cur
}

// Update downloads the latest binary for the current platform, verifies the
// checksum, and atomically replaces the running executable.
// Progress messages are sent on the returned channel (closed when done).
func Update(latest string) <-chan string {
	ch := make(chan string, 8)
	go func() {
		defer close(ch)

		send := func(s string) { ch <- s }

		os_ := runtime.GOOS
		arch := runtime.GOARCH
		asset := fmt.Sprintf("davoid-%s-%s", os_, arch)
		tag := latest

		send(fmt.Sprintf("Downloading %s...", asset))

		binaryURL := fmt.Sprintf("%s/%s/%s", downloadBase, tag, asset)
		checksumURL := fmt.Sprintf("%s/%s/checksums.txt", downloadBase, tag)

		client := &http.Client{Timeout: 60 * time.Second}

		// Download binary to temp file
		tmp, err := os.CreateTemp("", "davoid-update-*")
		if err != nil {
			send("Error: " + err.Error())
			return
		}
		tmpPath := tmp.Name()
		defer os.Remove(tmpPath)

		resp, err := client.Get(binaryURL)
		if err != nil {
			tmp.Close()
			send("Download failed: " + err.Error())
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			tmp.Close()
			send(fmt.Sprintf("Download failed: HTTP %d", resp.StatusCode))
			return
		}

		h := sha256.New()
		if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
			tmp.Close()
			send("Download error: " + err.Error())
			return
		}
		tmp.Close()
		actualSum := hex.EncodeToString(h.Sum(nil))

		send("Verifying checksum...")

		// Download checksums.txt
		csResp, err := client.Get(checksumURL)
		if err != nil {
			send("Checksum fetch failed: " + err.Error())
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
			send("Error: could not find checksum for " + asset)
			return
		}
		if actualSum != expectedSum {
			send("Error: checksum mismatch — update aborted")
			return
		}

		send("Installing...")

		// Get current executable path
		exePath, err := os.Executable()
		if err != nil {
			send("Error: cannot locate current binary: " + err.Error())
			return
		}

		// Make it executable
		if err := os.Chmod(tmpPath, 0755); err != nil {
			send("Error: chmod failed: " + err.Error())
			return
		}

		// Atomic replace
		if err := os.Rename(tmpPath, exePath); err != nil {
			// Rename may fail across filesystems — fallback to copy
			if err2 := copyFile(tmpPath, exePath); err2 != nil {
				send("Error: install failed: " + err2.Error())
				return
			}
		}

		send(fmt.Sprintf("Updated to %s — restart davoid to use the new version.", latest))
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
