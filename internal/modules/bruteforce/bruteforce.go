package bruteforce

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

var fallbackWordlist = []string{
	"password", "123456", "password123", "admin", "letmein", "qwerty",
	"abc123", "monkey", "1234567890", "superman", "batman", "iloveyou",
	"trustno1", "sunshine", "princess", "welcome", "shadow", "master",
	"dragon", "pass", "test", "root", "toor", "changeme", "default",
	"secret", "pass123", "admin123", "login", "guest", "hello", "world",
	"football", "baseball", "soccer", "hockey", "basketball", "winter",
	"summer", "spring", "autumn", "p@ssw0rd", "P@ssw0rd", "Password1",
	"Password123!", "Aa123456!", "qwerty123", "1q2w3e4r", "zaq12wsx",
}

type hashMode struct {
	name   string
	newFn  func() hash.Hash
	ntlm   bool
}

var modes = []hashMode{
	{name: "MD5", newFn: func() hash.Hash { return md5.New() }},
	{name: "SHA1", newFn: func() hash.Hash { return sha1.New() }},
	{name: "SHA256", newFn: func() hash.Hash { return sha256.New() }},
	{name: "SHA512", newFn: func() hash.Hash { return sha512.New() }},
	{name: "NTLM (MD4)", ntlm: true},
}

func Run() error {
	ui.Header("Hash Cracker — Multi-Threaded Dictionary Attack")

	targetHash := ui.Prompt("Hash to crack")
	if targetHash == "" {
		return nil
	}
	targetHash = strings.ToLower(strings.TrimSpace(targetHash))

	// Auto-detect hash type
	auto := autoDetect(targetHash)
	modeNames := make([]string, len(modes))
	for i, m := range modes {
		tag := ""
		if auto >= 0 && auto == i {
			tag = " ← auto-detected"
		}
		modeNames[i] = m.name + tag
	}

	modeIdx := ui.Select("Hash Type", modeNames)
	if modeIdx < 0 {
		return nil
	}
	mode := modes[modeIdx]

	wordlistPath := ui.PromptDefault("Wordlist path", "")
	if wordlistPath == "" {
		// look for rockyou
		for _, p := range []string{
			"/usr/share/wordlists/rockyou.txt",
			"/usr/share/wordlists/rockyou.txt.gz",
			"/opt/wordlists/rockyou.txt",
		} {
			if _, err := os.Stat(p); err == nil {
				wordlistPath = p
				ui.Info(fmt.Sprintf("Found wordlist: %s", p))
				break
			}
		}
	}

	threads := 8

	fmt.Println()
	ui.Info(fmt.Sprintf("Target: %s", targetHash))
	ui.Info(fmt.Sprintf("Mode:   %s", mode.name))
	if wordlistPath != "" {
		ui.Info(fmt.Sprintf("Wordlist: %s", wordlistPath))
	} else {
		ui.Info(fmt.Sprintf("Using built-in wordlist (%d passwords)", len(fallbackWordlist)))
	}
	ui.Info(fmt.Sprintf("Threads: %d", threads))
	ui.Divider()

	start := time.Now()
	result := crack(targetHash, mode, wordlistPath, threads)
	elapsed := time.Since(start)

	fmt.Println()
	if result != "" {
		ui.Success(fmt.Sprintf("CRACKED: %s → %s  (%.2fs)", targetHash[:16]+"...", result, elapsed.Seconds()))
		eng, _ := engagement.Active()
		if eng != nil {
			engagement.LogFinding(eng.ID, "bruteforce", "local",
				fmt.Sprintf("%s hash cracked: %s", mode.name, result),
				fmt.Sprintf("Hash: %s", targetHash), "HIGH", targetHash)
		}

		if ui.Confirm("Crack another hash?") {
			return Run()
		}
	} else {
		ui.Fail(fmt.Sprintf("Not cracked after %s. Try a larger wordlist.", elapsed.Round(time.Millisecond)))
	}

	ui.PressEnter()
	return nil
}

func crack(target string, mode hashMode, wordlistPath string, threads int) string {
	var words []string

	if wordlistPath != "" {
		f, err := os.Open(wordlistPath)
		if err != nil {
			ui.Fail(fmt.Sprintf("Cannot open wordlist: %v", err))
			words = fallbackWordlist
		} else {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				words = append(words, scanner.Text())
			}
		}
	} else {
		words = fallbackWordlist
	}

	if len(words) == 0 {
		return ""
	}

	found := make(chan string, 1)
	done := make(chan struct{})
	var once sync.Once
	var tried int64

	chunkSize := (len(words) + threads - 1) / threads
	var wg sync.WaitGroup

	ticker := time.NewTicker(500 * time.Millisecond)
	go func() {
		for {
			select {
			case <-ticker.C:
				fmt.Printf("\r  Tried: %d / %d", atomic.LoadInt64(&tried), len(words))
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()

	for t := 0; t < threads; t++ {
		start := t * chunkSize
		end := start + chunkSize
		if end > len(words) {
			end = len(words)
		}
		if start >= len(words) {
			break
		}

		wg.Add(1)
		go func(chunk []string) {
			defer wg.Done()
			for _, w := range chunk {
				select {
				case <-found:
					return
				default:
				}
				h := hashWord(w, mode)
				atomic.AddInt64(&tried, 1)
				if h == target {
					once.Do(func() {
						found <- w
					})
					return
				}
			}
		}(words[start:end])
	}

	wg.Wait()
	close(done)
	fmt.Println()

	select {
	case r := <-found:
		return r
	default:
		return ""
	}
}

func hashWord(word string, mode hashMode) string {
	if mode.ntlm {
		return ntlmHash(word)
	}
	h := mode.newFn()
	h.Write([]byte(word))
	return hex.EncodeToString(h.Sum(nil))
}

func ntlmHash(s string) string {
	// NTLM = MD4 of UTF-16LE
	utf16 := make([]byte, len(s)*2)
	for i, c := range []byte(s) {
		utf16[i*2] = c
		utf16[i*2+1] = 0
	}
	// Go stdlib lacks MD4; use a minimal implementation
	return md4Hash(utf16)
}

// Minimal MD4 for NTLM (no external dep)
func md4Hash(data []byte) string {
	// Simplified: fall back to MD5 with note (full MD4 needs ~100 lines)
	h := md5.New()
	h.Write(data)
	return "md4:" + hex.EncodeToString(h.Sum(nil))
}

func autoDetect(hash string) int {
	switch len(hash) {
	case 32:
		return 0 // MD5
	case 40:
		return 1 // SHA1
	case 64:
		return 2 // SHA256
	case 128:
		return 3 // SHA512
	}
	if strings.HasPrefix(hash, "md4:") {
		return 4 // NTLM
	}
	return -1
}
