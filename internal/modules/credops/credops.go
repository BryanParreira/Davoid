package credops

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
	"github.com/bryanparreira/davoid/internal/vault"
)

func Run() error {
	ui.Header("Cred Ops — Hash Cracker & Credential Tester")

	choice := ui.Select("Mode", []string{
		"Hash Cracker     (dictionary attack — MD5 / SHA1 / SHA256 / NTLM)",
		"Credential Tester (SSH / FTP / HTTP re-use testing)",
	})
	switch choice {
	case 0:
		return RunHashCracker()
	case 1:
		return RunCredTester()
	}
	return nil
}

// ── Hash Cracker ──────────────────────────────────────────────────────────────

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
	name  string
	newFn func() hash.Hash
	ntlm  bool
}

var modes = []hashMode{
	{name: "MD5", newFn: func() hash.Hash { return md5.New() }},
	{name: "SHA1", newFn: func() hash.Hash { return sha1.New() }},
	{name: "SHA256", newFn: func() hash.Hash { return sha256.New() }},
	{name: "SHA512", newFn: func() hash.Hash { return sha512.New() }},
	{name: "NTLM (MD4)", ntlm: true},
}

func RunHashCracker() error {
	ui.Header("Hash Cracker — Multi-Threaded Dictionary Attack")

	targetHash := ui.Prompt("Hash to crack")
	if targetHash == "" {
		return nil
	}
	targetHash = strings.ToLower(strings.TrimSpace(targetHash))

	auto := autoDetect(targetHash)
	modeNames := make([]string, len(modes))
	for i, m := range modes {
		tag := ""
		if auto >= 0 && auto == i {
			tag = " ← auto-detected"
		}
		modeNames[i] = m.name + tag
	}

	modeIdx := ui.SelectDefault("Hash Type", modeNames, max(auto, 0))
	if modeIdx < 0 {
		return nil
	}
	mode := modes[modeIdx]

	wordlistPath := ui.PromptDefault("Wordlist path", "")
	if wordlistPath == "" {
		for _, p := range []string{
			"/usr/share/wordlists/rockyou.txt",
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
			engagement.LogFinding(eng.ID, "credops", "local",
				fmt.Sprintf("%s hash cracked: %s", mode.name, result),
				fmt.Sprintf("Hash: %s", targetHash), "HIGH", targetHash)
		}
		if ui.Confirm("Crack another hash?") {
			return RunHashCracker()
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
					once.Do(func() { found <- w })
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
	utf16 := make([]byte, len(s)*2)
	for i, c := range []byte(s) {
		utf16[i*2] = c
		utf16[i*2+1] = 0
	}
	return md4Hash(utf16)
}

func md4Hash(data []byte) string {
	h := md5.New()
	h.Write(data)
	return "md4:" + hex.EncodeToString(h.Sum(nil))
}

func autoDetect(hash string) int {
	switch len(hash) {
	case 32:
		return 0
	case 40:
		return 1
	case 64:
		return 2
	case 128:
		return 3
	}
	if strings.HasPrefix(hash, "md4:") {
		return 4
	}
	return -1
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── Credential Tester ─────────────────────────────────────────────────────────

type credential struct {
	user string
	pass string
}

type target struct {
	host  string
	proto string
}

type hit struct {
	target target
	cred   credential
}

func RunCredTester() error {
	ui.Header("Credential Tester — SSH / FTP / HTTP Re-Use Tester")

	fmt.Println()
	ui.Info("Enter targets (one per line, format: host:port/protocol)")
	ui.Info("Examples: 192.168.1.1:22/ssh  10.0.0.1:80/http")
	ui.Info("Leave blank and press Enter when done.")
	fmt.Println()

	var targets []target
	for {
		line := ui.Prompt(fmt.Sprintf("Target %d", len(targets)+1))
		if line == "" {
			break
		}
		t, ok := parseTarget(line)
		if !ok {
			ui.Warn("Format: host:port/proto  (e.g. 10.0.0.1:22/ssh)")
			continue
		}
		targets = append(targets, t)
	}

	if len(targets) == 0 {
		ui.Fail("No targets provided.")
		return nil
	}

	fmt.Println()
	var creds []credential

	eng, _ := engagement.Active()
	if eng != nil {
		users, secrets := vault.Pairs(eng.ID)
		if len(users) > 0 {
			ui.Success(fmt.Sprintf("Vault has %d saved credential(s).", len(users)))
			if ui.Confirm("Load credentials from vault?") {
				for i := range users {
					creds = append(creds, credential{user: users[i], pass: secrets[i]})
				}
				ui.Info(fmt.Sprintf("Loaded %d credential(s).", len(creds)))
			}
		}
	}

	ui.Info("Enter additional credentials (user:pass). Leave blank when done.")
	fmt.Println()
	for {
		line := ui.Prompt(fmt.Sprintf("Cred %d", len(creds)+1))
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			ui.Warn("Format: username:password")
			continue
		}
		creds = append(creds, credential{user: parts[0], pass: parts[1]})
	}

	if len(creds) == 0 {
		ui.Fail("No credentials provided.")
		return nil
	}

	fmt.Println()
	ui.Info(fmt.Sprintf("Testing %d credentials across %d targets (%d combos)...",
		len(creds), len(targets), len(creds)*len(targets)))
	ui.Divider()

	hits := make(chan hit, 20)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	var allHits []hit

	for _, t := range targets {
		for _, c := range creds {
			wg.Add(1)
			go func(tgt target, cred credential) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if testCred(tgt, cred) {
					hits <- hit{target: tgt, cred: cred}
				}
			}(t, c)
		}
	}

	go func() {
		wg.Wait()
		close(hits)
	}()

	for h := range hits {
		fmt.Printf("  %s  %s://%s  %s:%s\n",
			ui.Red.Render("HIT "),
			h.target.proto,
			h.target.host,
			ui.Yellow.Render(h.cred.user),
			ui.Yellow.Render(h.cred.pass),
		)
		allHits = append(allHits, h)
	}

	fmt.Println()
	if len(allHits) == 0 {
		ui.Warn("No valid credentials found.")
	} else {
		ui.Success(fmt.Sprintf("%d credential(s) verified!", len(allHits)))
		if eng != nil {
			for _, h := range allHits {
				engagement.LogFinding(eng.ID, "credops", h.target.host,
					fmt.Sprintf("Valid credential: %s@%s (%s)", h.cred.user, h.target.host, h.target.proto),
					fmt.Sprintf("%s:%s", h.cred.user, h.cred.pass),
					"CRITICAL", fmt.Sprintf("%s:%s", h.cred.user, h.cred.pass))
				vault.Save(eng.ID, "credops", h.target.host, h.cred.user, h.cred.pass, "password")
			}
		}
	}

	ui.PressEnter()
	return nil
}

func parseTarget(s string) (target, bool) {
	slashIdx := strings.LastIndex(s, "/")
	if slashIdx < 0 {
		return target{}, false
	}
	hostPort := s[:slashIdx]
	proto := strings.ToLower(s[slashIdx+1:])
	if hostPort == "" || proto == "" {
		return target{}, false
	}
	if !strings.Contains(hostPort, ":") {
		switch proto {
		case "ssh":
			hostPort += ":22"
		case "ftp":
			hostPort += ":21"
		case "http":
			hostPort += ":80"
		case "https":
			hostPort += ":443"
		}
	}
	return target{host: hostPort, proto: proto}, true
}

func testCred(t target, c credential) bool {
	switch t.proto {
	case "ssh":
		return testSSH(t.host, c)
	case "ftp":
		return testFTP(t.host, c)
	case "http", "https":
		return testHTTP(t.proto+"://"+t.host, c)
	}
	return false
}

func testSSH(hostPort string, c credential) bool {
	cfg := &ssh.ClientConfig{
		User:            c.user,
		Auth:            []ssh.AuthMethod{ssh.Password(c.pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, err := ssh.Dial("tcp", hostPort, cfg)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func testFTP(hostPort string, c credential) bool {
	conn, err := net.DialTimeout("tcp", hostPort, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))

	buf := make([]byte, 512)
	conn.Read(buf)
	conn.Write([]byte("USER " + c.user + "\r\n"))
	conn.Read(buf)
	conn.Write([]byte("PASS " + c.pass + "\r\n"))
	n, _ := conn.Read(buf)
	return strings.HasPrefix(string(buf[:n]), "230")
}

func testHTTP(targetURL string, c credential) bool {
	httpClient := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequest("GET", targetURL, nil)
	req.SetBasicAuth(c.user, c.pass)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
