package credtester

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

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

func Run() error {
	ui.Header("Credential Tester — SSH / FTP / HTTP Re-Use Tester")

	// Collect targets
	fmt.Println()
	ui.Info("Enter targets (one per line, format: host:port/protocol e.g. 192.168.1.1:22/ssh)")
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
			ui.Warn("Format: host:port/proto  (e.g. 10.0.0.1:22/ssh, 10.0.0.1:80/http)")
			continue
		}
		targets = append(targets, t)
	}

	if len(targets) == 0 {
		ui.Fail("No targets provided.")
		return nil
	}

	// Collect credentials
	fmt.Println()
	ui.Info("Enter credentials (one per line, format: user:pass)")
	ui.Info("Leave blank and press Enter when done.")
	fmt.Println()

	var creds []credential
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
		eng, _ := engagement.Active()
		if eng != nil {
			for _, h := range allHits {
				engagement.LogFinding(eng.ID, "cred_tester", h.target.host,
					fmt.Sprintf("Valid credential: %s@%s (%s)", h.cred.user, h.target.host, h.target.proto),
					fmt.Sprintf("%s:%s", h.cred.user, h.cred.pass),
					"CRITICAL", fmt.Sprintf("%s:%s", h.cred.user, h.cred.pass))
			}
		}
	}

	ui.PressEnter()
	return nil
}

func parseTarget(s string) (target, bool) {
	// Format: host:port/proto
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
		// Add default port
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
	// Read banner
	conn.Read(buf)

	// Send USER
	conn.Write([]byte("USER " + c.user + "\r\n"))
	conn.Read(buf)

	// Send PASS
	conn.Write([]byte("PASS " + c.pass + "\r\n"))
	n, _ := conn.Read(buf)
	response := string(buf[:n])

	// 230 = Login successful
	return strings.HasPrefix(response, "230")
}

func testHTTP(targetURL string, c credential) bool {
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequest("GET", targetURL, nil)
	req.SetBasicAuth(c.user, c.pass)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
