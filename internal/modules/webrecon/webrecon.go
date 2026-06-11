package webrecon

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

var client = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

var securityHeaders = []struct {
	name     string
	severity string
}{
	{"Content-Security-Policy", "HIGH"},
	{"Strict-Transport-Security", "MEDIUM"},
	{"X-Frame-Options", "MEDIUM"},
	{"X-Content-Type-Options", "LOW"},
	{"Referrer-Policy", "LOW"},
	{"Permissions-Policy", "LOW"},
	{"X-XSS-Protection", "LOW"},
}

var sensitivePatterns = []struct {
	name    string
	pattern string
}{
	{"Email", `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`},
	{"API Key (generic)", `(?i)(api[_\-]?key|apikey|api_secret)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})`},
	{"AWS Key", `AKIA[0-9A-Z]{16}`},
	{"JWT Token", `eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}`},
	{"Private Key", `-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----`},
}

var sensitivePaths = []string{
	"/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.production",
	"/config.php", "/config.yml", "/config.json", "/settings.py",
	"/admin", "/admin/login", "/wp-admin", "/wp-login.php",
	"/phpmyadmin", "/phpMyAdmin", "/pma",
	"/api", "/api/v1", "/api/v2", "/graphql", "/swagger.json", "/openapi.json",
	"/robots.txt", "/sitemap.xml", "/.htaccess", "/server-status",
	"/backup.zip", "/backup.tar.gz", "/dump.sql", "/db.sql",
	"/.DS_Store", "/Thumbs.db",
	"/actuator", "/actuator/health", "/actuator/env",
	"/.well-known/security.txt",
}

// RunTarget runs web recon against a pre-determined URL (no prompts).
// Used by the webintel pipeline module.
func RunTarget(targetURL string) error {
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "https://" + targetURL
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	eng, _ := engagement.Active()
	return runRecon(targetURL, parsed, eng)
}

func Run() error {
	ui.Header("Web Ghost Elite — Professional Web Auditor")

	targetURL := ui.Prompt("Target URL (e.g. https://example.com)")
	if targetURL == "" {
		return nil
	}
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "https://" + targetURL
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		ui.Fail("Invalid URL.")
		return nil
	}

	eng, _ := engagement.Active()
	return runRecon(targetURL, parsed, eng)
}

func runRecon(targetURL string, parsed *url.URL, eng *engagement.Engagement) error {
	// ── Initial request ──────────────────────────────────────────────────────
	ui.Info(fmt.Sprintf("Connecting to %s...", parsed.Host))
	resp, err := client.Get(targetURL)
	if err != nil {
		ui.Fail(fmt.Sprintf("Connection failed: %v", err))
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	fmt.Println()
	ui.Divider()
	ui.Info("Server Fingerprint")
	ui.Divider()
	fmt.Printf("  %s  %s\n", ui.Cyan.Render("Status  "), statusStyle(resp.StatusCode))
	if server := resp.Header.Get("Server"); server != "" {
		fmt.Printf("  %s  %s\n", ui.Cyan.Render("Server  "), server)
		if eng != nil {
			engagement.LogFinding(eng.ID, "web_recon", parsed.Host,
				"Server banner disclosure: "+server,
				"Server header reveals technology stack", "LOW", server)
		}
	}
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		fmt.Printf("  %s  %s\n", ui.Cyan.Render("Powered "), powered)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		fmt.Printf("  %s  %s\n", ui.Cyan.Render("Type    "), ct)
	}

	// ── Security headers ─────────────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Security Header Audit")
	ui.Divider()
	for _, h := range securityHeaders {
		val := resp.Header.Get(h.name)
		if val == "" {
			fmt.Printf("  %s  %-35s  %s\n",
				ui.Red.Render("MISS"),
				h.name,
				ui.Yellow.Render("["+h.severity+"]"),
			)
			if eng != nil {
				engagement.LogFinding(eng.ID, "web_recon", parsed.Host,
					"Missing security header: "+h.name,
					"Header not present in HTTP response", h.severity, "")
			}
		} else {
			fmt.Printf("  %s  %-35s  %s\n",
				ui.Green.Render("OK  "),
				h.name,
				ui.Dim.Render(truncate(val, 50)),
			)
		}
	}

	// ── Sensitive data extraction ─────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Sensitive Data Extraction")
	ui.Divider()
	for _, p := range sensitivePatterns {
		re := regexp.MustCompile(p.pattern)
		matches := re.FindAllString(bodyStr, 5)
		if len(matches) > 0 {
			for _, m := range matches {
				fmt.Printf("  %s  %-20s  %s\n",
					ui.Red.Render("FOUND"),
					p.name,
					ui.Yellow.Render(truncate(m, 60)),
				)
				if eng != nil {
					engagement.LogFinding(eng.ID, "web_recon", parsed.Host,
						fmt.Sprintf("Sensitive data in HTML: %s", p.name),
						m, "HIGH", m)
				}
			}
		}
	}

	// ── Path fuzzing ─────────────────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info(fmt.Sprintf("Path Fuzzing (%d paths)", len(sensitivePaths)))
	ui.Divider()

	type pathResult struct {
		path   string
		code   int
		length int
	}

	results := make(chan pathResult, len(sensitivePaths))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	base := strings.TrimRight(targetURL, "/")
	for _, p := range sensitivePaths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			u := base + path
			resp, err := client.Get(u)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 404 {
				results <- pathResult{path: path, code: resp.StatusCode, length: len(body)}
			}
		}(p)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		codeStr := statusStyle(r.code)
		fmt.Printf("  %s  %-35s  %s  (%d bytes)\n",
			codeStr,
			r.path,
			ui.Dim.Render(""),
			r.length,
		)
		sev := "LOW"
		if r.code == 200 {
			sev = "HIGH"
		}
		if eng != nil {
			engagement.LogFinding(eng.ID, "web_recon", parsed.Host,
				fmt.Sprintf("Sensitive path accessible: %s (HTTP %d)", r.path, r.code),
				base+r.path, sev, "")
		}
	}

	fmt.Println()
	ui.Success("Web recon complete.")
	ui.PressEnter()
	return nil
}

func statusStyle(code int) string {
	s := fmt.Sprintf("%d", code)
	if code >= 200 && code < 300 {
		return ui.Green.Render(s)
	}
	if code >= 300 && code < 400 {
		return ui.Cyan.Render(s)
	}
	if code >= 400 {
		return ui.Red.Render(s)
	}
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
