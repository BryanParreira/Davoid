package webscan

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// ─── Data structures ──────────────────────────────────────────────────────────

type crawlResult struct {
	rawURL  string
	params  []string
	forms   []formData
	cookies []*http.Cookie
	headers http.Header
	body    string
	status  int
}

type formData struct {
	action string
	method string
	fields []formField
}

type formField struct {
	name  string
	value string
	ftype string
}

type finding struct {
	vuln   string
	sev    string
	target string
	param  string
	detail string
}

// ─── Detection patterns ───────────────────────────────────────────────────────

var sqlErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)you have an error in your sql syntax`),
	regexp.MustCompile(`(?i)warning: mysql`),
	regexp.MustCompile(`(?i)unclosed quotation mark`),
	regexp.MustCompile(`(?i)quoted string not properly terminated`),
	regexp.MustCompile(`ORA-[0-9]{4,5}`),
	regexp.MustCompile(`(?i)pg::syntaxerror`),
	regexp.MustCompile(`(?i)SQLite.*error`),
	regexp.MustCompile(`SQLSTATE\[`),
	regexp.MustCompile(`(?i)Microsoft SQL Native Client`),
	regexp.MustCompile(`(?i)\[SQL Server\]`),
}

var verboseErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)traceback \(most recent call`),
	regexp.MustCompile(`(?i)stack trace:`),
	regexp.MustCompile(`(?i)at java\.`),
	regexp.MustCompile(`(?i)javax\.servlet`),
	regexp.MustCompile(`(?i)fatal error:`),
	regexp.MustCompile(`(?i)unhandled exception`),
}

// ─── Entry point ─────────────────────────────────────────────────────────────

func Run() error {
	ui.Header("Web App Scanning Suite")

	targetURL := ui.Prompt("Target URL (e.g. https://example.com)")
	if targetURL == "" {
		return nil
	}
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "https://" + targetURL
	}
	if _, err := url.Parse(targetURL); err != nil {
		ui.Fail("Invalid URL.")
		return nil
	}

	eng, _ := engagement.Active()
	runFull(targetURL, eng)
	ui.PressEnter()
	return nil
}

func RunFull() error {
	ui.Header("Web Scanner — Full Scan")
	targetURL, eng := promptTarget()
	if targetURL == "" {
		return nil
	}
	runFull(targetURL, eng)
	ui.PressEnter()
	return nil
}

func RunSpider() error {
	ui.Header("Web Spider — Crawler & Surface Mapper")
	targetURL, _ := promptTarget()
	if targetURL == "" {
		return nil
	}
	results := runSpider(targetURL)
	printSpiderSummary(results)
	ui.PressEnter()
	return nil
}

func RunPassive() error {
	ui.Header("Passive Analyzer — Headers · Cookies · CORS · Leaks")
	targetURL, eng := promptTarget()
	if targetURL == "" {
		return nil
	}
	runPassiveOnly(targetURL, eng)
	ui.PressEnter()
	return nil
}

func RunActive() error {
	ui.Header("Active Scanner — SQLi · XSS · Traversal · SSTI · RCE")
	targetURL, eng := promptTarget()
	if targetURL == "" {
		return nil
	}
	runActiveOnly(targetURL, eng)
	ui.PressEnter()
	return nil
}

func promptTarget() (string, *engagement.Engagement) {
	targetURL := ui.Prompt("Target URL (e.g. https://example.com)")
	if targetURL == "" {
		return "", nil
	}
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "https://" + targetURL
	}
	if _, err := url.Parse(targetURL); err != nil {
		ui.Fail("Invalid URL.")
		return "", nil
	}
	eng, _ := engagement.Active()
	return targetURL, eng
}

// ─── Spider ───────────────────────────────────────────────────────────────────

func runSpider(baseURL string) []crawlResult {
	ui.Divider()
	ui.Info(fmt.Sprintf("Spidering %s...", baseURL))
	ui.Divider()
	return spider(baseURL, 3, 100)
}

func printSpiderSummary(results []crawlResult) {
	params, forms := 0, 0
	for _, r := range results {
		params += len(r.params)
		forms += len(r.forms)
	}
	fmt.Println()
	ui.Success(fmt.Sprintf("Spider complete: %d URLs  %d forms  %d params", len(results), forms, params))
}

func spider(baseURL string, maxDepth, maxPages int) []crawlResult {
	type qitem struct {
		u     string
		depth int
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	visited := make(map[string]bool)
	queue := []qitem{{baseURL, 0}}
	var results []crawlResult

	for len(queue) > 0 && len(results) < maxPages {
		item := queue[0]
		queue = queue[1:]

		norm := normalizeURL(item.u)
		if visited[norm] {
			continue
		}
		visited[norm] = true

		resp, err := httpClient.Get(item.u)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)

		parsed, _ := url.Parse(item.u)
		var params []string
		for k := range parsed.Query() {
			params = append(params, k)
		}

		var forms []formData
		var links []string
		ct := resp.Header.Get("Content-Type")
		if strings.Contains(ct, "html") || strings.Contains(bodyStr, "<html") {
			doc, parseErr := html.Parse(strings.NewReader(bodyStr))
			if parseErr == nil {
				links = extractLinks(doc, base)
				forms = extractForms(doc, item.u)
			}
		}

		results = append(results, crawlResult{
			rawURL:  item.u,
			params:  params,
			forms:   forms,
			cookies: resp.Cookies(),
			headers: resp.Header,
			body:    bodyStr,
			status:  resp.StatusCode,
		})

		pInfo := ""
		if len(params) > 0 {
			pInfo = fmt.Sprintf(" [%d params]", len(params))
		}
		fInfo := ""
		if len(forms) > 0 {
			fInfo = fmt.Sprintf(" [%d forms]", len(forms))
		}
		fmt.Printf("  %s  %s%s%s\n",
			statusBadge(resp.StatusCode),
			truncatePath(item.u, 65),
			ui.Dim.Render(pInfo),
			ui.Dim.Render(fInfo),
		)

		if item.depth < maxDepth {
			for _, link := range links {
				if !visited[normalizeURL(link)] {
					queue = append(queue, qitem{link, item.depth + 1})
				}
			}
		}
	}

	return results
}

func extractLinks(doc *html.Node, base *url.URL) []string {
	seen := make(map[string]bool)
	var links []string

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			var href string
			switch n.Data {
			case "a", "link":
				for _, a := range n.Attr {
					if a.Key == "href" {
						href = a.Val
					}
				}
			case "form":
				for _, a := range n.Attr {
					if a.Key == "action" {
						href = a.Val
					}
				}
			}
			if href != "" {
				resolved := resolveURL(base, href)
				if resolved != "" && !seen[resolved] {
					seen[resolved] = true
					links = append(links, resolved)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return links
}

func extractForms(doc *html.Node, pageURL string) []formData {
	base, _ := url.Parse(pageURL)
	var forms []formData

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			f := formData{method: "GET", action: pageURL}
			for _, a := range n.Attr {
				switch a.Key {
				case "action":
					if ref, err := url.Parse(a.Val); err == nil {
						f.action = base.ResolveReference(ref).String()
					}
				case "method":
					f.method = strings.ToUpper(a.Val)
				}
			}

			var walkForm func(*html.Node)
			walkForm = func(fn *html.Node) {
				if fn.Type == html.ElementNode {
					switch fn.Data {
					case "input", "textarea", "select":
						field := formField{ftype: "text"}
						for _, a := range fn.Attr {
							switch a.Key {
							case "name":
								field.name = a.Val
							case "value":
								field.value = a.Val
							case "type":
								field.ftype = a.Val
							}
						}
						skip := field.name == "" ||
							field.ftype == "submit" ||
							field.ftype == "button" ||
							field.ftype == "hidden" ||
							field.ftype == "checkbox" ||
							field.ftype == "radio"
						if !skip {
							f.fields = append(f.fields, field)
						}
					}
				}
				for c := fn.FirstChild; c != nil; c = c.NextSibling {
					walkForm(c)
				}
			}
			walkForm(n)
			forms = append(forms, f)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return forms
}

// ─── Passive scanner ──────────────────────────────────────────────────────────

func runPassiveOnly(baseURL string, eng *engagement.Engagement) {
	ui.Divider()
	ui.Info("Spidering for passive analysis...")
	ui.Divider()
	results := spider(baseURL, 2, 50)
	fmt.Println()
	ui.Divider()
	ui.Info("Passive Analysis")
	ui.Divider()
	findings := passiveScan(results)
	printFindings(findings, eng)
}

func passiveScan(results []crawlResult) []finding {
	var findings []finding
	seen := make(map[string]bool)

	add := func(f finding) {
		key := f.vuln + "|" + f.target + "|" + f.param
		if !seen[key] {
			seen[key] = true
			findings = append(findings, f)
		}
	}

	// track per-host header checks so we report each missing header once per host
	hostHeaders := make(map[string]bool)

	for _, r := range results {
		parsed, _ := url.Parse(r.rawURL)
		host := parsed.Host

		// Insecure cookies
		for _, c := range r.cookies {
			if !c.HttpOnly {
				add(finding{"Cookie Missing HttpOnly", "MEDIUM", r.rawURL, c.Name, "Cookie readable via JavaScript — XSS escalation risk"})
			}
			if !c.Secure && parsed.Scheme == "https" {
				add(finding{"Cookie Missing Secure Flag", "MEDIUM", r.rawURL, c.Name, "Cookie transmitted over plain HTTP"})
			}
			if c.SameSite == 0 { // 0 = unset (not SameSiteDefaultMode which is 1)
				add(finding{"Cookie Missing SameSite", "LOW", r.rawURL, c.Name, "No SameSite attribute — CSRF risk"})
			}
		}

		// Info disclosure headers
		for _, hdr := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"} {
			if val := r.headers.Get(hdr); val != "" {
				add(finding{"Information Disclosure — " + hdr, "LOW", host, hdr, val})
			}
		}

		// CORS wildcard
		if acao := r.headers.Get("Access-Control-Allow-Origin"); acao == "*" {
			add(finding{"CORS Wildcard", "HIGH", r.rawURL, "Access-Control-Allow-Origin", "Any origin can read cross-domain responses"})
		}

		// Verbose errors
		for _, re := range verboseErrorPatterns {
			if re.MatchString(r.body) {
				add(finding{"Verbose Error Disclosure", "MEDIUM", r.rawURL, "response body", "Stack trace or framework error leaked"})
				break
			}
		}

		// Missing security headers — once per host
		critHeaders := map[string]string{
			"Content-Security-Policy":   "HIGH",
			"Strict-Transport-Security": "MEDIUM",
			"X-Frame-Options":           "MEDIUM",
			"X-Content-Type-Options":    "LOW",
		}
		for h, sev := range critHeaders {
			hostKey := host + "|" + h
			if !hostHeaders[hostKey] && r.headers.Get(h) == "" {
				hostHeaders[hostKey] = true
				add(finding{"Missing Security Header — " + h, sev, host, h, "Header absent from HTTP response"})
			}
		}

		// Mixed content
		if parsed.Scheme == "https" {
			mixedRe := regexp.MustCompile(`(?i)(src|href|action)\s*=\s*["']http://`)
			if mixedRe.MatchString(r.body) {
				add(finding{"Mixed Content", "MEDIUM", r.rawURL, "page resources", "HTTP resources loaded on HTTPS page"})
			}
		}
	}

	return findings
}

// ─── Active scanner ───────────────────────────────────────────────────────────

const xssMarker = "davoid_xss_7x9z"

type scanPayload struct {
	name   string
	value  string
	detect func(body, location string) bool
	vuln   string
	sev    string
}

var activeScanPayloads = []scanPayload{
	// SQLi — error-based
	{
		name:  "SQLi-quote",
		value: "'",
		detect: func(body, _ string) bool {
			for _, re := range sqlErrorPatterns {
				if re.MatchString(body) {
					return true
				}
			}
			return false
		},
		vuln: "SQL Injection",
		sev:  "CRITICAL",
	},
	{
		name:  "SQLi-or",
		value: "' OR '1'='1",
		detect: func(body, _ string) bool {
			for _, re := range sqlErrorPatterns {
				if re.MatchString(body) {
					return true
				}
			}
			return false
		},
		vuln: "SQL Injection",
		sev:  "CRITICAL",
	},
	// XSS — reflection
	{
		name:  "XSS-script",
		value: "<script>" + xssMarker + "</script>",
		detect: func(body, _ string) bool {
			return strings.Contains(body, "<script>"+xssMarker+"</script>")
		},
		vuln: "XSS — Reflected",
		sev:  "HIGH",
	},
	{
		name:  "XSS-attr",
		value: `"><img src=x onerror="` + xssMarker + `">`,
		detect: func(body, _ string) bool {
			return strings.Contains(body, xssMarker)
		},
		vuln: "XSS — Reflected",
		sev:  "HIGH",
	},
	// Path traversal
	{
		name:  "PathTraversal-unix",
		value: "../../../../etc/passwd",
		detect: func(body, _ string) bool {
			return strings.Contains(body, "root:x:0:0")
		},
		vuln: "Path Traversal",
		sev:  "HIGH",
	},
	{
		name:  "PathTraversal-encoded",
		value: "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
		detect: func(body, _ string) bool {
			return strings.Contains(body, "root:x:0:0")
		},
		vuln: "Path Traversal",
		sev:  "HIGH",
	},
	// Open redirect — unique domain to avoid FPs
	{
		name:  "OpenRedirect",
		value: "//davoid-redirect-test.invalid/",
		detect: func(_, location string) bool {
			return strings.Contains(location, "davoid-redirect-test.invalid")
		},
		vuln: "Open Redirect",
		sev:  "MEDIUM",
	},
	// Command injection
	{
		name:  "CmdInjection-echo",
		value: "; echo davoid_cmd_9z7x",
		detect: func(body, _ string) bool {
			return strings.Contains(body, "davoid_cmd_9z7x")
		},
		vuln: "Command Injection",
		sev:  "CRITICAL",
	},
	{
		name:  "CmdInjection-pipe",
		value: "| echo davoid_cmd_9z7x",
		detect: func(body, _ string) bool {
			return strings.Contains(body, "davoid_cmd_9z7x")
		},
		vuln: "Command Injection",
		sev:  "CRITICAL",
	},
	// SSTI — uses 1337*1337=1787569 (unlikely natural occurrence)
	{
		name:  "SSTI-jinja",
		value: "{{1337*1337}}",
		detect: func(body, _ string) bool {
			return strings.Contains(body, "1787569")
		},
		vuln: "SSTI — Template Injection",
		sev:  "HIGH",
	},
	{
		name:  "SSTI-freemarker",
		value: "${1337*1337}",
		detect: func(body, _ string) bool {
			return strings.Contains(body, "1787569")
		},
		vuln: "SSTI — Template Injection",
		sev:  "HIGH",
	},
}

func runActiveOnly(baseURL string, eng *engagement.Engagement) {
	ui.Divider()
	ui.Info("Spidering for attack surface...")
	ui.Divider()
	results := spider(baseURL, 2, 50)
	printSpiderSummary(results)

	fmt.Println()
	ui.Divider()
	ui.Info("Active Scanning...")
	ui.Divider()
	findings := activeScan(results)
	printFindings(findings, eng)
}

func activeScan(results []crawlResult) []finding {
	var findings []finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	seen := make(map[string]bool)
	var seenMu sync.Mutex

	addFinding := func(f finding) {
		key := f.vuln + "|" + f.target + "|" + f.param
		seenMu.Lock()
		dup := seen[key]
		if !dup {
			seen[key] = true
		}
		seenMu.Unlock()
		if !dup {
			mu.Lock()
			findings = append(findings, f)
			mu.Unlock()
			fmt.Printf("  %s  %-35s  %s  %s\n",
				ui.Red.Render("VULN"),
				f.vuln,
				ui.Yellow.Render("["+f.sev+"]"),
				ui.Dim.Render(f.detail),
			)
		}
	}

	// Test GET query parameters
	for _, r := range results {
		if len(r.params) == 0 {
			continue
		}
		parsed, err := url.Parse(r.rawURL)
		if err != nil {
			continue
		}
		origQ := parsed.Query()

		for _, param := range r.params {
			wg.Add(1)
			go func(targetURL string, origQ url.Values, param string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				for _, pl := range activeScanPayloads {
					q := cloneValues(origQ)
					q.Set(param, pl.value)
					u2, _ := url.Parse(targetURL)
					u2.RawQuery = q.Encode()

					resp, err := httpClient.Get(u2.String())
					if err != nil {
						continue
					}
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					loc := resp.Header.Get("Location")

					if pl.detect(string(body), loc) {
						addFinding(finding{
							vuln:   pl.vuln,
							sev:    pl.sev,
							target: targetURL,
							param:  param,
							detail: fmt.Sprintf("param=%s payload=%s", param, pl.name),
						})
						break
					}
				}
			}(r.rawURL, origQ, param)
		}
	}

	// Test form fields
	for _, r := range results {
		for _, form := range r.forms {
			if len(form.fields) == 0 {
				continue
			}
			for _, field := range form.fields {
				wg.Add(1)
				go func(form formData, field formField) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					for _, pl := range activeScanPayloads {
						body, loc := submitForm(form, field.name, pl.value)
						if pl.detect(body, loc) {
							addFinding(finding{
								vuln:   pl.vuln,
								sev:    pl.sev,
								target: form.action,
								param:  field.name + " (form)",
								detail: fmt.Sprintf("form=%s field=%s payload=%s", shortPath(form.action), field.name, pl.name),
							})
							break
						}
					}
				}(form, field)
			}
		}
	}

	wg.Wait()
	return findings
}

func submitForm(form formData, injectField, injectValue string) (body, location string) {
	vals := url.Values{}
	for _, f := range form.fields {
		if f.name == injectField {
			vals.Set(f.name, injectValue)
		} else {
			vals.Set(f.name, f.value)
		}
	}

	var resp *http.Response
	var err error
	if form.method == "POST" {
		resp, err = httpClient.PostForm(form.action, vals)
	} else {
		target, _ := url.Parse(form.action)
		target.RawQuery = vals.Encode()
		resp, err = httpClient.Get(target.String())
	}
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.Header.Get("Location")
}

// ─── Full scan ────────────────────────────────────────────────────────────────

func runFull(baseURL string, eng *engagement.Engagement) {
	ui.Divider()
	ui.Info("Phase 1/3 — Spider")
	ui.Divider()
	results := spider(baseURL, 3, 100)
	printSpiderSummary(results)

	fmt.Println()
	ui.Divider()
	ui.Info("Phase 2/3 — Passive Analysis")
	ui.Divider()
	passiveFindings := passiveScan(results)
	printFindings(passiveFindings, eng)

	fmt.Println()
	ui.Divider()
	ui.Info("Phase 3/3 — Active Scanning")
	ui.Divider()

	hasAttackSurface := false
	for _, r := range results {
		if len(r.params) > 0 || len(r.forms) > 0 {
			hasAttackSurface = true
			break
		}
	}
	if !hasAttackSurface {
		ui.Warn("No injectable params or forms found — skipping active scan.")
		ui.Success(fmt.Sprintf("Scan complete. %d passive findings.", len(passiveFindings)))
		return
	}

	activeFindings := activeScan(results)
	if len(activeFindings) == 0 {
		ui.Info("No active vulnerabilities detected.")
	}

	total := len(passiveFindings) + len(activeFindings)
	fmt.Println()
	ui.Success(fmt.Sprintf("Scan complete. %d passive  %d active  (%d total findings).",
		len(passiveFindings), len(activeFindings), total))
}

// ─── Output ───────────────────────────────────────────────────────────────────

func printFindings(findings []finding, eng *engagement.Engagement) {
	if len(findings) == 0 {
		ui.Info("No findings.")
		return
	}
	for _, f := range findings {
		var sev = ui.Red
		switch f.sev {
		case "HIGH":
			sev = ui.Yellow
		case "MEDIUM":
			sev = ui.Cyan
		case "LOW":
			sev = ui.Dim
		}
		fmt.Printf("  %s  %-40s  %s\n",
			sev.Render("["+f.sev+"]"),
			f.vuln,
			ui.Dim.Render(shortPath(f.target)),
		)
		if f.param != "" {
			fmt.Printf("         %s\n", ui.Dim.Render("param: "+f.param))
		}
		if eng != nil {
			engagement.LogFinding(eng.ID, "webscan", f.target,
				f.vuln, f.detail, f.sev, f.param)
		}
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func resolveURL(base *url.URL, href string) string {
	if href == "" {
		return ""
	}
	lower := strings.ToLower(href)
	if strings.HasPrefix(lower, "#") ||
		strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	resolved.Fragment = ""
	if resolved.Host != base.Host {
		return ""
	}
	return resolved.String()
}

func normalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Fragment = ""
	return u.String()
}

func cloneValues(v url.Values) url.Values {
	clone := make(url.Values, len(v))
	for k, vals := range v {
		clone[k] = append([]string{}, vals...)
	}
	return clone
}

func shortPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		if len(rawURL) > 50 {
			return rawURL[:47] + "..."
		}
		return rawURL
	}
	s := u.Path
	if u.RawQuery != "" {
		s += "?" + u.RawQuery
	}
	if s == "" {
		s = "/"
	}
	if len(s) > 50 {
		return s[:47] + "..."
	}
	return s
}

func truncatePath(rawURL string, max int) string {
	if len(rawURL) <= max {
		return rawURL
	}
	return rawURL[:max-3] + "..."
}

func statusBadge(code int) string {
	s := fmt.Sprintf("%d", code)
	if code >= 200 && code < 300 {
		return ui.Green.Render(s)
	}
	if code >= 300 && code < 400 {
		return ui.Cyan.Render(s)
	}
	return ui.Red.Render(s)
}
