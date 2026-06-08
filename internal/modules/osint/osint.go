package osint

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

var client = &http.Client{Timeout: 15 * time.Second}

// noRedirectClient follows zero redirects so we can capture the chain manually.
var noRedirectClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// ── Entry point ───────────────────────────────────────────────────────────────

func Run() error {
	ui.Header("Holmes Engine — Unified OSINT Suite")

	fmt.Println()
	ui.Info("Paste target — URL, domain, IP, or @username. Auto-detected.")
	fmt.Println()

	target := ui.Prompt("Target")
	if target == "" {
		return nil
	}

	return autoRoute(target)
}

func autoRoute(target string) error {
	t := strings.TrimSpace(target)

	// URL: has scheme or contains a path separator after a dot
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		return urlIntel(t)
	}
	// Looks like URL without scheme: contains a dot AND a slash, or a dot AND common TLD + path
	if looksLikeURL(t) {
		return urlIntel("https://" + t)
	}
	// Username
	if strings.HasPrefix(t, "@") {
		return usernameTrack(strings.TrimPrefix(t, "@"))
	}
	// IP address
	if net.ParseIP(t) != nil {
		return ipIntel(t)
	}
	// Email → email harvester on domain
	if strings.Contains(t, "@") {
		parts := strings.SplitN(t, "@", 2)
		if len(parts) == 2 {
			return emailHarvest(parts[1], "", "")
		}
	}
	// Default: domain
	return domainIntel(t)
}

func looksLikeURL(t string) bool {
	// has a path component (slash after domain) or clear URL structure
	if strings.Contains(t, "/") {
		return true
	}
	// has query params or fragment
	if strings.Contains(t, "?") || strings.Contains(t, "#") {
		return true
	}
	return false
}

// ── URL Intelligence ──────────────────────────────────────────────────────────

type tracker struct {
	name    string
	pattern string
}

var knownTrackers = []tracker{
	{"Google Analytics GA4", "gtag("},
	{"Google Analytics UA", "ga('create'"},
	{"Google Tag Manager", "GTM-"},
	{"Google Tag Manager", "googletagmanager.com"},
	{"Facebook Pixel", "fbq("},
	{"Facebook SDK", "connect.facebook.net"},
	{"HotJar", "hotjar"},
	{"Mixpanel", "mixpanel"},
	{"Segment", "segment.com"},
	{"Intercom", "intercom"},
	{"Drift", "drift.com"},
	{"Heap Analytics", "cdn.heapanalytics.com"},
	{"Amplitude", "amplitude.com/libs"},
	{"Twitter/X Pixel", "static.ads-twitter.com"},
	{"LinkedIn Insight Tag", "snap.licdn.com"},
	{"Microsoft Clarity", "clarity.ms"},
	{"Yandex Metrika", "mc.yandex.ru"},
	{"Cloudflare Insights", "cloudflareinsights.com"},
	{"Sentry", "browser.sentry-cdn.com"},
	{"Crisp Chat", "crisp.chat"},
	{"TikTok Pixel", "analytics.tiktok.com"},
	{"Pinterest Tag", "pintrk("},
	{"HubSpot", "js.hs-scripts.com"},
	{"Quantcast", "quantserve.com"},
	{"DoubleClick", "doubleclick.net"},
	{"Adobe Analytics", "omtrdc.net"},
	{"FullStory", "fullstory.com"},
	{"Lucky Orange", "luckyorange.com"},
	{"Crazy Egg", "script.crazyegg.com"},
	{"VWO", "vwo.com"},
	{"Optimizely", "optimizely.com"},
	{"Mouseflow", "mouseflow.com"},
	{"Pendo", "pendo.io"},
	{"Datadog RUM", "browser.datadoghq.com"},
	{"New Relic", "js-agent.newrelic.com"},
}

var securityHeaders = []struct {
	name  string
	key   string
	good  string
}{
	{"Content-Security-Policy", "Content-Security-Policy", ""},
	{"Strict-Transport-Security", "Strict-Transport-Security", ""},
	{"X-Frame-Options", "X-Frame-Options", ""},
	{"X-Content-Type-Options", "X-Content-Type-Options", "nosniff"},
	{"Referrer-Policy", "Referrer-Policy", ""},
	{"Permissions-Policy", "Permissions-Policy", ""},
	{"X-XSS-Protection", "X-XSS-Protection", ""},
	{"Cross-Origin-Embedder-Policy", "Cross-Origin-Embedder-Policy", ""},
	{"Cross-Origin-Opener-Policy", "Cross-Origin-Opener-Policy", ""},
}

var techHeaders = []string{
	"Server", "X-Powered-By", "X-Generator", "X-Drupal-Cache",
	"X-WordPress-User", "X-AspNet-Version", "X-AspNetMvc-Version",
	"X-Magento-Cache-Control", "Via", "X-Varnish", "X-Cache",
}

func urlIntel(rawURL string) error {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "https://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		ui.Fail("Invalid URL: " + err.Error())
		return nil
	}
	host := parsed.Hostname()

	eng, _ := engagement.Active()

	// ── Redirect Chain ────────────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Redirect Chain")
	ui.Divider()

	chain, finalURL, finalResp := followRedirects(rawURL)
	for i, hop := range chain {
		arrow := "  →"
		if i == 0 {
			arrow = "  ⊙"
		}
		fmt.Printf("%s  [%d] %s\n", ui.Cyan.Render(arrow), hop.code, ui.Bold.Render(hop.url))
	}
	if finalResp != nil {
		defer finalResp.Body.Close()
	}

	// Update host if redirected
	if finalURL != "" {
		if p, err2 := url.Parse(finalURL); err2 == nil {
			host = p.Hostname()
		}
	}

	// ── HTTP Headers ──────────────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Technology Fingerprint (HTTP Headers)")
	ui.Divider()

	if finalResp != nil {
		found := false
		for _, h := range techHeaders {
			if v := finalResp.Header.Get(h); v != "" {
				fmt.Printf("  %s  %s: %s\n", ui.Cyan.Render("•"), ui.Bold.Render(h), v)
				found = true
			}
		}
		if !found {
			ui.Dim.Render("  No technology headers disclosed.")
			fmt.Println(ui.Dim.Render("  No technology headers disclosed."))
		}
	}

	// ── Security Headers Audit ────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Security Headers Audit")
	ui.Divider()

	if finalResp != nil {
		for _, sh := range securityHeaders {
			val := finalResp.Header.Get(sh.key)
			if val == "" {
				fmt.Printf("  %s  %-35s  %s\n", ui.Red.Render("✗"), sh.name, ui.Dim.Render("MISSING"))
			} else {
				short := val
				if len(short) > 50 {
					short = short[:50] + "…"
				}
				fmt.Printf("  %s  %-35s  %s\n", ui.Green.Render("✓"), sh.name, ui.Dim.Render(short))
			}
		}
	}

	// ── Cookies ───────────────────────────────────────────────────────────
	if finalResp != nil {
		cookies := finalResp.Cookies()
		if len(cookies) > 0 {
			fmt.Println()
			ui.Divider()
			ui.Info(fmt.Sprintf("Cookies (%d)", len(cookies)))
			ui.Divider()
			for _, c := range cookies {
				flags := []string{}
				if c.HttpOnly {
					flags = append(flags, "HttpOnly")
				}
				if c.Secure {
					flags = append(flags, "Secure")
				}
				if c.SameSite != 0 {
					flags = append(flags, fmt.Sprintf("SameSite=%v", c.SameSite))
				}
				flagStr := ""
				if len(flags) > 0 {
					flagStr = "  [" + strings.Join(flags, " ") + "]"
				} else {
					flagStr = ui.Red.Render("  [no flags — vulnerable to theft]")
				}
				fmt.Printf("  %s  %s%s\n", ui.Cyan.Render("◦"), c.Name, flagStr)
			}
		}
	}

	// ── SSL/TLS Certificate ───────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("SSL/TLS Certificate")
	ui.Divider()
	tlsIntel(host)

	// ── Tracking & Analytics ──────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Tracking & Analytics Scripts")
	ui.Divider()

	if finalResp != nil {
		// Re-fetch body for analysis (finalResp body may be closed)
	}
	trackingFound := scanForTrackers(rawURL)
	if len(trackingFound) == 0 {
		fmt.Println(ui.Dim.Render("  No known trackers detected."))
	}

	// ── DNS & Hosting ─────────────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("DNS & Hosting")
	ui.Divider()
	geoAndASN(host)

	// ── Wayback Machine ───────────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Wayback Machine — historical endpoints")
	ui.Divider()
	wayback(host)

	if eng != nil {
		engagement.LogFinding(eng.ID, "osint", rawURL,
			"URL intelligence completed",
			fmt.Sprintf("Host: %s | Redirects: %d | Trackers: %d", host, len(chain), len(trackingFound)),
			"INFO", "")
	}

	ui.PressEnter()
	return nil
}

type hop struct {
	url  string
	code int
}

func followRedirects(rawURL string) ([]hop, string, *http.Response) {
	var chain []hop
	current := rawURL
	for i := 0; i < 10; i++ {
		req, err := http.NewRequest("GET", current, nil)
		if err != nil {
			break
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; DavoidScanner/2.6)")
		resp, err := noRedirectClient.Do(req)
		if err != nil {
			break
		}
		chain = append(chain, hop{url: current, code: resp.StatusCode})
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			resp.Body.Close()
			if loc == "" {
				break
			}
			// Handle relative redirects
			if !strings.HasPrefix(loc, "http") {
				base, err := url.Parse(current)
				if err != nil {
					break
				}
				rel, err := url.Parse(loc)
				if err != nil {
					break
				}
				loc = base.ResolveReference(rel).String()
			}
			current = loc
		} else {
			return chain, current, resp
		}
	}
	return chain, current, nil
}

func tlsIntel(host string) {
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         host,
	})
	if err != nil {
		// Try with InsecureSkipVerify to still extract cert info
		conn, err = tls.Dial("tcp", host+":443", &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
		if err != nil {
			fmt.Println(ui.Dim.Render("  TLS not available or port 443 closed."))
			return
		}
		ui.Warn("TLS cert verification failed (self-signed or invalid)")
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		fmt.Println(ui.Dim.Render("  No certificates returned."))
		return
	}
	cert := certs[0]
	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
	expiryColor := ui.Green.Render
	if daysLeft < 30 {
		expiryColor = ui.Red.Render
	} else if daysLeft < 90 {
		expiryColor = ui.Yellow.Render
	}

	fmt.Printf("  %s  Subject:  %s\n", ui.Cyan.Render("•"), cert.Subject.CommonName)
	fmt.Printf("  %s  Issuer:   %s\n", ui.Cyan.Render("•"), cert.Issuer.CommonName)
	fmt.Printf("  %s  Valid:    %s → %s (%s)\n",
		ui.Cyan.Render("•"),
		cert.NotBefore.Format("2006-01-02"),
		cert.NotAfter.Format("2006-01-02"),
		expiryColor(fmt.Sprintf("%d days left", daysLeft)),
	)
	if len(cert.DNSNames) > 0 {
		sans := cert.DNSNames
		if len(sans) > 6 {
			sans = append(sans[:6], fmt.Sprintf("…+%d more", len(cert.DNSNames)-6))
		}
		fmt.Printf("  %s  SANs:     %s\n", ui.Cyan.Render("•"), strings.Join(sans, ", "))
	}
	fmt.Printf("  %s  Protocol: %s\n", ui.Cyan.Render("•"), tlsVersionName(conn.ConnectionState().Version))
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return ui.Red.Render("TLS 1.0 (insecure)")
	case tls.VersionTLS11:
		return ui.Yellow.Render("TLS 1.1 (deprecated)")
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return ui.Green.Render("TLS 1.3")
	default:
		return "Unknown"
	}
}

func scanForTrackers(rawURL string) []string {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; DavoidScanner/2.6)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512KB max
	if err != nil {
		return nil
	}
	bodyStr := strings.ToLower(string(body))

	seen := map[string]bool{}
	var found []string
	for _, t := range knownTrackers {
		if seen[t.name] {
			continue
		}
		if strings.Contains(bodyStr, strings.ToLower(t.pattern)) {
			seen[t.name] = true
			found = append(found, t.name)
			fmt.Printf("  %s  %s\n", ui.Yellow.Render("⚡"), t.name)
		}
	}

	// Also extract GA measurement IDs and GTM container IDs
	gaRe := regexp.MustCompile(`G-[A-Z0-9]{8,}`)
	gtmRe := regexp.MustCompile(`GTM-[A-Z0-9]{4,}`)
	uaRe := regexp.MustCompile(`UA-\d{4,}-\d+`)

	for _, m := range gaRe.FindAllString(string(body), -1) {
		fmt.Printf("  %s  GA4 Measurement ID: %s\n", ui.Dim.Render("  ↳"), m)
	}
	for _, m := range gtmRe.FindAllString(string(body), -1) {
		fmt.Printf("  %s  GTM Container: %s\n", ui.Dim.Render("  ↳"), m)
	}
	for _, m := range uaRe.FindAllString(string(body), -1) {
		fmt.Printf("  %s  UA Property: %s\n", ui.Dim.Render("  ↳"), m)
	}

	return found
}

func geoAndASN(host string) {
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		ui.Warn("Could not resolve host.")
		return
	}
	ip := addrs[0]
	fmt.Printf("  %s  A record: %s\n", ui.Cyan.Render("•"), strings.Join(addrs, ", "))

	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,regionName,city,isp,org,as", ip))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var geo struct {
		Status  string `json:"status"`
		Country string `json:"country"`
		Region  string `json:"regionName"`
		City    string `json:"city"`
		ISP     string `json:"isp"`
		Org     string `json:"org"`
		AS      string `json:"as"`
	}
	if json.Unmarshal(body, &geo) == nil && geo.Status == "success" {
		fmt.Printf("  %s  Location: %s, %s, %s\n", ui.Cyan.Render("•"), geo.City, geo.Region, geo.Country)
		fmt.Printf("  %s  ISP:      %s\n", ui.Cyan.Render("•"), geo.ISP)
		fmt.Printf("  %s  Org:      %s\n", ui.Cyan.Render("•"), geo.Org)
		fmt.Printf("  %s  ASN:      %s\n", ui.Cyan.Render("•"), geo.AS)
	}

	// InternetDB
	resp2, err := client.Get("https://internetdb.shodan.io/" + ip)
	if err == nil {
		defer resp2.Body.Close()
		body2, _ := io.ReadAll(resp2.Body)
		var idb struct {
			Ports []int    `json:"ports"`
			Vulns []string `json:"vulns"`
			Tags  []string `json:"tags"`
		}
		if json.Unmarshal(body2, &idb) == nil {
			if len(idb.Ports) > 0 {
				ports := make([]string, len(idb.Ports))
				for i, p := range idb.Ports {
					ports[i] = fmt.Sprintf("%d", p)
				}
				fmt.Printf("  %s  Open Ports: %s\n", ui.Cyan.Render("•"), strings.Join(ports, ", "))
			}
			for _, v := range idb.Vulns {
				fmt.Printf("  %s  %s\n", ui.Red.Render("CVE"), v)
			}
		}
	}
}

// ── Domain Intelligence ───────────────────────────────────────────────────────

func domainIntel(domain string) error {
	if domain == "" {
		domain = ui.Prompt("Target domain (e.g. example.com)")
		if domain == "" {
			return nil
		}
	}
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")
	domain = strings.Split(domain, "/")[0]

	eng, _ := engagement.Active()

	fmt.Println()
	ui.Divider()
	ui.Info("DNS Records")
	ui.Divider()

	if addrs, _ := net.LookupHost(domain); len(addrs) > 0 {
		fmt.Printf("  %s  %s\n", ui.Cyan.Render("A     "), strings.Join(addrs, ", "))
	}
	if mxs, _ := net.LookupMX(domain); len(mxs) > 0 {
		for _, mx := range mxs {
			fmt.Printf("  %s  %s (pref %d)\n", ui.Cyan.Render("MX    "), mx.Host, mx.Pref)
		}
	}
	if nss, _ := net.LookupNS(domain); len(nss) > 0 {
		for _, ns := range nss {
			fmt.Printf("  %s  %s\n", ui.Cyan.Render("NS    "), ns.Host)
		}
	}
	if txts, _ := net.LookupTXT(domain); len(txts) > 0 {
		for _, t := range txts {
			fmt.Printf("  %s  %s\n", ui.Cyan.Render("TXT   "), t)
		}
	}

	fmt.Println()
	ui.Divider()
	ui.Info("Subdomain Brute-Force (70 common names)")
	ui.Divider()

	subs := commonSubdomains()
	found := make(chan string, 10)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, sub := range subs {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fqdn := s + "." + domain
			addrs, err := net.LookupHost(fqdn)
			if err == nil && len(addrs) > 0 {
				found <- fmt.Sprintf("  %s  %s  → %s", ui.Green.Render("FOUND"), fqdn, strings.Join(addrs, ", "))
			}
		}(sub)
	}

	go func() {
		wg.Wait()
		close(found)
	}()

	subCount := 0
	for line := range found {
		fmt.Println(line)
		subCount++
	}
	if subCount == 0 {
		ui.Warn("No subdomains discovered.")
	}

	fmt.Println()
	ui.Divider()
	ui.Info("InternetDB / Shodan-lite (open ports + CVEs)")
	ui.Divider()
	queryInternetDB(domain, eng)

	fmt.Println()
	ui.Divider()
	ui.Info("Wayback Machine — interesting endpoints")
	ui.Divider()
	wayback(domain)

	if eng != nil {
		engagement.LogFinding(eng.ID, "osint", domain,
			"OSINT domain intelligence completed",
			fmt.Sprintf("DNS enum + %d subdomains + InternetDB + Wayback", subCount),
			"INFO", "")
	}

	ui.PressEnter()
	return nil
}

func queryInternetDB(domain string, eng *engagement.Engagement) {
	addrs, err := net.LookupHost(domain)
	if err != nil || len(addrs) == 0 {
		ui.Warn("Could not resolve domain to IP.")
		return
	}
	ip := addrs[0]
	targetURL := "https://internetdb.shodan.io/" + ip
	resp, err := client.Get(targetURL)
	if err != nil {
		ui.Warn("InternetDB unavailable.")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var data struct {
		IP        string   `json:"ip"`
		Ports     []int    `json:"ports"`
		Cpes      []string `json:"cpes"`
		Hostnames []string `json:"hostnames"`
		Vulns     []string `json:"vulns"`
		Tags      []string `json:"tags"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		ui.Warn("No InternetDB data.")
		return
	}

	fmt.Printf("  IP: %s\n", ui.Bold.Render(data.IP))
	if len(data.Ports) > 0 {
		ports := make([]string, len(data.Ports))
		for i, p := range data.Ports {
			ports[i] = fmt.Sprintf("%d", p)
		}
		fmt.Printf("  Ports: %s\n", strings.Join(ports, ", "))
	}
	if len(data.Tags) > 0 {
		fmt.Printf("  Tags: %s\n", strings.Join(data.Tags, ", "))
	}
	for _, vuln := range data.Vulns {
		fmt.Printf("  %s  %s\n", ui.Red.Render("CVE"), vuln)
		if eng != nil {
			engagement.LogFinding(eng.ID, "osint", ip,
				"Known vulnerability: "+vuln,
				"Discovered via InternetDB", "HIGH", vuln)
		}
	}
}

func wayback(domain string) {
	targetURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&limit=20&fl=original&filter=statuscode:200&collapse=urlkey", domain)
	resp, err := client.Get(targetURL)
	if err != nil {
		ui.Warn("Wayback Machine unreachable.")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var results [][]string
	if err := json.Unmarshal(body, &results); err != nil || len(results) < 2 {
		ui.Info("No Wayback results.")
		return
	}

	interesting := []string{".sql", ".bak", ".env", ".config", "admin", "api", "backup", "login", "secret", "key", "token", ".git"}
	count := 0
	for _, row := range results[1:] {
		if len(row) == 0 {
			continue
		}
		u := row[0]
		for _, kw := range interesting {
			if strings.Contains(strings.ToLower(u), kw) {
				fmt.Printf("  %s  %s\n", ui.Yellow.Render("!"), u)
				count++
				break
			}
		}
	}
	if count == 0 {
		ui.Info(fmt.Sprintf("Found %d archived URLs, no interesting endpoints.", len(results)-1))
	}
}

// ── Username Tracker ──────────────────────────────────────────────────────────

func usernameTrack(username string) error {
	if username == "" {
		username = ui.Prompt("Username to investigate")
		if username == "" {
			return nil
		}
	}

	platforms := []struct {
		name string
		url  string
	}{
		{"GitHub", "https://github.com/%s"},
		{"Twitter/X", "https://twitter.com/%s"},
		{"Instagram", "https://www.instagram.com/%s/"},
		{"Reddit", "https://www.reddit.com/user/%s"},
		{"TikTok", "https://www.tiktok.com/@%s"},
		{"YouTube", "https://www.youtube.com/@%s"},
		{"LinkedIn", "https://www.linkedin.com/in/%s"},
		{"Pinterest", "https://www.pinterest.com/%s/"},
		{"Twitch", "https://www.twitch.tv/%s"},
		{"Steam", "https://steamcommunity.com/id/%s"},
		{"HackerNews", "https://news.ycombinator.com/user?id=%s"},
		{"GitLab", "https://gitlab.com/%s"},
		{"Keybase", "https://keybase.io/%s"},
		{"Dev.to", "https://dev.to/%s"},
	}

	fmt.Println()
	ui.Info(fmt.Sprintf("Probing %d platforms for '%s'...", len(platforms), username))
	fmt.Println()

	type result struct {
		name  string
		url   string
		found bool
	}

	results := make(chan result, len(platforms))
	var wg sync.WaitGroup

	for _, p := range platforms {
		wg.Add(1)
		go func(name, urlFmt string) {
			defer wg.Done()
			u := fmt.Sprintf(urlFmt, username)
			resp, err := client.Get(u)
			if err != nil {
				results <- result{name: name, url: u, found: false}
				return
			}
			resp.Body.Close()
			found := resp.StatusCode == 200
			results <- result{name: name, url: u, found: found}
		}(p.name, p.url)
	}

	wg.Wait()
	close(results)

	eng, _ := engagement.Active()
	foundCount := 0
	for r := range results {
		if r.found {
			fmt.Printf("  %s  %-15s  %s\n", ui.Green.Render("✓"), r.name, ui.Dim.Render(r.url))
			foundCount++
			if eng != nil {
				engagement.LogFinding(eng.ID, "osint", username,
					fmt.Sprintf("Username '%s' found on %s", username, r.name),
					r.url, "INFO", r.url)
			}
		} else {
			fmt.Printf("  %s  %-15s\n", ui.Dim.Render("✗"), r.name)
		}
	}

	fmt.Println()
	ui.Info(fmt.Sprintf("Found on %d / %d platforms.", foundCount, len(platforms)))
	ui.PressEnter()
	return nil
}

// ── IP Intelligence ───────────────────────────────────────────────────────────

func ipIntel(target string) error {
	if target == "" {
		target = ui.Prompt("IP address")
		if target == "" {
			return nil
		}
	}

	fmt.Println()
	ui.Info("Querying ip-api.com...")

	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,regionName,city,isp,org,as,query", target))
	if err != nil {
		ui.Fail("Geo-IP lookup failed.")
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var geo struct {
		Status string `json:"status"`
		Country string `json:"country"`
		Region  string `json:"regionName"`
		City    string `json:"city"`
		ISP     string `json:"isp"`
		Org     string `json:"org"`
		AS      string `json:"as"`
		Query   string `json:"query"`
	}
	json.Unmarshal(body, &geo)

	if geo.Status == "success" {
		ui.Divider()
		fmt.Printf("  %s  %s\n", ui.Cyan.Render("IP      "), geo.Query)
		fmt.Printf("  %s  %s, %s, %s\n", ui.Cyan.Render("Location"), geo.City, geo.Region, geo.Country)
		fmt.Printf("  %s  %s\n", ui.Cyan.Render("ISP     "), geo.ISP)
		fmt.Printf("  %s  %s\n", ui.Cyan.Render("Org     "), geo.Org)
		fmt.Printf("  %s  %s\n", ui.Cyan.Render("ASN     "), geo.AS)
		ui.Divider()
	}

	ui.Info("InternetDB port/CVE lookup...")
	resp2, err := client.Get("https://internetdb.shodan.io/" + target)
	if err == nil {
		defer resp2.Body.Close()
		body2, _ := io.ReadAll(resp2.Body)
		var idb struct {
			Ports []int    `json:"ports"`
			Vulns []string `json:"vulns"`
			Tags  []string `json:"tags"`
		}
		if json.Unmarshal(body2, &idb) == nil {
			if len(idb.Ports) > 0 {
				ports := make([]string, len(idb.Ports))
				for i, p := range idb.Ports {
					ports[i] = fmt.Sprintf("%d", p)
				}
				fmt.Printf("  %s  %s\n", ui.Cyan.Render("Ports   "), strings.Join(ports, ", "))
			}
			for _, v := range idb.Vulns {
				fmt.Printf("  %s  %s\n", ui.Red.Render("CVE     "), v)
			}
		}
	}

	eng, _ := engagement.Active()
	if eng != nil {
		engagement.LogFinding(eng.ID, "osint", target,
			fmt.Sprintf("IP intelligence: %s (%s, %s)", target, geo.City, geo.Country),
			fmt.Sprintf("ISP: %s | Org: %s | ASN: %s", geo.ISP, geo.Org, geo.AS),
			"INFO", "")
	}

	ui.PressEnter()
	return nil
}

// ── Email Harvester ───────────────────────────────────────────────────────────

func emailHarvest(domain, firstName, lastName string) error {
	if domain == "" {
		domain = ui.Prompt("Target domain (e.g. example.com)")
		firstName = ui.Prompt("First name (optional, for pattern gen)")
		lastName = ui.Prompt("Last name (optional)")
	}

	fmt.Println()
	ui.Divider()
	ui.Info("Common email patterns for " + domain)
	ui.Divider()

	var patterns []string
	if firstName != "" && lastName != "" {
		f := strings.ToLower(firstName)
		l := strings.ToLower(lastName)
		fi := string(f[0])
		li := string(l[0])
		patterns = []string{
			f + "@" + domain,
			l + "@" + domain,
			f + "." + l + "@" + domain,
			fi + l + "@" + domain,
			f + li + "@" + domain,
			fi + "." + l + "@" + domain,
			l + "." + f + "@" + domain,
			f + "_" + l + "@" + domain,
			f + l + "@" + domain,
		}
	} else {
		patterns = []string{
			"info@" + domain,
			"admin@" + domain,
			"contact@" + domain,
			"support@" + domain,
			"security@" + domain,
			"abuse@" + domain,
			"webmaster@" + domain,
			"noc@" + domain,
		}
	}

	for _, e := range patterns {
		parts := strings.Split(e, "@")
		mxs, err := net.LookupMX(parts[1])
		mxStatus := ui.Dim.Render("(no MX)")
		if err == nil && len(mxs) > 0 {
			mxStatus = ui.Green.Render("(MX ok)")
		}
		fmt.Printf("  %s  %s  %s\n", ui.Cyan.Render("~"), e, mxStatus)
	}

	fmt.Println()
	ui.Info("Note: verify deliverability with an SMTP probe tool like hunter.io")
	ui.PressEnter()
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func commonSubdomains() []string {
	return []string{
		"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
		"smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
		"ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx",
		"email", "cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw",
		"admin", "store", "mx1", "cdn", "api", "exchange", "app", "gov",
		"media", "beta", "mail3", "chat", "mobile", "autodiscover", "autoconfig",
		"cpanel", "whm", "webdisk", "pop", "imap", "smtp2", "webmail2",
		"images", "static", "assets", "docs", "help", "status", "dashboard",
		"staging", "qa", "uat", "preprod", "prod",
	}
}
