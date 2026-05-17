package osint

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

var client = &http.Client{Timeout: 10 * time.Second}

func Run() error {
	ui.Header("Holmes Engine — Unified OSINT Suite")

	choice := ui.Select("OSINT Mode", []string{
		"Domain Intelligence   (DNS / subdomains / Wayback / CVE)",
		"Username Tracker      (14 platforms)",
		"IP Intelligence       (geo-IP / open ports / ASN)",
		"Email Harvester       (pattern generation + verification hints)",
	})

	switch choice {
	case 0:
		return domainIntel()
	case 1:
		return usernameTrack()
	case 2:
		return ipIntel()
	case 3:
		return emailHarvest()
	}
	return nil
}

// ── Domain Intelligence ──────────────────────────────────────────────────────

func domainIntel() error {
	domain := ui.Prompt("Target domain (e.g. example.com)")
	if domain == "" {
		return nil
	}
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")
	domain = strings.Split(domain, "/")[0]

	eng, _ := engagement.Active()

	fmt.Println()
	ui.Divider()
	ui.Info("DNS Records")
	ui.Divider()

	recordTypes := []string{"A", "AAAA", "MX", "NS", "TXT", "CNAME"}
	for _, rt := range recordTypes {
		recs, err := net.LookupHost(domain)
		switch rt {
		case "A":
			addrs, _ := net.LookupHost(domain)
			if len(addrs) > 0 {
				fmt.Printf("  %s  %s\n", ui.Cyan.Render(fmt.Sprintf("%-6s", rt)), strings.Join(addrs, ", "))
			}
		case "MX":
			mxs, _ := net.LookupMX(domain)
			for _, mx := range mxs {
				fmt.Printf("  %s  %s (pref %d)\n", ui.Cyan.Render(fmt.Sprintf("%-6s", rt)), mx.Host, mx.Pref)
			}
		case "NS":
			nss, _ := net.LookupNS(domain)
			for _, ns := range nss {
				fmt.Printf("  %s  %s\n", ui.Cyan.Render(fmt.Sprintf("%-6s", rt)), ns.Host)
			}
		case "TXT":
			txts, _ := net.LookupTXT(domain)
			for _, t := range txts {
				fmt.Printf("  %s  %s\n", ui.Cyan.Render(fmt.Sprintf("%-6s", rt)), t)
			}
		default:
			_ = recs
			_ = err
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
	url := "https://internetdb.shodan.io/" + ip
	resp, err := client.Get(url)
	if err != nil {
		ui.Warn("InternetDB unavailable.")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var data struct {
		IP       string   `json:"ip"`
		Ports    []int    `json:"ports"`
		Cpes     []string `json:"cpes"`
		Hostnames []string `json:"hostnames"`
		Vulns    []string `json:"vulns"`
		Tags     []string `json:"tags"`
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
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&limit=20&fl=original&filter=statuscode:200&collapse=urlkey", domain)
	resp, err := client.Get(url)
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

// ── Username Tracker ─────────────────────────────────────────────────────────

func usernameTrack() error {
	username := ui.Prompt("Username to investigate")
	if username == "" {
		return nil
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

// ── IP Intelligence ──────────────────────────────────────────────────────────

func ipIntel() error {
	target := ui.Prompt("IP address")
	if target == "" {
		return nil
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
		Status     string `json:"status"`
		Country    string `json:"country"`
		Region     string `json:"regionName"`
		City       string `json:"city"`
		ISP        string `json:"isp"`
		Org        string `json:"org"`
		AS         string `json:"as"`
		Query      string `json:"query"`
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

// ── Email Harvester ──────────────────────────────────────────────────────────

func emailHarvest() error {
	domain := ui.Prompt("Target domain (e.g. example.com)")
	firstName := ui.Prompt("First name (optional, for pattern gen)")
	lastName := ui.Prompt("Last name (optional)")

	fmt.Println()
	ui.Divider()
	ui.Info("Common email patterns for " + domain)
	ui.Divider()

	patterns := []string{}
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
		// MX check heuristic
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

// ── Helpers ──────────────────────────────────────────────────────────────────

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
