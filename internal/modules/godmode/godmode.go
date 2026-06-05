package godmode

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
	"github.com/bryanparreira/davoid/internal/targets"
	"github.com/bryanparreira/davoid/internal/vault"
)

var client = &http.Client{Timeout: 60 * time.Second}

func Run() error {
	ui.Header("GOD MODE — Autonomous Full-Campaign Orchestrator")

	ui.Warn("GOD MODE executes a fully autonomous attack chain:")
	fmt.Println("  Phase 1 · Reconnaissance  — Nmap full audit + service fingerprinting")
	fmt.Println("  Phase 2 · Service probes   — HTTP, FTP anon, Redis, SMB, RDP, DB checks")
	fmt.Println("  Phase 3 · AI Analysis      — Ollama maps exploits to discovered services")
	fmt.Println("  Phase 4 · Vuln correlation — Port/service → known CVE/technique mapping")
	fmt.Println("  Phase 5 · Decision tree    — Suggests next Davoid modules to run")
	fmt.Println("  Phase 6 · Report           — Full Markdown campaign report")
	fmt.Println()
	ui.Warn("For authorized penetration testing only.")
	fmt.Println()

	if !ui.Confirm("Launch GOD MODE campaign?") {
		return nil
	}

	target := ui.Prompt("Primary target (IP / CIDR / hostname)")
	if target == "" {
		return nil
	}

	ollamaURL := ui.PromptDefault("Ollama URL (for AI analysis, press Enter to skip)", "http://localhost:11434")
	model := ui.PromptDefault("AI model", "llama3")

	eng, _ := engagement.Active()
	if eng == nil {
		ui.Warn("No active engagement — findings will not be saved. Create one with 'davoid new <name>'.")
	}

	// ── Phase 1: Nmap Recon ──────────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info(fmt.Sprintf("Phase 1/6 · Reconnaissance → %s", target))
	ui.Divider()

	scanOutput := runNmap(target)
	if scanOutput == "" {
		ui.Fail("Nmap failed or not installed. Install: sudo apt install nmap")
		return nil
	}
	fmt.Println(ui.Dim.Render(truncate(scanOutput, 2000)))

	openPorts := extractPorts(scanOutput)
	serviceMap := extractServices(scanOutput)
	ui.Success(fmt.Sprintf("Phase 1 complete — %d open port(s): %s", len(openPorts), strings.Join(openPorts, ", ")))

	if eng != nil {
		engagement.LogFinding(eng.ID, "god_mode", target,
			fmt.Sprintf("Recon: %d open ports discovered", len(openPorts)),
			scanOutput, "INFO", strings.Join(openPorts, ","))

		// Auto-save discovered host to targets
		targets.Save(eng.ID, target, "", detectOS(scanOutput), openPorts)
	}

	// ── Phase 2: Service-Specific Probes ────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Phase 2/6 · Service Probes — testing discovered services")
	ui.Divider()

	probeResults := runServiceProbes(target, openPorts, serviceMap, eng)
	for _, r := range probeResults {
		icon := "  ✓"
		if r.critical {
			icon = "  !"
		}
		fmt.Printf("%s  [%s] %s/%s — %s\n",
			ui.Green.Render(icon), r.severity, r.port, r.service, r.detail)
	}
	if len(probeResults) == 0 {
		ui.Info("No services responded to automated probes.")
	}
	ui.Success("Phase 2 complete.")

	// ── Phase 3: AI Analysis ─────────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Phase 3/6 · AI Analysis — Ollama exploit mapping")
	ui.Divider()

	var aiSuggestions string
	if ollamaURL != "" && ollamaURL != "skip" && checkOllama(ollamaURL) {
		context := buildAIContext(target, scanOutput, probeResults)
		prompt := fmt.Sprintf(`You are a senior penetration tester writing a concise attack plan.
Given this scan + probe data for target %s, identify the top attack vectors and suggest
Metasploit modules or manual techniques for each. Include specific CVEs where applicable.
Be concise — one paragraph per finding, max 5 findings.

%s`, target, context)

		aiSuggestions = queryOllama(ollamaURL, model, prompt)
		if aiSuggestions != "" {
			fmt.Println()
			fmt.Println(ui.Green.Render("  AI Analysis:"))
			for _, line := range strings.Split(aiSuggestions, "\n") {
				fmt.Println("  " + line)
			}
			if eng != nil {
				engagement.LogFinding(eng.ID, "god_mode", target,
					"AI Analysis — exploit mapping complete",
					aiSuggestions, "HIGH", "")
			}
		}
	} else {
		ui.Warn("Ollama unavailable or skipped — skipping AI phase.")
		aiSuggestions = "AI analysis not performed."
	}
	ui.Success("Phase 3 complete.")

	// ── Phase 4: Vulnerability Correlation ──────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Phase 4/6 · Vulnerability Correlation — port/service → CVE mapping")
	ui.Divider()

	vulns := correlateVulns(openPorts, serviceMap, target)
	for _, v := range vulns {
		fmt.Printf("  %s  %s/%s  →  %s\n",
			ui.Red.Render(fmt.Sprintf("[%s]", v.severity)),
			ui.Bold.Render(v.port), v.service,
			v.finding,
		)
		if eng != nil {
			engagement.LogFinding(eng.ID, "god_mode", target,
				fmt.Sprintf("Correlated: %s/%s — %s", v.port, v.service, v.finding[:min(len(v.finding), 60)]),
				v.finding, v.severity, v.cve)
		}
	}
	if len(vulns) == 0 {
		ui.Info("No high-confidence vulnerabilities detected via port correlation.")
	}
	ui.Success("Phase 4 complete.")

	// ── Phase 5: Decision Tree — Next Module Suggestions ────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Phase 5/6 · Decision Tree — recommended Davoid modules")
	ui.Divider()

	suggestions := buildDecisionTree(openPorts, serviceMap, probeResults, eng)
	for i, s := range suggestions {
		fmt.Printf("  %d. %s\n     %s\n", i+1, ui.Bold.Render(s.module), ui.Dim.Render(s.reason))
	}
	if len(suggestions) == 0 {
		ui.Info("No specific follow-up modules identified.")
	}
	ui.Success("Phase 5 complete.")

	// ── Phase 6: Report ──────────────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Phase 6/6 · Generating Campaign Report")
	ui.Divider()

	fname := buildReport(target, openPorts, serviceMap, probeResults, aiSuggestions, vulns, suggestions, eng)
	ui.Success(fmt.Sprintf("Report saved: %s", fname))

	fmt.Println()
	ui.Divider()
	ui.Success("GOD MODE campaign complete.")
	if eng != nil {
		ui.Info("View results: Engagement Hub → Findings / Attack Graph")
	}
	ui.PressEnter()
	return nil
}

// ── Types ────────────────────────────────────────────────────────────────────

type vuln struct {
	port     string
	service  string
	finding  string
	severity string
	cve      string
}

type probeResult struct {
	port     string
	service  string
	detail   string
	severity string
	critical bool
}

type suggestion struct {
	module string
	reason string
}

// ── Phase 2: Service probes ──────────────────────────────────────────────────

func runServiceProbes(target string, ports []string, serviceMap map[string]string, eng *engagement.Engagement) []probeResult {
	portSet := map[string]bool{}
	for _, p := range ports {
		portSet[strings.Split(p, "/")[0]] = true
	}

	var results []probeResult

	// HTTP/HTTPS — banner grab + basic info
	for _, portProto := range []struct{ port, scheme string }{
		{"80", "http"}, {"8080", "http"}, {"8443", "https"}, {"443", "https"}, {"8000", "http"}, {"8888", "http"},
	} {
		if !portSet[portProto.port] {
			continue
		}
		url := fmt.Sprintf("%s://%s:%s/", portProto.scheme, target, portProto.port)
		r := probeHTTP(url, portProto.port)
		if r != nil {
			results = append(results, *r)
			if eng != nil {
				engagement.LogFinding(eng.ID, "god_mode", target,
					fmt.Sprintf("HTTP probe: %s port %s", portProto.scheme, portProto.port),
					r.detail, r.severity, "")
			}
		}
	}

	// FTP anonymous login
	if portSet["21"] {
		if r := probeFTPAnon(target); r != nil {
			results = append(results, *r)
			if eng != nil {
				engagement.LogFinding(eng.ID, "god_mode", target,
					"FTP anonymous login enabled", r.detail, r.severity, "")
			}
		}
	}

	// Redis no-auth
	if portSet["6379"] {
		if r := probeRedis(target); r != nil {
			results = append(results, *r)
			if eng != nil {
				engagement.LogFinding(eng.ID, "god_mode", target,
					"Redis unauthenticated access", r.detail, r.severity, "")
			}
		}
	}

	// MongoDB no-auth
	if portSet["27017"] {
		if r := probeMongoDB(target); r != nil {
			results = append(results, *r)
			if eng != nil {
				engagement.LogFinding(eng.ID, "god_mode", target,
					"MongoDB unauthenticated access", r.detail, r.severity, "")
			}
		}
	}

	// Memcached
	if portSet["11211"] {
		if r := probeMemcached(target); r != nil {
			results = append(results, *r)
			if eng != nil {
				engagement.LogFinding(eng.ID, "god_mode", target,
					"Memcached exposed (no auth)", r.detail, r.severity, "")
			}
		}
	}

	// Telnet — cleartext credential risk
	if portSet["23"] {
		results = append(results, probeResult{
			port: "23", service: "telnet",
			detail:   "Telnet is running — credentials transmitted in cleartext",
			severity: "CRITICAL", critical: true,
		})
		if eng != nil {
			engagement.LogFinding(eng.ID, "god_mode", target,
				"Telnet exposed — cleartext credentials", "Port 23/tcp open", "CRITICAL", "")
		}
	}

	// SMTP open relay check
	if portSet["25"] {
		if r := probeSMTPBanner(target); r != nil {
			results = append(results, *r)
		}
	}

	return results
}

func probeHTTP(url, port string) *probeResult {
	hc := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := hc.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	server := resp.Header.Get("Server")
	xPowered := resp.Header.Get("X-Powered-By")
	detail := fmt.Sprintf("HTTP %d — Server: %s", resp.StatusCode, server)
	if xPowered != "" {
		detail += fmt.Sprintf("  X-Powered-By: %s", xPowered)
	}
	sev := "INFO"
	if resp.StatusCode == 200 {
		sev = "MEDIUM"
	}
	return &probeResult{port: port, service: "http", detail: detail, severity: sev, critical: false}
}

func probeFTPAnon(target string) *probeResult {
	conn, err := net.DialTimeout("tcp", target+":21", 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	conn.Read(buf)
	// Try anonymous login
	fmt.Fprintf(conn, "USER anonymous\r\n")
	conn.Read(buf)
	fmt.Fprintf(conn, "PASS anon@test.com\r\n")
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if strings.HasPrefix(resp, "230") || strings.HasPrefix(resp, "331") {
		return &probeResult{
			port: "21", service: "ftp",
			detail:   "FTP anonymous login accepted — unauthenticated read/write may be possible",
			severity: "HIGH", critical: true,
		}
	}
	return nil
}

func probeRedis(target string) *probeResult {
	conn, err := net.DialTimeout("tcp", target+":6379", 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "PING\r\n")
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])
	if strings.Contains(resp, "+PONG") {
		return &probeResult{
			port: "6379", service: "redis",
			detail:   "Redis responds to PING without authentication — full RCE via CONFIG SET possible",
			severity: "CRITICAL", critical: true,
		}
	}
	return nil
}

func probeMongoDB(target string) *probeResult {
	conn, err := net.DialTimeout("tcp", target+":27017", 5*time.Second)
	if err != nil {
		return nil
	}
	conn.Close()
	return &probeResult{
		port: "27017", service: "mongodb",
		detail:   "MongoDB port open — check for no-auth configuration (common in dev environments)",
		severity: "HIGH", critical: true,
	}
}

func probeMemcached(target string) *probeResult {
	conn, err := net.DialTimeout("tcp", target+":11211", 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "stats\r\n")
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if strings.Contains(string(buf[:n]), "STAT") {
		return &probeResult{
			port: "11211", service: "memcached",
			detail:   "Memcached exposed with no authentication — cache poisoning and data theft possible",
			severity: "HIGH", critical: true,
		}
	}
	return nil
}

func probeSMTPBanner(target string) *probeResult {
	conn, err := net.DialTimeout("tcp", target+":25", 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	banner := string(buf[:n])
	if banner != "" {
		return &probeResult{
			port: "25", service: "smtp",
			detail:   fmt.Sprintf("SMTP banner: %s — check for open relay", strings.TrimSpace(banner[:min(len(banner), 80)])),
			severity: "MEDIUM", critical: false,
		}
	}
	return nil
}

// ── Phase 4: Vulnerability Correlation ──────────────────────────────────────

func correlateVulns(ports []string, serviceMap map[string]string, _ string) []vuln {
	type vulnDef struct {
		service  string
		finding  string
		severity string
		cve      string
	}
	portMap := map[string]vulnDef{
		"21":    {"FTP", "FTP cleartext auth; check for anonymous login and credential sniffing", "HIGH", "CVE-1999-0497"},
		"22":    {"SSH", "SSH exposed; attempt credential brute force or key-based auth bypass", "MEDIUM", ""},
		"23":    {"Telnet", "Telnet transmits all data including credentials in cleartext", "CRITICAL", ""},
		"25":    {"SMTP", "SMTP relay may be open — phishing pivot or spam vector", "MEDIUM", ""},
		"53":    {"DNS", "DNS exposed; attempt zone transfer (AXFR) for subdomain enumeration", "MEDIUM", ""},
		"80":    {"HTTP", "Unencrypted HTTP; check for SQLi, XSS, LFI, directory traversal", "MEDIUM", ""},
		"110":   {"POP3", "POP3 cleartext email retrieval; credential sniffing possible on MITM", "MEDIUM", ""},
		"111":   {"RPC", "RPC portmapper exposed; enumerate NFS shares and RPC services", "HIGH", "CVE-2011-2523"},
		"135":   {"MSRPC", "Microsoft RPC — enumerate services; pivot point for DCOM/WMI attacks", "HIGH", ""},
		"139":   {"NetBIOS", "NetBIOS exposed; enumerate shares, users, and domain info", "HIGH", ""},
		"143":   {"IMAP", "IMAP cleartext; credential sniffing and email access possible", "MEDIUM", ""},
		"443":   {"HTTPS", "HTTPS; check for SSL/TLS misconfigs, Heartbleed, outdated cipher suites", "INFO", "CVE-2014-0160"},
		"445":   {"SMB", "SMB — potential EternalBlue (MS17-010); enumerate shares and users", "CRITICAL", "CVE-2017-0144"},
		"512":   {"rexec", "rexec allows remote command execution with minimal auth", "CRITICAL", ""},
		"513":   {"rlogin", "rlogin — trusted host bypass; check .rhosts for unauthenticated access", "CRITICAL", ""},
		"514":   {"rsh", "rsh — unauthenticated remote shell via .rhosts trust", "CRITICAL", ""},
		"873":   {"rsync", "rsync may allow anonymous access and file exfiltration", "HIGH", ""},
		"1433":  {"MSSQL", "MSSQL exposed; try default sa credentials; xp_cmdshell for RCE", "HIGH", ""},
		"1521":  {"Oracle DB", "Oracle DB exposed; try default credentials (sys/change_on_install)", "HIGH", ""},
		"2049":  {"NFS", "NFS share exposed; check for world-readable/writable mounts", "HIGH", "CVE-2019-3010"},
		"3000":  {"Dev Server", "Development server exposed on port 3000 — check for debug endpoints", "MEDIUM", ""},
		"3306":  {"MySQL", "MySQL exposed; check for empty root password or default credentials", "HIGH", ""},
		"3389":  {"RDP", "RDP exposed — BlueKeep (CVE-2019-0708) or credential brute force", "CRITICAL", "CVE-2019-0708"},
		"4444":  {"Metasploit", "Port 4444 — possible existing Metasploit listener or backdoor", "CRITICAL", ""},
		"4848":  {"GlassFish", "GlassFish admin console; try default admin/adminadmin credentials", "HIGH", ""},
		"5432":  {"PostgreSQL", "PostgreSQL exposed; check for trust auth (no password for local/network)", "HIGH", ""},
		"5900":  {"VNC", "VNC exposed — check for no-auth or weak password (brute force)", "CRITICAL", ""},
		"5984":  {"CouchDB", "CouchDB admin party mode may allow unauthenticated DB access", "HIGH", "CVE-2017-12636"},
		"6379":  {"Redis", "Redis with no auth — CONFIG SET dir allows RCE via cron/SSH key write", "CRITICAL", "CVE-2022-0543"},
		"7001":  {"WebLogic", "WebLogic admin; check for known deserialization RCE (CVE-2020-14882)", "CRITICAL", "CVE-2020-14882"},
		"8080":  {"HTTP-Alt", "HTTP on 8080; often development/admin UI — check for exposed panels", "MEDIUM", ""},
		"8443":  {"HTTPS-Alt", "HTTPS on 8443; admin console or API — check for weak auth", "MEDIUM", ""},
		"8888":  {"HTTP-Dev", "HTTP on 8888 — often Jupyter Notebook (RCE if no token auth)", "CRITICAL", ""},
		"9200":  {"Elasticsearch", "Elasticsearch exposed without auth — full data read/write possible", "CRITICAL", "CVE-2015-3337"},
		"9300":  {"Elasticsearch", "Elasticsearch transport port — cluster takeover possible", "HIGH", ""},
		"27017": {"MongoDB", "MongoDB exposed — check for no-auth configuration (very common)", "HIGH", ""},
		"11211": {"Memcached", "Memcached no auth — cache poisoning and amplification DDoS vector", "HIGH", ""},
		"50000": {"SAP", "SAP ICM port; check for default credentials and known exploits", "HIGH", ""},
		"50030": {"Hadoop", "Hadoop JobTracker exposed; potential code execution via job submission", "CRITICAL", ""},
	}

	// Enrich service from nmap output if available
	var result []vuln
	for _, p := range ports {
		portNum := strings.Split(p, "/")[0]
		if def, ok := portMap[portNum]; ok {
			svc := def.service
			// If nmap detected a specific version, include it
			if nmapSvc, ok := serviceMap[portNum]; ok && nmapSvc != "" {
				svc = nmapSvc
			}
			result = append(result, vuln{
				port:     portNum,
				service:  svc,
				finding:  def.finding,
				severity: def.severity,
				cve:      def.cve,
			})
		}
	}
	return result
}

// ── Phase 5: Decision Tree ───────────────────────────────────────────────────

func buildDecisionTree(ports []string, serviceMap map[string]string, probes []probeResult, eng *engagement.Engagement) []suggestion {
	portSet := map[string]bool{}
	for _, p := range ports {
		portSet[strings.Split(p, "/")[0]] = true
	}

	var sugs []suggestion

	// Check if any creds in vault — if yes, suggest credtester first
	if eng != nil {
		vault.List(eng.ID) // warm up
	}

	if portSet["22"] || portSet["21"] || portSet["80"] || portSet["443"] || portSet["8080"] {
		if eng != nil {
			creds, _ := vault.List(eng.ID)
			if len(creds) > 0 {
				sugs = append(sugs, suggestion{
					module: "davoid run cred_tester",
					reason: fmt.Sprintf("%d credential(s) in vault — test SSH/FTP/HTTP access", len(creds)),
				})
			}
		}
	}

	if portSet["80"] || portSet["443"] || portSet["8080"] || portSet["8443"] || portSet["3000"] || portSet["8888"] {
		sugs = append(sugs, suggestion{
			module: "davoid run web_recon",
			reason: "Web service found — fingerprint, path fuzz, extract sensitive data",
		})
	}

	if portSet["445"] || portSet["139"] || portSet["135"] {
		sugs = append(sugs, suggestion{
			module: "davoid run ad_ops",
			reason: "SMB/RPC open — enumerate AD users, groups, Kerberoast, check MS17-010",
		})
	}

	if portSet["22"] {
		sugs = append(sugs, suggestion{
			module: "davoid run looter",
			reason: "SSH open — if you have valid credentials, run post-exploitation enumeration",
		})
	}

	if portSet["21"] {
		sugs = append(sugs, suggestion{
			module: "davoid run sniff",
			reason: "FTP cleartext — run traffic capture to harvest credentials in transit",
		})
	}

	// Redis/Memcached/MongoDB → high value, suggest manual exploitation steps
	if portSet["6379"] || portSet["27017"] || portSet["9200"] || portSet["5984"] {
		sugs = append(sugs, suggestion{
			module: "davoid run ai_assist",
			reason: "NoSQL/cache service exposed — ask AI Console for specific exploitation commands",
		})
	}

	if portSet["3389"] {
		sugs = append(sugs, suggestion{
			module: "davoid run bruteforce",
			reason: "RDP exposed — brute force credentials or check BlueKeep (CVE-2019-0708)",
		})
	}

	if portSet["25"] || portSet["587"] || portSet["465"] {
		sugs = append(sugs, suggestion{
			module: "davoid run phishing",
			reason: "SMTP exposed — use for spear phishing or relay through target mail server",
		})
	}

	// Any HTTP probe returned server banner → webrecon
	for _, p := range probes {
		if p.service == "http" && strings.Contains(p.detail, "Server:") {
			sugs = append(sugs, suggestion{
				module: "davoid run web_recon",
				reason: "HTTP banner grabbed — run web recon for deeper enumeration",
			})
			break
		}
	}

	// Deduplicate
	seen := map[string]bool{}
	unique := []suggestion{}
	for _, s := range sugs {
		if !seen[s.module] {
			seen[s.module] = true
			unique = append(unique, s)
		}
	}
	return unique
}

// ── Phase 6: Report ──────────────────────────────────────────────────────────

func buildReport(target string, ports []string, serviceMap map[string]string, probes []probeResult, aiAnalysis string, vulns []vuln, sugs []suggestion, eng *engagement.Engagement) string {
	var sb strings.Builder
	sb.WriteString("# GOD MODE Campaign Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** `%s`\n", target))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n", time.Now().Format(time.RFC1123)))
	if eng != nil {
		sb.WriteString(fmt.Sprintf("**Engagement:** %s\n", eng.Name))
	}
	sb.WriteString(fmt.Sprintf("**Ports Scanned:** %d open\n\n", len(ports)))

	sb.WriteString("---\n\n")

	sb.WriteString("## Phase 1 — Reconnaissance\n\n")
	if len(ports) > 0 {
		sb.WriteString("| Port | Service |\n|------|--------|\n")
		for _, p := range ports {
			portNum := strings.Split(p, "/")[0]
			svc := serviceMap[portNum]
			if svc == "" {
				svc = "unknown"
			}
			sb.WriteString(fmt.Sprintf("| %s | %s |\n", portNum, svc))
		}
	} else {
		sb.WriteString("No open ports discovered.\n")
	}
	sb.WriteString("\n")

	sb.WriteString("## Phase 2 — Service Probes\n\n")
	if len(probes) > 0 {
		for _, r := range probes {
			sb.WriteString(fmt.Sprintf("- **[%s]** %s/%s — %s\n", r.severity, r.port, r.service, r.detail))
		}
	} else {
		sb.WriteString("No automated probe findings.\n")
	}
	sb.WriteString("\n")

	sb.WriteString("## Phase 3 — AI Analysis\n\n")
	sb.WriteString(aiAnalysis + "\n\n")

	sb.WriteString("## Phase 4 — Vulnerability Correlation\n\n")
	if len(vulns) > 0 {
		sb.WriteString("| Port | Service | Finding | Severity | CVE |\n")
		sb.WriteString("|------|---------|---------|----------|-----|\n")
		for _, v := range vulns {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | **%s** | %s |\n",
				v.port, v.service, v.finding[:min(len(v.finding), 80)], v.severity, v.cve))
		}
	} else {
		sb.WriteString("No high-confidence vulnerabilities correlated.\n")
	}
	sb.WriteString("\n")

	sb.WriteString("## Phase 5 — Recommended Next Steps\n\n")
	if len(sugs) > 0 {
		for i, s := range sugs {
			sb.WriteString(fmt.Sprintf("%d. `%s`\n   - %s\n", i+1, s.module, s.reason))
		}
	} else {
		sb.WriteString("No specific follow-up actions identified.\n")
	}
	sb.WriteString("\n")

	sb.WriteString("---\n*Generated by Davoid GOD MODE — Authorized use only.*\n")

	fname := fmt.Sprintf("reports/godmode_%d.md", time.Now().Unix())
	os.MkdirAll("reports", 0750)
	os.WriteFile(fname, []byte(sb.String()), 0600)
	return fname
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func runNmap(target string) string {
	if _, err := exec.LookPath("nmap"); err != nil {
		return ""
	}
	out, _ := exec.Command("nmap", "-sV", "-T4", "--open", "-p-", target).CombinedOutput()
	return string(out)
}

func extractPorts(output string) []string {
	var ports []string
	for _, line := range strings.Split(output, "\n") {
		if (strings.Contains(line, "/tcp") || strings.Contains(line, "/udp")) &&
			strings.Contains(line, "open") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				ports = append(ports, parts[0])
			}
		}
	}
	return ports
}

// extractServices parses nmap -sV output: "80/tcp  open  http  nginx 1.18.0" → map["80"]="nginx 1.18.0"
func extractServices(output string) map[string]string {
	svcMap := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if (!strings.Contains(line, "/tcp") && !strings.Contains(line, "/udp")) ||
			!strings.Contains(line, "open") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		portNum := strings.Split(parts[0], "/")[0]
		// parts[2] = service name, parts[3...] = version
		svc := parts[2]
		if len(parts) > 3 {
			svc = parts[2] + " " + strings.Join(parts[3:], " ")
		}
		svcMap[portNum] = strings.TrimSpace(svc)
	}
	return svcMap
}

func detectOS(output string) string {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "windows"):
		return "Windows"
	case strings.Contains(lower, "linux"):
		return "Linux"
	case strings.Contains(lower, "freebsd"):
		return "FreeBSD"
	case strings.Contains(lower, "darwin") || strings.Contains(lower, "mac os"):
		return "macOS"
	}
	return ""
}

func buildAIContext(target, scanOutput string, probes []probeResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Nmap scan of %s ===\n", target))
	sb.WriteString(truncate(scanOutput, 2000))
	if len(probes) > 0 {
		sb.WriteString("\n\n=== Automated probe results ===\n")
		for _, p := range probes {
			sb.WriteString(fmt.Sprintf("[%s] %s/%s: %s\n", p.severity, p.port, p.service, p.detail))
		}
	}
	return sb.String()
}

func checkOllama(baseURL string) bool {
	resp, err := client.Get(baseURL + "/api/tags")
	return err == nil && resp.StatusCode == 200
}

func queryOllama(baseURL, model, prompt string) string {
	req := map[string]interface{}{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	}
	body, _ := json.Marshal(req)
	resp, err := client.Post(baseURL+"/api/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var r struct {
		Response string `json:"response"`
	}
	json.Unmarshal(data, &r)
	return r.Response
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
