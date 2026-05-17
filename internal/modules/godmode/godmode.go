package godmode

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

var client = &http.Client{Timeout: 60 * time.Second}

func Run() error {
	ui.Header("GOD MODE — Autonomous Full-Campaign Orchestrator")

	ui.Warn("GOD MODE executes a full automated attack chain:")
	fmt.Println("  Phase 1: Reconnaissance (Nmap full audit)")
	fmt.Println("  Phase 2: AI Analysis (Ollama exploit mapping)")
	fmt.Println("  Phase 3: Vulnerability correlation")
	fmt.Println("  Phase 4: Report generation")
	fmt.Println()
	ui.Warn("For authorized penetration testing only.")
	fmt.Println()

	if !ui.Confirm("Launch GOD MODE campaign?") {
		return nil
	}

	target := ui.Prompt("Primary target (IP / CIDR)")
	if target == "" {
		return nil
	}

	ollamaURL := ui.PromptDefault("Ollama URL (for AI analysis)", "http://localhost:11434")
	model := ui.PromptDefault("AI model", "llama3")

	eng, _ := engagement.Active()
	if eng == nil {
		ui.Warn("No active engagement. Create one for full tracking.")
	}

	// ── Phase 1: Nmap Recon ──────────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info(fmt.Sprintf("Phase 1/4: Reconnaissance → %s", target))
	ui.Divider()

	scanOutput := runNmap(target)
	if scanOutput == "" {
		ui.Fail("Nmap failed or not installed.")
		return nil
	}
	fmt.Println(ui.Dim.Render(truncate(scanOutput, 2000)))

	// Parse basic info
	openPorts := extractPorts(scanOutput)
	ui.Success(fmt.Sprintf("Phase 1 complete. Open ports: %s", strings.Join(openPorts, ", ")))

	if eng != nil {
		engagement.LogFinding(eng.ID, "god_mode", target,
			fmt.Sprintf("GOD MODE Recon: %d open ports", len(openPorts)),
			scanOutput, "INFO", strings.Join(openPorts, ","))
	}

	// ── Phase 2: AI Analysis ─────────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Phase 2/4: AI Analysis — Mapping exploits via Ollama")
	ui.Divider()

	var aiSuggestions string
	if checkOllama(ollamaURL) {
		prompt := fmt.Sprintf(`You are a penetration tester. Given this Nmap scan result for target %s,
identify the top 3 most exploitable vulnerabilities and suggest Metasploit modules or manual techniques.
Be concise — one paragraph per finding.

Nmap output:
%s`, target, truncate(scanOutput, 3000))

		aiSuggestions = queryOllama(ollamaURL, model, prompt)
		if aiSuggestions != "" {
			fmt.Println()
			fmt.Println(ui.Green.Render("  AI Analysis:"))
			for _, line := range strings.Split(aiSuggestions, "\n") {
				fmt.Println("  " + line)
			}
			if eng != nil {
				engagement.LogFinding(eng.ID, "god_mode", target,
					"GOD MODE AI Analysis complete",
					aiSuggestions, "HIGH", "")
			}
		}
	} else {
		ui.Warn("Ollama unavailable — skipping AI phase.")
		aiSuggestions = "AI analysis unavailable (Ollama offline)."
	}
	ui.Success("Phase 2 complete.")

	// ── Phase 3: Vulnerability Correlation ──────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Phase 3/4: Vulnerability Correlation")
	ui.Divider()

	vulns := correlateVulns(openPorts, target)
	for _, v := range vulns {
		fmt.Printf("  %s  %s  →  %s\n",
			ui.Red.Render(fmt.Sprintf("[%s]", v.severity)),
			ui.Bold.Render(v.port+"/"+v.service),
			v.finding,
		)
		if eng != nil {
			engagement.LogFinding(eng.ID, "god_mode", target,
				fmt.Sprintf("Correlated vuln on %s: %s", v.port, v.finding),
				v.finding, v.severity, v.port)
		}
	}
	if len(vulns) == 0 {
		ui.Info("No known vulnerable services detected via port correlation.")
	}
	ui.Success("Phase 3 complete.")

	// ── Phase 4: Report ──────────────────────────────────────────────────────
	fmt.Println()
	ui.Divider()
	ui.Info("Phase 4/4: Generating Campaign Report")
	ui.Divider()

	fname := buildReport(target, openPorts, aiSuggestions, vulns, eng)
	ui.Success(fmt.Sprintf("Report saved: %s", fname))

	fmt.Println()
	ui.Divider()
	ui.Success("GOD MODE campaign complete.")
	ui.PressEnter()
	return nil
}

type vuln struct {
	port     string
	service  string
	finding  string
	severity string
}

// correlateVulns maps open ports to known risky services
func correlateVulns(ports []string, _ string) []vuln {
	portMap := map[string]vuln{
		"21":   {"21", "FTP", "FTP allows anonymous login or cleartext auth", "HIGH"},
		"23":   {"23", "Telnet", "Telnet sends credentials in cleartext", "CRITICAL"},
		"25":   {"25", "SMTP", "SMTP relay may be open (spam/phishing vector)", "MEDIUM"},
		"80":   {"80", "HTTP", "Unencrypted web service; check for SQLi/XSS", "MEDIUM"},
		"445":  {"445", "SMB", "SMB may be vulnerable to EternalBlue (MS17-010)", "CRITICAL"},
		"1433": {"1433", "MSSQL", "SQL Server exposed; try default creds sa/sa", "HIGH"},
		"3306": {"3306", "MySQL", "MySQL exposed; check for default/empty passwords", "HIGH"},
		"3389": {"3389", "RDP", "RDP exposed; vulnerable to BlueKeep (CVE-2019-0708)", "CRITICAL"},
		"5432": {"5432", "PostgreSQL", "PostgreSQL exposed; check for trust auth", "HIGH"},
		"6379": {"6379", "Redis", "Redis likely unauthenticated; full RCE possible", "CRITICAL"},
	}

	var result []vuln
	for _, p := range ports {
		// extract just the port number
		portNum := strings.Split(p, "/")[0]
		if v, ok := portMap[portNum]; ok {
			result = append(result, v)
		}
	}
	return result
}

func runNmap(target string) string {
	if _, err := exec.LookPath("nmap"); err != nil {
		return ""
	}
	out, err := exec.Command("nmap", "-sV", "-T4", "--open", "-p-", target).CombinedOutput()
	if err != nil {
		return string(out)
	}
	return string(out)
}

func extractPorts(output string) []string {
	var ports []string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "/tcp") || strings.Contains(line, "/udp") {
			if strings.Contains(line, "open") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					ports = append(ports, parts[0])
				}
			}
		}
	}
	return ports
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

func buildReport(target string, ports []string, aiAnalysis string, vulns []vuln, eng *engagement.Engagement) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# GOD MODE Campaign Report\n\n"))
	sb.WriteString(fmt.Sprintf("**Target:** %s\n", target))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n\n", time.Now().Format(time.RFC1123)))

	if eng != nil {
		sb.WriteString(fmt.Sprintf("**Engagement:** %s\n\n", eng.Name))
	}

	sb.WriteString("## Phase 1: Reconnaissance\n\n")
	sb.WriteString(fmt.Sprintf("Open ports discovered: `%s`\n\n", strings.Join(ports, "`, `")))

	sb.WriteString("## Phase 2: AI Analysis\n\n")
	sb.WriteString(aiAnalysis + "\n\n")

	sb.WriteString("## Phase 3: Vulnerability Correlation\n\n")
	if len(vulns) > 0 {
		sb.WriteString("| Port | Service | Finding | Severity |\n")
		sb.WriteString("|------|---------|---------|----------|\n")
		for _, v := range vulns {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", v.port, v.service, v.finding, v.severity))
		}
	} else {
		sb.WriteString("No high-confidence vulnerabilities correlated.\n")
	}

	sb.WriteString("\n---\n*Generated by Davoid GOD MODE — Authorized use only.*\n")

	fname := fmt.Sprintf("reports/godmode_%d.md", time.Now().Unix())
	writeReport(fname, sb.String())
	return fname
}

func writeReport(fname, content string) {
	parts := strings.Split(fname, "/")
	if len(parts) > 1 {
		os.MkdirAll(strings.Join(parts[:len(parts)-1], "/"), 0755)
	}
	os.WriteFile(fname, []byte(content), 0600)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
