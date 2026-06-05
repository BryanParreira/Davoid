package aiassist

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/modules/ui"
)

var client = &http.Client{Timeout: 120 * time.Second}

type ollamaReq struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResp struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

type tool struct {
	name string
	desc string
	fn   func(args string) string
}

var tools []tool

func init() {
	tools = []tool{
		// Recon
		{"ping", "ping <host> — check host reachability", toolPing},
		{"nmap", "nmap <host> — quick port scan", toolNmap},
		{"dig", "dig <domain> — DNS lookup", toolDig},
		{"whois", "whois <domain/IP> — WHOIS lookup", toolWhois},
		{"masscan", "masscan <host/cidr> <ports> — fast port scanner", toolMasscan},
		// Web
		{"curl", "curl <url> — HTTP request with headers", toolCurl},
		{"nikto", "nikto <host> — web vulnerability scanner", toolNikto},
		{"gobuster", "gobuster <url> <wordlist> — directory/file brute force", toolGobuster},
		{"sqlmap", "sqlmap <url> — SQL injection test", toolSQLMap},
		// Post-exploitation helpers
		{"grep", "grep <pattern> <file> — search in file", toolGrep},
		{"find", "find <path> <name> — find files", toolFind},
		{"id", "id — show current user", toolID},
		{"uname", "uname — show system info", toolUname},
		{"netstat", "netstat — show listening ports", toolNetstat},
		{"hashcat", "hashcat <hash> <wordlist> — crack hash", toolHashcat},
	}
}

func Run() error {
	ui.Header("AI Console — LLM-Powered Autonomous Pentest Agent")

	ollamaURL := ui.PromptDefault("Ollama URL", "http://localhost:11434")

	if !checkOllama(ollamaURL) {
		ui.Fail("Ollama not reachable. Start with: ollama serve")
		ui.Info("Install: https://ollama.ai")
		return nil
	}
	ui.Success("Ollama connected.")

	// List available models and let user pick from a menu
	models := listModels(ollamaURL)
	if len(models) == 0 {
		ui.Fail("No models installed. Run: ollama pull llama3")
		ui.Info("See https://ollama.ai/library for available models.")
		return nil
	}

	modelIdx := ui.Select("Select Model", models)
	if modelIdx < 0 {
		return nil
	}
	model := models[modelIdx]
	ui.Info(fmt.Sprintf("Using model: %s", model))

	fmt.Println()
	ui.Info("Tools: " + toolList())
	ui.Divider()
	ui.Info("Chat with the AI. It can call tools via TOOL:<name>:<args>")
	ui.Info("Type 'quit' to exit.")
	fmt.Println()

	systemPrompt := `You are an expert penetration tester AI assistant running inside Davoid,
a red team engagement platform. You help operators plan and execute authorized security assessments.

You have access to the following tools. To use one, respond with exactly:
TOOL:<toolname>:<args>

Available tools: ` + toolList() + `

Rules:
- Only use tools when they will genuinely help answer the question.
- After each tool result, analyze the output and provide a clear recommendation.
- Always remind users that all testing must be authorized.
- Be concise and action-oriented.`

	// Sliding window history to prevent context overflow (~8000 chars max)
	const maxHistoryLen = 8000
	history := systemPrompt
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print(ui.Cyan.Render("  you» ") + " ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			continue
		}
		if input == "quit" || input == "exit" {
			break
		}

		// Trim history to sliding window
		if len(history) > maxHistoryLen {
			history = systemPrompt + "\n[...earlier context trimmed...]\n" + history[len(history)-maxHistoryLen/2:]
		}

		history += "\nUser: " + input + "\nAssistant: "

		ui.Info("Thinking...")
		response := queryOllama(ollamaURL, model, history)
		if response == "" {
			ui.Fail("No response from Ollama. Check: ollama serve")
			continue
		}
		history += response

		// If AI called tools, execute them and feed results back for analysis
		if strings.Contains(response, "TOOL:") {
			toolOutput := executeTools(response)
			if toolOutput != "" {
				history += "\n[Tool Results]:\n" + toolOutput + "\nAssistant: "
				ui.Info("Analyzing results...")
				followUp := queryOllama(ollamaURL, model, history)
				if followUp != "" {
					history += followUp
					response = followUp
				}
			}
		}

		fmt.Println()
		fmt.Println(ui.Green.Render("  ai» ") + " " + strings.TrimSpace(response))
		fmt.Println()
	}
	return nil
}

// executeTools runs all TOOL: calls in a response, prints output, returns combined output for AI feedback.
func executeTools(response string) string {
	var feedback strings.Builder
	for _, line := range strings.Split(response, "\n") {
		if !strings.HasPrefix(line, "TOOL:") {
			continue
		}
		parts := strings.SplitN(line[5:], ":", 2)
		toolName := strings.TrimSpace(parts[0])
		args := ""
		if len(parts) > 1 {
			args = strings.TrimSpace(parts[1])
		}

		for _, t := range tools {
			if t.name == toolName {
				fmt.Printf("\n  %s  %s %s\n", ui.Yellow.Render("[TOOL]"), toolName, args)
				if !ui.Confirm(fmt.Sprintf("Execute: %s %s", toolName, args)) {
					feedback.WriteString(fmt.Sprintf("[%s(%s)]: user declined execution\n\n", toolName, args))
					break
				}
				out := t.fn(args)
				display := truncate(out, 500)
				fmt.Printf("  %s\n", ui.Dim.Render(display))
				feedback.WriteString(fmt.Sprintf("[%s(%s)]:\n%s\n\n", toolName, args, truncate(out, 300)))
				break
			}
		}
	}
	return feedback.String()
}

func queryOllama(baseURL, model, prompt string) string {
	req := ollamaReq{Model: model, Prompt: prompt, Stream: false}
	body, _ := json.Marshal(req)

	resp, err := client.Post(baseURL+"/api/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		ui.Warn(fmt.Sprintf("Ollama request failed: %v", err))
		return ""
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	// Surface Ollama errors (e.g. model not found)
	var errResp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &errResp) == nil && errResp.Error != "" {
		ui.Fail(fmt.Sprintf("Ollama error: %s", errResp.Error))
		return ""
	}

	var or ollamaResp
	if err := json.Unmarshal(data, &or); err != nil {
		ui.Warn(fmt.Sprintf("Unexpected Ollama response: %s", truncate(string(data), 200)))
		return ""
	}
	return or.Response
}

func checkOllama(baseURL string) bool {
	resp, err := client.Get(baseURL + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func listModels(baseURL string) []string {
	resp, err := client.Get(baseURL + "/api/tags")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}
	names := make([]string, len(result.Models))
	for i, m := range result.Models {
		names[i] = m.Name
	}
	return names
}

func toolList() string {
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.name
	}
	return strings.Join(names, ", ")
}

// ── Tool implementations ─────────────────────────────────────────────────────

func toolPing(args string) string {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "usage: ping <host>"
	}
	count := "-c"
	if runtime.GOOS == "windows" {
		count = "-n"
	}
	out, _ := exec.Command("ping", count, "3", parts[0]).CombinedOutput()
	return string(out)
}

func toolNmap(args string) string {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "usage: nmap <host>"
	}
	out, _ := exec.Command("nmap", "-sV", "-T4", "--top-ports", "100", parts[0]).CombinedOutput()
	return string(out)
}

func toolDig(args string) string {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "usage: dig <domain>"
	}
	out, _ := exec.Command("dig", parts...).CombinedOutput()
	return string(out)
}

func toolWhois(args string) string {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "usage: whois <domain/IP>"
	}
	out, _ := exec.Command("whois", parts[0]).CombinedOutput()
	if len(out) > 2000 {
		out = out[:2000]
	}
	return string(out)
}

func toolCurl(args string) string {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "usage: curl <url>"
	}
	cmdArgs := append([]string{"-s", "-L", "--max-time", "10"}, parts...)
	out, _ := exec.Command("curl", cmdArgs...).CombinedOutput()
	if len(out) > 2000 {
		out = out[:2000]
	}
	return string(out)
}

func toolGrep(args string) string {
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "usage: grep <pattern> <file>"
	}
	out, _ := exec.Command("grep", "-r", parts[0], parts[1]).CombinedOutput()
	return string(out)
}

func toolFind(args string) string {
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "usage: find <path> <name>"
	}
	out, _ := exec.Command("find", parts[0], "-name", parts[1], "-type", "f").CombinedOutput()
	return string(out)
}

func toolID(_ string) string {
	out, _ := exec.Command("id").CombinedOutput()
	return string(out)
}

func toolUname(_ string) string {
	out, _ := exec.Command("uname", "-a").CombinedOutput()
	return string(out)
}

func toolNetstat(_ string) string {
	var out []byte
	switch runtime.GOOS {
	case "darwin":
		out, _ = exec.Command("netstat", "-an", "-p", "tcp").CombinedOutput()
	case "windows":
		out, _ = exec.Command("netstat", "-an").CombinedOutput()
	default:
		out, _ = exec.Command("netstat", "-tulnp").CombinedOutput()
	}
	if len(out) > 2000 {
		out = out[:2000]
	}
	return string(out)
}

func toolMasscan(args string) string {
	if _, err := exec.LookPath("masscan"); err != nil {
		return "masscan not found. Install: sudo apt install masscan"
	}
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "usage: masscan <target> <ports>  e.g. masscan 10.0.0.0/24 80,443,8080"
	}
	// masscan requires root; --rate limit to avoid destroying networks
	cmdArgs := []string{parts[0], "-p", parts[1], "--rate", "1000", "--wait", "3"}
	out, _ := exec.Command("masscan", cmdArgs...).CombinedOutput()
	if len(out) > 2000 {
		out = out[:2000]
	}
	return string(out)
}

func toolNikto(args string) string {
	if _, err := exec.LookPath("nikto"); err != nil {
		return "nikto not found. Install: sudo apt install nikto"
	}
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "usage: nikto <host or url>"
	}
	target := parts[0]
	out, _ := exec.Command("nikto", "-h", target, "-Tuning", "123bde", "-maxtime", "60s").CombinedOutput()
	if len(out) > 3000 {
		out = out[:3000]
	}
	return string(out)
}

func toolGobuster(args string) string {
	if _, err := exec.LookPath("gobuster"); err != nil {
		return "gobuster not found. Install: sudo apt install gobuster  OR  go install github.com/OJ/gobuster/v3@latest"
	}
	parts := strings.Fields(args)
	if len(parts) < 1 {
		return "usage: gobuster <url> [wordlist]"
	}
	url := parts[0]
	wordlist := "/usr/share/wordlists/dirb/common.txt"
	if len(parts) >= 2 {
		wordlist = parts[1]
	}
	out, _ := exec.Command("gobuster", "dir",
		"-u", url,
		"-w", wordlist,
		"-t", "20",
		"-q",
		"--no-error",
	).CombinedOutput()
	if len(out) > 3000 {
		out = out[:3000]
	}
	return string(out)
}

func toolSQLMap(args string) string {
	if _, err := exec.LookPath("sqlmap"); err != nil {
		return "sqlmap not found. Install: sudo apt install sqlmap  OR  pip install sqlmap"
	}
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "usage: sqlmap <url>  e.g. sqlmap http://target.com/login?id=1"
	}
	// Non-interactive, batch mode, limited requests to avoid IDS noise
	cmdArgs := []string{
		"-u", parts[0],
		"--batch",
		"--level", "1",
		"--risk", "1",
		"--timeout", "10",
		"--retries", "1",
		"--output-dir", "/tmp/davoid_sqlmap",
	}
	out, _ := exec.Command("sqlmap", cmdArgs...).CombinedOutput()
	if len(out) > 3000 {
		out = out[:3000]
	}
	return string(out)
}

func toolHashcat(args string) string {
	if _, err := exec.LookPath("hashcat"); err != nil {
		return "hashcat not found. Install: sudo apt install hashcat"
	}
	parts := strings.Fields(args)
	if len(parts) < 2 {
		return "usage: hashcat <hash_or_file> <wordlist>  (auto-detects hash type)"
	}
	hashInput := parts[0]
	wordlist := parts[1]
	// Write hash to temp file if it looks like a raw hash (no file path separators)
	hashFile := hashInput
	if !strings.Contains(hashInput, "/") && !strings.Contains(hashInput, "\\") {
		tmp, err := os.CreateTemp("", "davoid_hash_*")
		if err == nil {
			tmp.WriteString(hashInput + "\n")
			tmp.Close()
			hashFile = tmp.Name()
			defer os.Remove(hashFile)
		}
	}
	// -a 0 = dictionary attack, --quiet = no progress spam, --force = skip GPU warning
	out, _ := exec.Command("hashcat",
		"-a", "0",
		hashFile, wordlist,
		"--quiet",
		"--force",
		"--potfile-disable",
	).CombinedOutput()
	if len(out) > 2000 {
		out = out[:2000]
	}
	return string(out)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
