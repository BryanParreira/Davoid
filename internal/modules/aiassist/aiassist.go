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
		{"ping", "ping <host> — check host reachability", toolPing},
		{"nmap", "nmap <host> — quick port scan", toolNmap},
		{"dig", "dig <domain> — DNS lookup", toolDig},
		{"whois", "whois <domain/IP> — WHOIS lookup", toolWhois},
		{"curl", "curl <url> — HTTP request", toolCurl},
		{"grep", "grep <pattern> <file> — search in file", toolGrep},
		{"find", "find <path> <name> — find files", toolFind},
		{"id", "id — show current user", toolID},
		{"uname", "uname — show system info", toolUname},
		{"netstat", "netstat — show listening ports", toolNetstat},
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

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
