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

// Built-in tools the AI can call
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
		{"netstat", "netstat — show network connections", toolNetstat},
	}
}

func Run() error {
	ui.Header("AI Console — LLM-Powered Autonomous Pentest Agent")

	// Check Ollama
	ollamaURL := ui.PromptDefault("Ollama URL", "http://localhost:11434")
	model := ui.PromptDefault("Model", "llama3")

	if !checkOllama(ollamaURL) {
		ui.Fail("Ollama not reachable. Start with: ollama serve")
		ui.Info("Install: https://ollama.ai")
		return nil
	}
	ui.Success(fmt.Sprintf("Ollama connected. Model: %s", model))

	fmt.Println()
	ui.Info("Available tools: " + toolList())
	ui.Divider()
	ui.Info("Chat with the AI. It can invoke tools by saying: TOOL:<name>:<args>")
	ui.Info("Type 'quit' to exit.")
	fmt.Println()

	systemPrompt := `You are an expert penetration tester AI assistant running inside Davoid,
a red team engagement platform. You help operators plan and execute authorized security assessments.
You have access to tools. To use a tool, respond with: TOOL:<toolname>:<args>
Available tools: ` + toolList() + `
After using a tool, you'll receive its output. Use it to inform your next action.
Always remind the user that all testing must be authorized.`

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

		history += "\nUser: " + input + "\nAssistant: "

		response := queryOllama(ollamaURL, model, history)
		if response == "" {
			ui.Fail("No response from Ollama.")
			continue
		}

		history += response

		// Handle tool calls
		if strings.Contains(response, "TOOL:") {
			response = handleToolCalls(response)
		}

		fmt.Println()
		fmt.Println(ui.Green.Render("  ai» ") + " " + response)
		fmt.Println()
	}
	return nil
}

func queryOllama(baseURL, model, prompt string) string {
	req := ollamaReq{Model: model, Prompt: prompt, Stream: false}
	body, _ := json.Marshal(req)

	resp, err := client.Post(baseURL+"/api/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var or ollamaResp
	if err := json.Unmarshal(data, &or); err != nil {
		return ""
	}
	return or.Response
}

func handleToolCalls(response string) string {
	lines := strings.Split(response, "\n")
	var result strings.Builder

	for _, line := range lines {
		if strings.HasPrefix(line, "TOOL:") {
			parts := strings.SplitN(line[5:], ":", 2)
			toolName := strings.TrimSpace(parts[0])
			args := ""
			if len(parts) > 1 {
				args = strings.TrimSpace(parts[1])
			}

			found := false
			for _, t := range tools {
				if t.name == toolName {
					fmt.Printf("\n  %s  %s %s\n", ui.Yellow.Render("[TOOL]"), toolName, args)
					out := t.fn(args)
					fmt.Printf("  %s\n", ui.Dim.Render(truncate(out, 500)))
					result.WriteString(fmt.Sprintf("[Tool %s result: %s]\n", toolName, truncate(out, 200)))
					found = true
					break
				}
			}
			if !found {
				result.WriteString(line + "\n")
			}
		} else {
			result.WriteString(line + "\n")
		}
	}
	return result.String()
}

func toolList() string {
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.name
	}
	return strings.Join(names, ", ")
}

func checkOllama(baseURL string) bool {
	resp, err := client.Get(baseURL + "/api/tags")
	return err == nil && resp.StatusCode == 200
}

// ── Tool implementations ─────────────────────────────────────────────────────

func toolPing(args string) string {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return "usage: ping <host>"
	}
	out, _ := exec.Command("ping", "-c", "3", parts[0]).CombinedOutput()
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
	host := parts[0]
	out, _ := exec.Command("whois", host).CombinedOutput()
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
	out, _ := exec.Command("find", parts[0], "-name", parts[1], "-type", "f", "2>/dev/null").CombinedOutput()
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
	out, _ := exec.Command("netstat", "-tulnp").CombinedOutput()
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
