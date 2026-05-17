package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Module represents a Davoid module that can be invoked.
type Module struct {
	Key         string
	Name        string
	Description string
	Category    string
	PyModule    string // Python module name in modules/ directory
}

// Categories in display order
var Categories = []string{
	"Intelligence & OSINT",
	"Offensive Operations",
	"Post-Exploitation",
	"Active Directory",
	"Advanced",
	"System",
}

// Registry is the full list of available modules.
var Registry = []Module{
	// Intelligence & OSINT
	{Key: "scanner", Name: "Net-Mapper", Description: "Nmap orchestration with live CVE lookup (NVD)", Category: "Intelligence & OSINT", PyModule: "scanner"},
	{Key: "sniff", Name: "Live Interceptor", Description: "Real-time traffic capture, DNS tracking, credential extraction", Category: "Intelligence & OSINT", PyModule: "sniff"},
	{Key: "osint", Name: "Holmes Engine", Description: "Username OSINT across 14 platforms, phone intel, subdomain brute", Category: "Intelligence & OSINT", PyModule: "osint"},
	{Key: "web_recon", Name: "Web Recon", Description: "robots.txt scrape, domain reputation, Google Dorks, CT logs", Category: "Intelligence & OSINT", PyModule: "web_recon"},

	// Offensive Operations
	{Key: "mitm", Name: "MITM Engine", Description: "ARP poisoning + automatic IP forwarding (Linux/macOS)", Category: "Offensive Operations", PyModule: "mitm"},
	{Key: "phishing", Name: "Phantom Cloner", Description: "Dynamic page cloning with JS credential harvesting portal", Category: "Offensive Operations", PyModule: "phishing"},
	{Key: "ghost_hub", Name: "GHOST-HUB C2", Description: "AES-encrypted async HTTP command & control server", Category: "Offensive Operations", PyModule: "ghost_hub"},

	// Post-Exploitation
	{Key: "payloads", Name: "Shell Forge", Description: "Multi-language payload generator (Bash, Python, PHP, PS, MSF)", Category: "Post-Exploitation", PyModule: "payloads"},
	{Key: "crypt_keeper", Name: "Crypt-Keeper", Description: "Payload encryption + self-decrypting AES loaders", Category: "Post-Exploitation", PyModule: "crypt_keeper"},
	{Key: "persistence", Name: "Persistence Engine", Description: "systemd, crontab (Linux), LaunchAgent (macOS), registry (Windows)", Category: "Post-Exploitation", PyModule: "persistence"},
	{Key: "bruteforce", Name: "Hash Cracker", Description: "Multi-threaded dictionary/brute MD5, SHA256, NTLM", Category: "Post-Exploitation", PyModule: "bruteforce"},
	{Key: "looter", Name: "Looter", Description: "Privilege escalation discovery, SSH key harvest, loot collection", Category: "Post-Exploitation", PyModule: "looter"},
	{Key: "cred_tester", Name: "Credential Tester", Description: "Credential re-use testing across SSH, FTP, HTTP", Category: "Post-Exploitation", PyModule: "cred_tester"},

	// Active Directory
	{Key: "ad_ops", Name: "AD Ops", Description: "LDAP enum, Kerberoasting, DCSync detection, BloodHound export", Category: "Active Directory", PyModule: "ad_ops"},

	// Advanced
	{Key: "msf_engine", Name: "Metasploit Bridge", Description: "MSF RPC client — auto exploit selection & execution", Category: "Advanced", PyModule: "msf_engine"},
	{Key: "ai_assist", Name: "AI Console", Description: "LangChain + Ollama AI-assisted attack strategy & payload mutation", Category: "Advanced", PyModule: "ai_assist"},
	{Key: "cloud_ops", Name: "Cloud Ops", Description: "Cloud-specific attack modules (AWS, GCP, Azure)", Category: "Advanced", PyModule: "cloud_ops"},
	{Key: "purple_team", Name: "Purple Team", Description: "Defensive scenario simulation and blue team reporting", Category: "Advanced", PyModule: "purple_team"},

	// System
	{Key: "auditor", Name: "Setup Auditor", Description: "Pre-flight check: dependencies, network interface capabilities", Category: "System", PyModule: "auditor"},
	{Key: "god_mode", Name: "God Mode", Description: "Advanced exploitation chains", Category: "System", PyModule: "god_mode"},
}

// ByCategory returns modules filtered by category.
func ByCategory(category string) []Module {
	var out []Module
	for _, m := range Registry {
		if m.Category == category {
			out = append(out, m)
		}
	}
	return out
}

// FindDavoidRoot returns the absolute path of the directory containing main.py.
// Priority: binary's own directory → cwd → /opt/davoid.
func FindDavoidRoot() string {
	var candidates []string
	if ex, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(ex))
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}
	candidates = append(candidates, "/opt/davoid")

	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(filepath.Join(abs, "main.py")); err == nil {
				return abs
			}
		}
	}
	return "."
}

// FindPython returns the Python interpreter to use, preferring the venv
// local to root so packages are always available.
func FindPython(root string) string {
	candidates := []string{
		filepath.Join(root, "venv/bin/python3"),
		filepath.Join(root, "venv/bin/python"),
		"/opt/davoid/venv/bin/python3",
		"/opt/davoid/venv/bin/python",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if p, err := exec.LookPath("python3"); err == nil {
		return p
	}
	return "python3"
}

// RunModule launches a Python module directly via DAVOID_MODULE env var,
// bypassing the interactive menu entirely.
func RunModule(key string) error {
	root := FindDavoidRoot()
	python := FindPython(root)
	mainPy := filepath.Join(root, "main.py")

	cmd := exec.Command(python, mainPy)
	cmd.Dir = root
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), fmt.Sprintf("DAVOID_MODULE=%s", key))

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("module exited with code %d", exitErr.ExitCode())
		}
		return fmt.Errorf("module error: %w", err)
	}
	return nil
}

// RunInteractivePython launches the full Python TUI (legacy mode).
func RunInteractivePython() error {
	root := FindDavoidRoot()
	python := FindPython(root)
	mainPy := filepath.Join(root, "main.py")

	cmd := exec.Command(python, mainPy)
	cmd.Dir = root
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// ShortDesc truncates a description to fit the terminal.
func ShortDesc(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// ColumnPad right-pads a string to width.
func ColumnPad(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}
