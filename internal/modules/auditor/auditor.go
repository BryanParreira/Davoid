package auditor

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/modules/ui"
)

type toolCheck struct {
	name    string
	cmd     string
	install string
}

var tools = []toolCheck{
	{"nmap", "nmap", "brew install nmap / apt install nmap"},
	{"tcpdump", "tcpdump", "brew install tcpdump / apt install tcpdump"},
	{"arpspoof", "arpspoof", "brew install dsniff / apt install dsniff"},
	{"msfconsole", "msfconsole", "https://metasploit.com"},
	{"msfvenom", "msfvenom", "included with Metasploit"},
	{"nc (netcat)", "nc", "brew install ncat / apt install netcat"},
	{"curl", "curl", "brew install curl / apt install curl"},
	{"dig", "dig", "brew install bind / apt install dnsutils"},
	{"whois", "whois", "brew install whois / apt install whois"},
	{"git", "git", "https://git-scm.com"},
	{"ssh", "ssh", "built-in on macOS/Linux"},
	{"john", "john", "brew install john / apt install john"},
	{"hashcat", "hashcat", "brew install hashcat / apt install hashcat"},
	{"ollama", "ollama", "https://ollama.ai"},
}

var commonPorts = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443}

func Run() error {
	ui.Header("Setup Auditor — Dependency & System Posture Check")

	fmt.Println()
	ui.Divider()
	ui.Info(fmt.Sprintf("Platform: %s/%s", runtime.GOOS, runtime.GOARCH))
	ui.Info(fmt.Sprintf("Hostname: %s", hostname()))
	uid := os.Getuid()
	if uid == 0 {
		ui.Warn("Running as root.")
	} else {
		ui.Info(fmt.Sprintf("Running as UID %d (non-root — some modules require sudo).", uid))
	}
	ui.Divider()

	// Tool checks
	fmt.Println()
	ui.Info("Tool Availability")
	ui.Divider()
	fmt.Printf("  %-20s  %-8s  %s\n", ui.Bold.Render("TOOL"), ui.Bold.Render("STATUS"), ui.Bold.Render("INSTALL"))
	ui.Divider()

	available := 0
	missing := 0
	for _, t := range tools {
		path, err := exec.LookPath(t.cmd)
		if err != nil {
			fmt.Printf("  %-20s  %s  %s\n",
				t.name,
				ui.Red.Render("MISSING"),
				ui.Dim.Render(t.install),
			)
			missing++
		} else {
			ver := toolVersion(t.cmd)
			fmt.Printf("  %-20s  %s  %s\n",
				t.name,
				ui.Green.Render("OK     "),
				ui.Dim.Render(path+" "+ver),
			)
			available++
		}
	}

	fmt.Printf("\n  %s: %d  |  %s: %d\n",
		ui.Green.Render("Available"), available,
		ui.Red.Render("Missing"), missing,
	)

	// Network interface check
	fmt.Println()
	ui.Divider()
	ui.Info("Network Interfaces")
	ui.Divider()
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		var ips []string
		for _, a := range addrs {
			ips = append(ips, a.String())
		}
		flags := []string{}
		if iface.Flags&net.FlagUp != 0 {
			flags = append(flags, "UP")
		}
		if iface.Flags&net.FlagMulticast != 0 {
			flags = append(flags, "MULTICAST")
		}
		fmt.Printf("  %-12s  %-20s  %s  %s\n",
			ui.Cyan.Render(iface.Name),
			strings.Join(ips, " "),
			iface.HardwareAddr,
			ui.Dim.Render(strings.Join(flags, " ")),
		)
	}

	// Local port probe
	fmt.Println()
	ui.Divider()
	ui.Info("Local Port Probe")
	ui.Divider()
	for _, port := range commonPorts {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			fmt.Printf("  %s  %d  %s\n",
				ui.Yellow.Render("OPEN"),
				port,
				ui.Dim.Render(serviceName(port)),
			)
		}
	}

	// Writability checks
	fmt.Println()
	ui.Divider()
	ui.Info("Directory Writability")
	ui.Divider()
	dirs := []string{".", "./payloads", "./logs", "./reports", "/tmp"}
	for _, d := range dirs {
		os.MkdirAll(d, 0700)
		testFile := d + "/.davoid_test"
		err := os.WriteFile(testFile, []byte("x"), 0600)
		if err == nil {
			os.Remove(testFile)
			fmt.Printf("  %s  %s\n", ui.Green.Render("OK  "), d)
		} else {
			fmt.Printf("  %s  %s  (%v)\n", ui.Red.Render("FAIL"), d, err)
		}
	}

	fmt.Println()
	ui.Divider()
	ui.Success("Audit complete.")
	ui.PressEnter()
	return nil
}

func toolVersion(name string) string {
	var args []string
	switch name {
	case "nmap":
		args = []string{"--version"}
	case "msfconsole":
		args = []string{"--version"}
	default:
		args = []string{"--version"}
	}
	out, _ := exec.Command(name, args...).CombinedOutput()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 0 {
		return truncate(lines[0], 40)
	}
	return ""
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func serviceName(port int) string {
	m := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
		80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
		1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
		6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
	}
	if s, ok := m[port]; ok {
		return s
	}
	return "unknown"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
