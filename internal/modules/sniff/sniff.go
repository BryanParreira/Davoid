package sniff

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
	"github.com/bryanparreira/davoid/internal/vault"
)

func Run() error {
	ui.Header("Live Interceptor — Real-Time Packet Capture")

	if _, err := exec.LookPath("tcpdump"); err != nil {
		ui.Fail("tcpdump not found. Install: brew install tcpdump (macOS) or apt install tcpdump")
		return nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		ui.Fail("Cannot enumerate network interfaces.")
		return nil
	}

	var ifaceNames []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			ifaceNames = append(ifaceNames, fmt.Sprintf("%-12s %s", iface.Name, iface.HardwareAddr))
		}
	}
	if len(ifaceNames) == 0 {
		ifaceNames = []string{"en0", "eth0", "wlan0"}
	}

	idx := ui.Select("Network Interface", ifaceNames)
	if idx < 0 {
		return nil
	}
	iface := strings.Fields(ifaceNames[idx])[0]

	filter := ui.PromptDefault("BPF Filter", "tcp or udp")
	savePCAP := ui.Confirm("Save PCAP file?")

	pcapFile := ""
	if savePCAP {
		pcapFile = fmt.Sprintf("davoid_capture_%d.pcap", time.Now().Unix())
		ui.Info(fmt.Sprintf("PCAP will be saved to: %s", pcapFile))
	}

	fmt.Println()
	ui.Info(fmt.Sprintf("Sniffing on %s — Press Ctrl+C to stop", iface))
	ui.Divider()
	fmt.Printf("  %-8s  %-20s  %-20s  %s\n",
		ui.Bold.Render("PROTO"),
		ui.Bold.Render("SRC"),
		ui.Bold.Render("DST"),
		ui.Bold.Render("INFO"),
	)
	ui.Divider()

	args := []string{"-i", iface, "-l", "-n", "-q", "-tttt"}
	if filter != "" {
		args = append(args, filter)
	}
	if savePCAP {
		args = append(args, "-w", pcapFile)
	}

	cmd := exec.Command("tcpdump", args...)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		ui.Fail(fmt.Sprintf("tcpdump pipe error: %v", err))
		return nil
	}
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		ui.Fail(fmt.Sprintf("tcpdump start error: %v (try sudo)", err))
		return nil
	}

	eng, _ := engagement.Active()
	credHits := 0

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			line := scanner.Text()
			parsedLine, cred := parseTCPDumpLine(line)
			fmt.Println(parsedLine)
			if cred != "" {
				fmt.Printf("  %s  %s\n", ui.Red.Render("CRED"), ui.Yellow.Render(cred))
				credHits++
				if eng != nil {
					engagement.LogFinding(eng.ID, "sniff", "network",
						"Cleartext credential intercepted",
						cred, "HIGH", line)
					vault.Save(eng.ID, "sniff", "network", "", cred, "cleartext")
				}
			}
		}
	}()

	select {
	case <-stop:
	case <-done:
	}

	if cmd.Process != nil {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	}

	fmt.Println()
	ui.Divider()
	ui.Success(fmt.Sprintf("Capture stopped. Credentials intercepted: %d", credHits))
	if savePCAP {
		ui.Success(fmt.Sprintf("PCAP saved: %s", pcapFile))
	}
	ui.PressEnter()
	return nil
}

// RunCapture runs packet capture on the given interface without interactive prompts.
// Used by netintercept for combined MITM+sniff mode.
func RunCapture(iface, filter string, savePCAP bool) error {
	pcapFile := ""
	if savePCAP {
		pcapFile = fmt.Sprintf("davoid_capture_%d.pcap", time.Now().Unix())
		ui.Info(fmt.Sprintf("PCAP will be saved to: %s", pcapFile))
	}

	fmt.Println()
	ui.Info(fmt.Sprintf("Sniffing on %s — Press Ctrl+C to stop", iface))
	ui.Divider()
	fmt.Printf("  %-8s  %-20s  %-20s  %s\n",
		ui.Bold.Render("PROTO"),
		ui.Bold.Render("SRC"),
		ui.Bold.Render("DST"),
		ui.Bold.Render("INFO"),
	)
	ui.Divider()

	args := []string{"-i", iface, "-l", "-n", "-q", "-tttt"}
	if filter != "" {
		args = append(args, filter)
	}
	if savePCAP {
		args = append(args, "-w", pcapFile)
	}

	cmd := exec.Command("tcpdump", args...)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		ui.Fail(fmt.Sprintf("tcpdump pipe error: %v", err))
		return nil
	}
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		ui.Fail(fmt.Sprintf("tcpdump start error: %v (try sudo)", err))
		return nil
	}

	eng, _ := engagement.Active()
	credHits := 0

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pipe)
		for sc.Scan() {
			line := sc.Text()
			parsedLine, cred := parseTCPDumpLine(line)
			fmt.Println(parsedLine)
			if cred != "" {
				fmt.Printf("  %s  %s\n", ui.Red.Render("CRED"), ui.Yellow.Render(cred))
				credHits++
				if eng != nil {
					engagement.LogFinding(eng.ID, "sniff", "network",
						"Cleartext credential intercepted",
						cred, "HIGH", line)
					vault.Save(eng.ID, "sniff", "network", "", cred, "cleartext")
				}
			}
		}
	}()

	select {
	case <-stop:
	case <-done:
	}

	if cmd.Process != nil {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	}

	fmt.Println()
	ui.Divider()
	ui.Success(fmt.Sprintf("Capture stopped. Credentials intercepted: %d", credHits))
	if savePCAP {
		ui.Success(fmt.Sprintf("PCAP saved: %s", pcapFile))
	}
	return nil
}

func parseTCPDumpLine(line string) (display, cred string) {
	// Basic tcpdump -q -tttt output: timestamp proto src > dst: info
	lower := strings.ToLower(line)

	proto := "TCP"
	if strings.Contains(line, "UDP") || strings.Contains(line, " udp ") {
		proto = "UDP"
	} else if strings.Contains(line, "ICMP") {
		proto = "ICMP"
	} else if strings.Contains(line, "DNS") {
		proto = "DNS"
	}

	protoStyle := ui.Cyan.Render(fmt.Sprintf("%-5s", proto))

	// Check for credentials in payload
	credKeywords := []string{
		"password=", "pass=", "passwd=", "pwd=",
		"user=", "username=", "login=",
		"authorization: basic", "user ", "pass ",
	}
	for _, kw := range credKeywords {
		if idx := strings.Index(lower, kw); idx >= 0 {
			end := idx + 60
			if end > len(line) {
				end = len(line)
			}
			cred = strings.TrimSpace(line[idx:end])
			break
		}
	}

	// DNS query highlight
	if strings.Contains(lower, " a? ") || strings.Contains(lower, " aaaa? ") {
		parts := strings.Fields(line)
		for i, p := range parts {
			if p == "A?" || p == "AAAA?" {
				if i+1 < len(parts) {
					display = fmt.Sprintf("  %s  %s  %s",
						ui.Cyan.Render("DNS "),
						ui.Yellow.Render(parts[i+1]),
						ui.Dim.Render(line),
					)
					return display, cred
				}
			}
		}
	}

	display = fmt.Sprintf("  %s  %s", protoStyle, ui.Dim.Render(truncate(line, 100)))
	return display, cred
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
