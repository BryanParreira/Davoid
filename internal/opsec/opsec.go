// Package opsec rates the detection risk of red team operations.
// Each module has a noise level; the aggregate score shows overall OPSEC posture.
package opsec

import "fmt"

// NoiseLevel rates how detectable an operation is (0 = silent, 3 = loud).
type NoiseLevel int

const (
	NoiseNone   NoiseLevel = 0 // passive, no target contact
	NoiseLow    NoiseLevel = 1 // minimal traffic, unlikely to alert
	NoiseMedium NoiseLevel = 2 // detectable by IDS/SOC
	NoiseHigh   NoiseLevel = 3 // loud, likely to trigger alerts
)

func (n NoiseLevel) String() string {
	switch n {
	case NoiseNone:
		return "NONE"
	case NoiseLow:
		return "LOW"
	case NoiseMedium:
		return "MEDIUM"
	case NoiseHigh:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// ModuleInfo describes the noise profile of a module.
type ModuleInfo struct {
	Level  NoiseLevel
	Reason string
}

// ModuleNoise maps module keys to their noise characteristics.
var ModuleNoise = map[string]ModuleInfo{
	"scanner":        {NoiseHigh, "SYN scan sends thousands of packets per host"},
	"osint":          {NoiseNone, "passive public data sources — no target contact"},
	"web_recon":      {NoiseLow, "HTTP requests to target web server"},
	"mitm":           {NoiseHigh, "ARP poisoning detectable on managed switches"},
	"sniff":          {NoiseLow, "passive packet capture — no packet injection"},
	"phishing":       {NoiseMedium, "HTTP server started, link delivered to target"},
	"ghost_hub":      {NoiseMedium, "periodic HTTP beacon traffic to C2"},
	"payloads":       {NoiseNone, "local generation — no target contact"},
	"crypt_keeper":   {NoiseNone, "local encryption — no target contact"},
	"msf_engine":     {NoiseHigh, "active exploitation, noisy vulnerability probes"},
	"looter":         {NoiseMedium, "SSH session with enumeration commands"},
	"credops":        {NoiseHigh, "credential testing = multiple auth attempts — lockout risk; hash cracking = local only"},
	"persistence":    {NoiseMedium, "file writes and service/registry modifications"},
	"ad_ops":         {NoiseMedium, "LDAP queries and Kerberos ticket requests"},
	"ai_assist":      {NoiseNone, "local Ollama inference — no target contact"},
	"cloud_ops":      {NoiseMedium, "IMDS metadata requests and cloud API calls"},
	"purple_team":    {NoiseNone, "detection rule generation only — local"},
	"god_mode":       {NoiseHigh, "automated full campaign — very noisy by design"},
	"auditor":        {NoiseNone, "local capability checks only"},
	"wifi_monitor":   {NoiseLow, "interface mode change — no RF transmission"},
	"wifi_scan":      {NoiseLow, "passive channel hopping — read-only"},
	"wifi_deauth":    {NoiseHigh, "802.11 deauth frames — trivially detected"},
	"wifi_handshake": {NoiseMedium, "deauth trigger + passive handshake capture"},
	"wifi_crack":     {NoiseNone, "local dictionary attack against pcap file"},
	"wifi_eviltwin":  {NoiseHigh, "rogue AP beacon flood — visible to all nearby devices"},
}

// OpRecord records one module execution for scoring.
type OpRecord struct {
	ModuleKey string
	Level     NoiseLevel
	Reason    string
}

// Score calculates OPSEC score (0–100, higher = quieter) for a set of module keys.
// Returns: score, label (QUIET/MODERATE/LOUD/CRITICAL), and per-module breakdown lines.
func Score(moduleKeys []string) (score int, label string, breakdown []OpRecord) {
	seen := map[string]bool{}
	total := 0

	for _, key := range moduleKeys {
		if seen[key] {
			continue
		}
		seen[key] = true
		info, ok := ModuleNoise[key]
		if !ok {
			continue
		}
		total += int(info.Level)
		breakdown = append(breakdown, OpRecord{
			ModuleKey: key,
			Level:     info.Level,
			Reason:    info.Reason,
		})
	}

	if len(breakdown) == 0 {
		return 100, "CLEAN", nil
	}

	maxNoise := len(breakdown) * int(NoiseHigh)
	score = 100 - (total*100)/maxNoise

	switch {
	case score >= 80:
		label = "QUIET"
	case score >= 60:
		label = "MODERATE"
	case score >= 35:
		label = "LOUD"
	default:
		label = "CRITICAL"
	}

	return score, label, breakdown
}

// NoiseIcon returns a short text label for a noise level.
func NoiseIcon(n NoiseLevel) string {
	switch n {
	case NoiseNone:
		return "NONE"
	case NoiseLow:
		return "LOW"
	case NoiseMedium:
		return "MED"
	case NoiseHigh:
		return "HIGH"
	default:
		return "?"
	}
}

// LabelColor returns an ANSI color code for a score label.
func LabelColor(label string) string {
	switch label {
	case "QUIET":
		return "\033[32m" // green
	case "MODERATE":
		return "\033[33m" // yellow
	case "LOUD":
		return "\033[31m" // red
	case "CRITICAL":
		return "\033[35m" // magenta
	default:
		return "\033[0m"
	}
}

// ScoreBar renders a 20-char ASCII progress bar for a score 0–100.
func ScoreBar(score int) string {
	const width = 20
	filled := score * width / 100
	if filled > width {
		filled = width
	}
	bar := ""
	for i := 0; i < width; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	return fmt.Sprintf("[%s] %d/100", bar, score)
}
