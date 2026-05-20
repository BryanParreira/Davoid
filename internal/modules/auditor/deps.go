package auditor

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Dependency describes a required external tool and how to install it per package manager.
type Dependency struct {
	Name     string // display name
	Cmd      string // binary to look up
	Purpose  string // one-line description
	Brew     string // macOS homebrew
	Apt      string // Debian/Ubuntu/Kali
	Pacman   string // Arch/Manjaro
	Dnf      string // Fedora/RHEL/CentOS
	URL      string // fallback / no package
	LinuxOnly bool  // suppress on macOS
}

// AllDeps returns the full ordered list of Davoid tool dependencies.
func AllDeps() []Dependency {
	return []Dependency{
		// Core
		{"nmap", "nmap", "Network scanner", "brew install nmap", "apt install nmap", "pacman -S nmap", "dnf install nmap", "", false},
		{"tcpdump", "tcpdump", "Packet capture", "brew install tcpdump", "apt install tcpdump", "pacman -S tcpdump", "dnf install tcpdump", "", false},
		{"curl", "curl", "HTTP client", "brew install curl", "apt install curl", "pacman -S curl", "dnf install curl", "", false},
		{"git", "git", "Version control", "brew install git", "apt install git", "pacman -S git", "dnf install git", "", false},
		{"ssh", "ssh", "Secure shell client", "(built-in)", "apt install openssh-client", "pacman -S openssh", "dnf install openssh", "", false},
		{"nc (netcat)", "nc", "TCP listener / reverse shells", "brew install ncat", "apt install netcat-openbsd", "pacman -S openbsd-netcat", "dnf install nmap-ncat", "", false},
		{"dig", "dig", "DNS lookup", "brew install bind", "apt install dnsutils", "pacman -S bind-tools", "dnf install bind-utils", "", false},
		{"whois", "whois", "Domain WHOIS", "brew install whois", "apt install whois", "pacman -S whois", "dnf install whois", "", false},
		// Post-exploitation / cracking
		{"arpspoof", "arpspoof", "ARP poisoning (MITM)", "brew install dsniff", "apt install dsniff", "pacman -S dsniff", "dnf install dsniff", "", false},
		{"john", "john", "Password cracking", "brew install john-jumbo", "apt install john", "pacman -S john", "dnf install john", "", false},
		{"hashcat", "hashcat", "GPU hash cracking", "brew install hashcat", "apt install hashcat", "pacman -S hashcat", "dnf install hashcat", "", false},
		// Metasploit
		{"msfconsole", "msfconsole", "Metasploit framework", "", "", "", "", "https://metasploit.com/download", false},
		{"msfvenom", "msfvenom", "Payload generator (MSF)", "", "", "", "", "included with Metasploit", false},
		// WiFi (Linux only — these tools require kernel drivers & monitor mode)
		{"airmon-ng", "airmon-ng", "Monitor mode management", "", "apt install aircrack-ng", "pacman -S aircrack-ng", "dnf install aircrack-ng", "", true},
		{"airodump-ng", "airodump-ng", "WiFi network scanner", "", "apt install aircrack-ng", "pacman -S aircrack-ng", "dnf install aircrack-ng", "", true},
		{"aireplay-ng", "aireplay-ng", "Deauth / injection", "", "apt install aircrack-ng", "pacman -S aircrack-ng", "dnf install aircrack-ng", "", true},
		{"aircrack-ng", "aircrack-ng", "WPA handshake cracker", "", "apt install aircrack-ng", "pacman -S aircrack-ng", "dnf install aircrack-ng", "", true},
		{"hostapd", "hostapd", "Evil twin / rogue AP", "", "apt install hostapd", "pacman -S hostapd", "dnf install hostapd", "", true},
		{"dnsmasq", "dnsmasq", "DHCP for evil twin", "brew install dnsmasq", "apt install dnsmasq", "pacman -S dnsmasq", "dnf install dnsmasq", "", false},
		// Reporting / AI
		{"pandoc", "pandoc", "PDF report generation", "brew install pandoc", "apt install pandoc", "pacman -S pandoc", "dnf install pandoc", "", false},
		{"ollama", "ollama", "Local AI (AI console / reports)", "", "", "", "", "https://ollama.com", false},
	}
}

// PkgMgr represents the detected package manager.
type PkgMgr string

const (
	PkgBrew   PkgMgr = "brew"
	PkgApt    PkgMgr = "apt"
	PkgPacman PkgMgr = "pacman"
	PkgDnf    PkgMgr = "dnf"
	PkgUnknown PkgMgr = ""
)

// DetectPkgMgr returns the package manager for the current OS/distro.
func DetectPkgMgr() PkgMgr {
	if runtime.GOOS == "darwin" {
		return PkgBrew
	}
	// Parse /etc/os-release for distro hints first
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "arch") || strings.Contains(content, "manjaro") || strings.Contains(content, "endeavour") {
			return PkgPacman
		}
		if strings.Contains(content, "fedora") || strings.Contains(content, "rhel") ||
			strings.Contains(content, "centos") || strings.Contains(content, "rocky") || strings.Contains(content, "alma") {
			return PkgDnf
		}
		// kali, ubuntu, debian, parrot, etc. all use apt
		if strings.Contains(content, "ubuntu") || strings.Contains(content, "debian") ||
			strings.Contains(content, "kali") || strings.Contains(content, "parrot") || strings.Contains(content, "mint") {
			return PkgApt
		}
	}
	// Fallback: probe which binary is available
	for _, pm := range []struct {
		bin string
		mgr PkgMgr
	}{
		{"apt", PkgApt},
		{"pacman", PkgPacman},
		{"dnf", PkgDnf},
	} {
		if _, err := exec.LookPath(pm.bin); err == nil {
			return pm.mgr
		}
	}
	return PkgUnknown
}

// InstallCmd returns the install command for a dependency on the current system.
func InstallCmd(d Dependency, pm PkgMgr) string {
	switch pm {
	case PkgBrew:
		if d.Brew != "" {
			return d.Brew
		}
	case PkgApt:
		if d.Apt != "" {
			return d.Apt
		}
	case PkgPacman:
		if d.Pacman != "" {
			return d.Pacman
		}
	case PkgDnf:
		if d.Dnf != "" {
			return d.Dnf
		}
	}
	if d.URL != "" {
		return d.URL
	}
	return "—"
}
