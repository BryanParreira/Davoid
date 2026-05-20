<div align="center">

```
██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗
██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗
██║  ██║███████║██║   ██║██║   ██║██║██║  ██║
██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║
██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝
╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝
```

**ghost in the net · operator-grade red team engagement platform**

[![Release](https://img.shields.io/github/v/release/BryanParreira/Davoid?style=flat-square&labelColor=0d0d0d&color=00e5ff&label=release)](https://github.com/BryanParreira/Davoid/releases/latest)
[![Build](https://img.shields.io/github/actions/workflow/status/BryanParreira/Davoid/release.yml?style=flat-square&labelColor=0d0d0d&label=build)](https://github.com/BryanParreira/Davoid/actions/workflows/release.yml)
[![Go](https://img.shields.io/badge/language-Go-00ADD8?style=flat-square&labelColor=0d0d0d&logo=go)](https://go.dev)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-888888?style=flat-square&labelColor=0d0d0d)](https://github.com/BryanParreira/Davoid/releases)
[![License](https://img.shields.io/badge/license-MIT-444444?style=flat-square&labelColor=0d0d0d)](LICENSE)
[![Authorized Use Only](https://img.shields.io/badge/for-authorized%20testing%20only-ff3d3d?style=flat-square&labelColor=0d0d0d)](#legal)

</div>

---

Davoid is a **single-binary red team engagement platform** built entirely in Go. 26 offensive modules across 8 attack categories — recon, network attacks, social engineering, exploitation, post-exploitation, Active Directory, WiFi, and advanced — all compiled into one executable with a built-in engagement system that tracks every finding, harvested credential, and discovered host, then produces client-ready reports.

**No Python. No venv. No dependency hell. One binary.**

---

## Features

- **Engagement-first workflow** — every module auto-logs findings, credentials, and hosts to the active engagement
- **Credential vault** — phishing/sniff/looter harvest creds → vault stores them → cred_tester loads and reuses them automatically
- **Target inventory** — scanner discovers hosts → saved to SQLite → other modules offer quick-select from inventory
- **Network map** — ASCII topology of discovered hosts grouped by subnet, auto-rendered after every scan
- **Full WiFi suite** — monitor mode, airodump scan, deauth, WPA handshake capture, aircrack dictionary attack, evil twin AP
- **Reverse shell catcher** — built-in TCP listener, auto-prints one-liners for target, logs connections as findings
- **Engagement timeline** — chronological view of every finding + note merged in time order
- **Client-ready reports** — structured Markdown output, PDF via pandoc, with exec summary and full evidence
- **Self-updating** — press `U` in TUI to pull and install the latest release automatically
- **VPN awareness** — detects active tunnels (tun/tap/wg/proxychains) and shows them in the header
- **Single binary** — cross-compiled for Linux/macOS amd64/arm64, SHA256 verified on install

---

## Installation

### One-liner (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/BryanParreira/Davoid/main/install.sh | bash
```

Auto-detects OS + architecture, downloads the correct binary, verifies SHA256, installs to PATH.

### Manual download

Grab the binary for your platform from the [latest release](https://github.com/BryanParreira/Davoid/releases/latest):

| Platform | Download |
|----------|----------|
| macOS Apple Silicon | [davoid-darwin-arm64](https://github.com/BryanParreira/Davoid/releases/latest/download/davoid-darwin-arm64) |
| macOS Intel | [davoid-darwin-amd64](https://github.com/BryanParreira/Davoid/releases/latest/download/davoid-darwin-amd64) |
| Linux x86_64 | [davoid-linux-amd64](https://github.com/BryanParreira/Davoid/releases/latest/download/davoid-linux-amd64) |
| Linux ARM64 | [davoid-linux-arm64](https://github.com/BryanParreira/Davoid/releases/latest/download/davoid-linux-arm64) |

Then:

```bash
chmod +x davoid-*

# macOS Apple Silicon
sudo mv davoid-darwin-arm64 /opt/homebrew/bin/davoid

# macOS Intel / Linux
sudo mv davoid-* /usr/local/bin/davoid
```

Then just run:

```bash
davoid
```

**Check your dependencies after installing:**

```bash
davoid doctor
```

### Uninstall

Remove the binary:

```bash
# macOS Apple Silicon
rm /opt/homebrew/bin/davoid

# macOS Intel / Linux
sudo rm /usr/local/bin/davoid
```

Remove all data (engagements, findings, credentials, reports):

```bash
rm -rf ~/.davoid
```

That's everything. No system services, no background processes, nothing else left behind.

---

## Quick Start

```bash
# Launch the TUI
davoid

# Start a new engagement from the CLI
davoid new "Acme Corp — External" --target 10.0.0.0/8 --scope "10.0.0.0/8, acme.com"

# Run any module directly (no TUI)
davoid run scanner
davoid run wifi_deauth
davoid run catcher

# Engagement management
davoid list                  # all engagements with finding counts
davoid report                # Markdown report for active engagement

# Check tool dependencies
davoid doctor
```

---

## Attack Categories

Modules are organized in kill-chain order. Press the corresponding number in the TUI.

### `[1]` Recon & OSINT

| Module | Key | Description |
|--------|-----|-------------|
| **Net-Mapper** | `scanner` | Nmap orchestration with live CVE lookup via NVD API. Saves all discovered hosts to target inventory. |
| **Holmes Engine** | `osint` | Username OSINT across 14 platforms, subdomain brute-force, phone intel. |
| **Web Recon** | `web_recon` | Security header audit, robots.txt scrape, Google Dorks, CT log enumeration. |

### `[2]` Network Attacks

| Module | Key | Description |
|--------|-----|-------------|
| **MITM Engine** | `mitm` | ARP poisoning + automatic IP forwarding on Linux/macOS. |
| **Live Interceptor** | `sniff` | Real-time traffic capture, DNS query tracking, cleartext credential extraction. |

### `[3]` Social Engineering

| Module | Key | Description |
|--------|-----|-------------|
| **Phantom Cloner** | `phishing` | Clones any login page, spins up a harvesting server, logs creds to vault + engagement. |
| **GHOST-HUB C2** | `ghost_hub` | AES-GCM encrypted async HTTP command & control server. |

### `[4]` Exploitation

| Module | Key | Description |
|--------|-----|-------------|
| **Shell Forge** | `payloads` | Multi-language reverse shell generator: Bash, Python, PHP, Perl, PowerShell, msfvenom. |
| **Crypt-Keeper** | `crypt_keeper` | AES-GCM payload encryption + self-decrypting loader stubs. |
| **Metasploit Bridge** | `msf_engine` | MSF JSONRPC client — session management, auto exploit selection. |
| **Shell Catcher** | `catcher` | TCP reverse shell listener. Auto-prints bash/python/nc one-liners. Logs connections as CRITICAL findings. |

### `[5]` Post-Exploitation

| Module | Key | Description |
|--------|-----|-------------|
| **Looter** | `looter` | SSH-based privesc enum: SUID, sudo, cron, world-writable paths, SSH key harvest. |
| **Credential Tester** | `cred_tester` | Credential re-use across SSH, FTP, HTTP Basic Auth. Loads from vault automatically. |
| **Hash Cracker** | `bruteforce` | Multi-threaded goroutine dictionary attack — MD5, SHA1, SHA256, NTLM. |
| **Persistence Engine** | `persistence` | systemd/crontab (Linux), LaunchAgent (macOS), registry/schtasks (Windows). |

### `[6]` Active Directory

| Module | Key | Description |
|--------|-----|-------------|
| **AD Ops** | `ad_ops` | LDAP enum, AS-REP roasting, Kerberoasting, password spray, BloodHound export. |

### `[7]` WiFi & Wireless

| Module | Key | Description |
|--------|-----|-------------|
| **Monitor Mode** | `wifi_monitor` | Toggle monitor mode on wireless interfaces (airmon-ng). |
| **WiFi Scanner** | `wifi_scan` | Discover nearby APs + clients, channels, encryption (airodump-ng). Results shared with other WiFi modules. |
| **Deauth Attack** | `wifi_deauth` | Broadcast or targeted IEEE 802.11 deauthentication frames (aireplay-ng). |
| **Handshake Capture** | `wifi_handshake` | Targeted airodump capture with automatic WPA handshake detection. |
| **WPA Cracker** | `wifi_crack` | Dictionary attack on captured handshake (aircrack-ng). Cracked PSK saved to vault. |
| **Evil Twin AP** | `wifi_eviltwin` | Rogue AP cloning a target SSID with DHCP (hostapd + dnsmasq). |

> WiFi modules share scan state — run **WiFi Scanner** first, then Deauth/Handshake/Evil Twin will offer discovered networks in a selection menu.

### `[8]` Advanced

| Module | Key | Description |
|--------|-----|-------------|
| **AI Console** | `ai_assist` | Ollama ReAct agent with 10 built-in pentest tools. |
| **Cloud Ops** | `cloud_ops` | AWS/Azure/GCP IMDS credential extraction, S3 enum, container escape. |
| **Purple Team** | `purple_team` | 15 MITRE ATT&CK TTPs, Splunk SPL + Sigma rule generation, Navigator export. |
| **God Mode** | `god_mode` | Autonomous campaign: Nmap → AI analysis → vuln correlation → report. |
| **Setup Auditor** | `auditor` | Pre-flight check: tool availability, interface capabilities, capability bits. |

---

## The Engagement System

Everything in Davoid ties to a named **engagement**. Start one before operating.

```
[E] Engagement Hub
  ├── [N] New Engagement        create and activate
  ├── [S] Switch                pick from all engagements
  ├── [F] Findings              all findings, scrollable
  ├── [L] Timeline              chronological findings + notes merged
  ├── [R] Generate Report       Markdown to ~/.davoid/reports/
  ├── [V] Credential Vault      all harvested credentials
  ├── [M] Target Map            ASCII network topology by subnet
  └── [O] Notes                 free-form engagement notes
```

**Data stored in** `~/.davoid/engagements.db` (SQLite):

```
engagements  →  name, target, scope, status, timestamps
  ├── findings     severity, module, target, title, evidence
  ├── credentials  source, host, username, secret, kind
  ├── hosts        ip, hostname, os, ports
  └── notes        free-form text
```

**Log a finding from the CLI:**

```bash
davoid finding \
  --title    "Kerberoastable SPN found" \
  --severity HIGH \
  --module   ad_ops \
  --target   "svc_backup@corp.local" \
  --desc     "SPN set on service account, ticket offline-crackable" \
  --evidence "GetUserSPNs output..."
```

---

## Credential Pipeline

Credentials flow automatically across modules — no manual copy-pasting.

```
phishing   ──┐
sniff      ──┤──▶  vault (SQLite)  ──▶  cred_tester
looter     ──┤                     ──▶  ad_ops
wifi_crack ──┘                     ──▶  report
```

1. Run **Phantom Cloner** → victim submits form → creds saved to vault
2. Run **Live Interceptor** → extracts cleartext creds → saved to vault
3. Run **Credential Tester** → `Load from vault? [y/N]` — one keypress loads all harvested pairs

---

## CLI Reference

```
davoid                            Launch interactive TUI
davoid new <name>                 Start a new engagement
  --target <ip/cidr/domain>
  --scope  <cidr,domain,...>
davoid list                       List all engagements with finding counts
davoid report [id]                Generate Markdown report
davoid finding                    Log a finding manually
  --title    <title>
  --severity CRITICAL|HIGH|MEDIUM|INFO
  --module   <module-key>
  --target   <host>
  --desc     <description>
  --evidence <raw evidence>
davoid run <module-key>           Run any module directly (no TUI)
davoid modules                    List all available modules
davoid doctor                     Check external tool dependencies
davoid version                    Print version
```

**TUI keyboard shortcuts:**

```
1–8         open attack category
E           engagement hub
C           campaign mode (guided kill chain)
U           install available update
↑/↓  j/k   navigate
enter        select
esc          back
ctrl+c       quit
```

---

## External Tool Dependencies

Davoid's core runs with zero external tools. Some modules call system tools when present:

| Tool | Module | Install |
|------|---------|---------|
| `nmap` | Net-Mapper, God Mode | `brew install nmap` / `apt install nmap` |
| `tcpdump` | Live Interceptor | `brew install tcpdump` / `apt install tcpdump` |
| `arpspoof` | MITM Engine | `apt install dsniff` |
| `airmon-ng` `airodump-ng` `aireplay-ng` `aircrack-ng` | WiFi suite | `apt install aircrack-ng` |
| `hostapd` | Evil Twin | `apt install hostapd` |
| `dnsmasq` | Evil Twin | `apt install dnsmasq` |
| `pandoc` | PDF reports | `brew install pandoc` / `apt install pandoc` |
| `msfconsole` | Metasploit Bridge | [metasploit.com](https://metasploit.com/download) |
| `ollama` | AI Console, God Mode | [ollama.com](https://ollama.com) |

Run `davoid doctor` to see which tools are installed and get install commands for missing ones.

> **Linux users:** Run `davoid run auditor` after install — it sets `CAP_NET_RAW` on the binary so sniff/mitm work without `sudo`.

---

## Architecture

```
cmd/davoid/              CLI entry point (Cobra commands)
internal/
  tui/                   Bubble Tea TUI — menu, views, styles
  engagement/            Engagement DB, findings, timeline, scope check (SQLite)
  runner/                Module registry + dispatcher
  vault/                 Credential vault — save, list, deduplicate
  targets/               Host inventory — upsert, network map rendering
  updater/               Self-update — GitHub API, SHA256 verify, atomic replace
  modules/
    ui/                  Shared terminal I/O — prompts, tables, spinners, colors
    scanner/             Nmap + NVD CVE lookup
    sniff/               tcpdump packet capture + credential extraction
    osint/               Username, phone, subdomain OSINT
    webrecon/            Web security audit
    mitm/                ARP poisoning
    phishing/            Credential harvesting portal
    ghosthub/            AES C2 server
    payloads/            Reverse shell generator
    catcher/             Reverse shell TCP listener
    cryptkeeper/         Payload encryption
    persistence/         Persistence installs
    bruteforce/          Hash dictionary cracker
    looter/              SSH post-exploitation
    credtester/          Credential re-use tester
    adops/               Active Directory attack suite
    wifi/                Full 802.11 wireless attack suite
    msfengine/           Metasploit RPC bridge
    aiassist/            Ollama AI agent
    cloudops/            Cloud attack modules
    purpleteam/          ATT&CK mapper + detection rules
    auditor/             System capability checker
    godmode/             Autonomous campaign engine
```

---

## Contributing

1. Fork and create a feature branch
2. All modules live in `internal/modules/<name>/` — each exports a single `Run() error`
3. Register in `internal/runner/runner.go` — add to `Registry` and `RunModule` switch
4. Run `go build ./...` and `go vet ./...` before opening a PR

---

## Legal

Davoid is intended for **authorized penetration testing, security research, and educational use only**. You must have explicit written permission before testing any system you do not own. The author assumes no liability for misuse. Use responsibly.

---

## License

MIT © [BryanParreira](https://github.com/BryanParreira)
