```
██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗
██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗
██║  ██║███████║██║   ██║██║   ██║██║██║  ██║
██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║
██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝
╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝
```

<p align="center">
  <b>ghost in the net · operator-grade red team engagement platform</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-00e5ff?style=flat-square&labelColor=0d0d0d">
  <img src="https://img.shields.io/badge/language-Go-00ADD8?style=flat-square&labelColor=0d0d0d&logo=go">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-888888?style=flat-square&labelColor=0d0d0d">
  <img src="https://img.shields.io/badge/license-MIT-444444?style=flat-square&labelColor=0d0d0d">
  <img src="https://img.shields.io/badge/for-authorized%20testing%20only-ff3d3d?style=flat-square&labelColor=0d0d0d">
</p>

---

Davoid is a **single-binary red team engagement platform** built entirely in Go. It combines a full suite of offensive security modules with a first-class **engagement management system** — so every operation you run is tracked, every finding is logged, and every engagement ends with a professional report you can hand to a client.

No Python. No venv. No dependency hell. One binary.

---

## Why Davoid

Most offensive tools do one thing well. You end up juggling a terminal full of separate tools with no shared context — Nmap output in one window, Responder in another, manual notes in a text file. Davoid fixes that.

- **Single binary.** One `davoid` executable. Cross-compile for any platform. Drop it anywhere, run it.
- **Engagement-first.** Start every op with `davoid new`, and every module you run logs its findings to that engagement automatically.
- **Built to be shown.** The TUI is designed to be screenshot-worthy. The reports are designed to be client-ready.
- **20 native Go modules.** Recon, MITM, C2, post-exploitation, AD, AI — all compiled in, no subprocess spawning.

---

## Installation

### Binary (recommended)

Download the latest release for your platform from the [releases page](https://github.com/BryanParreira/Davoid/releases).

```bash
# Linux x86_64
curl -Lo davoid https://github.com/BryanParreira/Davoid/releases/latest/download/davoid-linux-amd64
chmod +x davoid
sudo mv davoid /usr/local/bin/

davoid version
```

### Build from source

Requires Go 1.24+.

```bash
git clone https://github.com/BryanParreira/Davoid.git
cd Davoid
go build -o davoid ./cmd/davoid/
sudo mv davoid /usr/local/bin/
```

### Full install (auto-installs Go + optional tools)

```bash
git clone https://github.com/BryanParreira/Davoid.git
cd Davoid
sudo bash install.sh
```

> Root is required for raw socket operations (ARP poisoning, packet capture).

---

## Quick Start

```bash
# Start a new engagement
davoid new "Client Corp Internal" --target "10.0.0.0/8" --scope "Internal network, no OT systems"

# Open the TUI
sudo davoid

# Log a finding from the command line
davoid finding --title "Kerberoastable SPN found" --severity HIGH --module ad_ops --target "svc_backup@corp.local"

# Generate a report
davoid report
```

---

## The Engagement System

This is what makes Davoid different.

Every operation you run is tied to an **engagement** — a named context with a target scope, timeline, and finding log. When you finish, `davoid report` produces a structured Markdown report (convert to PDF with `pandoc`).

```
davoid new "Acme Corp - External"   →  creates engagement, sets it active
davoid list                         →  shows all engagements with finding counts
davoid report                       →  generates report for active engagement
davoid report <id>                  →  report for a specific engagement
```

Findings are stored in `~/.davoid/engagements.db` (SQLite). Reports go to the current directory.

---

## Modules

| Module | Category | Description |
|---|---|---|
| **Net-Mapper** | Intelligence & OSINT | Nmap orchestration with live CVE lookup via NVD API |
| **Live Interceptor** | Intelligence & OSINT | Real-time packet capture (tcpdump), DNS tracking, credential extraction |
| **Holmes Engine** | Intelligence & OSINT | Username OSINT across 14 platforms, subdomain brute, IP intel, Wayback |
| **Web Recon** | Intelligence & OSINT | Security header audit, path fuzzing, sensitive data extraction, InternetDB |
| **MITM Engine** | Offensive Operations | ARP poisoning + IP forwarding (Linux/macOS) |
| **Phantom Cloner** | Offensive Operations | Dynamic page cloning + credential harvesting portal |
| **GHOST-HUB C2** | Offensive Operations | AES-GCM encrypted async HTTP command & control server |
| **Shell Forge** | Post-Exploitation | Payload generator: Bash, Python, PHP, Perl, PowerShell, msfvenom |
| **Crypt-Keeper** | Post-Exploitation | AES-GCM payload encryption + self-decrypting loader stubs |
| **Persistence Engine** | Post-Exploitation | systemd / crontab (Linux), LaunchAgent (macOS), registry / schtasks (Windows) |
| **Hash Cracker** | Post-Exploitation | Multi-threaded goroutine dictionary attack — MD5, SHA1, SHA256, SHA512, NTLM |
| **Looter** | Post-Exploitation | SSH-based PrivEsc enumeration, SUID/sudo/cron, SSH key harvest |
| **Credential Tester** | Post-Exploitation | Credential re-use testing across SSH, FTP, HTTP Basic Auth |
| **AD Ops** | Active Directory | LDAP enum, AS-REP roasting, Kerberoasting, password spray, BloodHound export |
| **Metasploit Bridge** | Advanced | MSF JSONRPC client — session management, exploit execution, msfvenom |
| **AI Console** | Advanced | Ollama ReAct agent with 10 built-in pentest tools |
| **Cloud Ops** | Advanced | AWS/Azure/GCP IMDS credential extraction, S3 bucket enum, container escape |
| **Purple Team** | Advanced | 15 MITRE ATT&CK TTPs, Splunk SPL + Sigma rules, Navigator JSON export |
| **Setup Auditor** | System | Tool availability, interface enum, local port probe, writability checks |
| **God Mode** | System | Autonomous campaign: Nmap → AI analysis → vuln correlation → report |

---

## Architecture

Davoid is pure Go — all 20 modules are native Go packages compiled directly into the binary.

```
cmd/davoid/          CLI entry point (Cobra)
internal/
  tui/               Bubble Tea TUI — menu, views, styles
  engagement/        Engagement & finding management (SQLite)
  runner/            Module registry + dispatcher
  modules/
    ui/              Shared terminal I/O helpers (prompts, tables, colors)
    scanner/         Nmap + NVD CVE
    osint/           OSINT suite
    sniff/           Packet capture
    webrecon/        Web auditor
    mitm/            ARP poisoning
    phishing/        Credential harvester
    ghosthub/        C2 server
    payloads/        Shell generator
    cryptkeeper/     AES encryption
    persistence/     Persistence installs
    bruteforce/      Hash cracker
    looter/          SSH post-exploit
    credtester/      Credential tester
    adops/           Active Directory
    msfengine/       Metasploit RPC
    aiassist/        Ollama AI agent
    cloudops/        Cloud recon
    purpleteam/      ATT&CK mapper
    auditor/         System checker
    godmode/         Autonomous campaign
```

---

## CLI Reference

```
davoid                          Launch interactive TUI
davoid new <name>               Start a new engagement
  --target <ip/cidr/domain>
  --scope  <description>
davoid list                     List all engagements
davoid report [id]              Generate Markdown report
davoid finding                  Log a finding to active engagement
  --title    <title>
  --severity CRITICAL|HIGH|MEDIUM|INFO
  --module   <module-name>
  --target   <host>
  --desc     <description>
  --evidence <raw evidence>
davoid modules                  List all available modules
davoid version                  Print version
```

---

## Optional External Tools

Some modules call external tools when available. None are required to run Davoid — they enhance specific modules:

| Tool | Module | Install |
|------|---------|---------|
| `nmap` | Net-Mapper, God Mode | `brew install nmap` / `apt install nmap` |
| `tcpdump` | Live Interceptor | `brew install tcpdump` / `apt install tcpdump` |
| `arpspoof` | MITM Engine | `brew install dsniff` / `apt install dsniff` |
| `msfvenom` | Metasploit Bridge, Shell Forge | [metasploit.com](https://metasploit.com) |
| `ollama` | AI Console, God Mode | [ollama.ai](https://ollama.ai) |

---

## Legal

Davoid is for **authorized penetration testing and security research only**. You must have written permission before testing any system you do not own. The author assumes no liability for misuse.

---

## License

MIT © [BryanParreira](https://github.com/BryanParreira)
