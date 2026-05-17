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

Davoid is a **single-binary red team engagement platform** built in Go. It combines a full suite of offensive security modules with a first-class **engagement management system** — so every operation you run is tracked, every finding is logged, and every engagement ends with a professional report you can hand to a client.

Think of it as the tool that sits between your recon phase and your final report, and handles everything in between.

---

## Why Davoid

Most offensive tools do one thing well. You end up juggling a terminal full of separate tools with no shared context — Nmap output in one window, Responder in another, manual notes in a text file. Davoid fixes that.

- **Single binary.** One `davoid` executable, no Python venv, no dependency hell. Cross-compile for any platform.
- **Engagement-first.** Start every op with `davoid new`, and every module you run logs its findings to that engagement automatically.
- **Built to be shown.** The TUI is designed to be screenshot-worthy. The reports are designed to be client-ready.
- **Modular by design.** 20+ built-in modules across recon, MITM, C2, post-exploitation, and AD. Plugin architecture for your own tools.

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

### Full install (Python modules + Go binary)

```bash
git clone https://github.com/BryanParreira/Davoid.git
cd Davoid
sudo bash install.sh
```

> Root is required for raw socket operations (Scapy, ARP poisoning, packet capture).

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

Findings are stored in `~/.davoid/engagements.db` (SQLite). Reports go to `~/.davoid/reports/`.

---

## Modules

| Module | Category | Description |
|---|---|---|
| **Net-Mapper** | Intelligence & OSINT | Nmap orchestration with live CVE lookup via NVD API |
| **Live Interceptor** | Intelligence & OSINT | Real-time packet capture, DNS tracking, credential extraction |
| **Holmes Engine** | Intelligence & OSINT | Username OSINT across 14 platforms, phone intel, subdomain brute |
| **Web Recon** | Intelligence & OSINT | robots.txt, domain reputation, Google Dorks, CT logs, Shodan/InternetDB |
| **MITM Engine** | Offensive | ARP poisoning + automatic IP forwarding (Linux/macOS) |
| **Phantom Cloner** | Offensive | Dynamic page cloning with JS form-hooking for credential harvesting |
| **DNS Spoofer** | Offensive | Real-time DNS hijacking → custom phishing portal |
| **GHOST-HUB C2** | Offensive | AES-encrypted async HTTP command & control server |
| **Shell Forge** | Post-Exploitation | Payload generator: Bash, Python, PHP, Ruby, PowerShell, MSF |
| **Crypt-Keeper** | Post-Exploitation | Payload encryption + self-decrypting AES loaders |
| **Persistence Engine** | Post-Exploitation | systemd / crontab (Linux), LaunchAgent (macOS), registry (Windows) |
| **Hash Cracker** | Post-Exploitation | Multi-threaded dictionary/brute — MD5, SHA256, NTLM |
| **Looter** | Post-Exploitation | Privilege escalation discovery, SSH key harvest |
| **Credential Tester** | Post-Exploitation | Credential re-use testing across SSH, FTP, HTTP |
| **AD Ops** | Active Directory | LDAP enum, Kerberoasting, DCSync detection, BloodHound export |
| **Metasploit Bridge** | Advanced | MSF RPC client — auto exploit selection & execution |
| **AI Console** | Advanced | LangChain + Ollama AI-assisted attack strategy & payload mutation |

---

## Architecture

Davoid v2 is built in Go. The TUI uses [Bubble Tea](https://github.com/charmbracelet/bubbletea) + [Lip Gloss](https://github.com/charmbracelet/lipgloss). The engagement database is SQLite with no external dependencies.

The existing Python modules run as subprocesses — they're not going away, they're just getting a better driver. Modules will be ported to native Go incrementally.

```
cmd/davoid/          CLI entry point (cobra)
internal/
  tui/               Bubble Tea TUI — menu, views, styles
  engagement/        Engagement & finding management (SQLite)
  runner/            Module registry + Python subprocess bridge
modules/             Python security modules (20+)
core/                Python framework (database, context, UI)
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
davoid --legacy                 Launch Python TUI (legacy mode)
```

---

## Legal

Davoid is for **authorized penetration testing and security research only**. You must have written permission before testing any system you do not own. The author assumes no liability for misuse. Violations of the Computer Fraud and Abuse Act (CFAA) or equivalent law in your jurisdiction are your responsibility.

---

## License

MIT © [BryanParreira](https://github.com/BryanParreira)
