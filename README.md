```
██████╗  █████╗ ██╗   ██╗ ██████╗ ██╗██████╗
██╔══██╗██╔══██╗██║   ██║██╔═══██╗██║██╔══██╗
██║  ██║███████║██║   ██║██║   ██║██║██║  ██║
██║  ██║██╔══██║╚██╗ ██╔╝██║   ██║██║██║  ██║
██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝██║██████╔╝
╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚═╝╚═════╝
```

<p align="center"><b>ghost in the net · operator-grade red team engagement platform</b></p>

<p align="center">
  <a href="https://github.com/BryanParreira/Davoid/releases/latest"><img src="https://img.shields.io/github/v/release/BryanParreira/Davoid?style=flat-square&labelColor=0d0d0d&color=00e5ff&label=release"></a>
  <a href="https://github.com/BryanParreira/Davoid/actions/workflows/release.yml"><img src="https://img.shields.io/github/actions/workflow/status/BryanParreira/Davoid/release.yml?style=flat-square&labelColor=0d0d0d&label=build"></a>
  <a href="https://github.com/BryanParreira/Davoid/pkgs/container/davoid"><img src="https://img.shields.io/badge/docker-ghcr.io-2496ED?style=flat-square&labelColor=0d0d0d&logo=docker"></a>
  <img src="https://img.shields.io/badge/language-Go-00ADD8?style=flat-square&labelColor=0d0d0d&logo=go">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-888888?style=flat-square&labelColor=0d0d0d">
  <img src="https://img.shields.io/badge/license-MIT-444444?style=flat-square&labelColor=0d0d0d">
  <img src="https://img.shields.io/badge/for-authorized%20testing%20only-ff3d3d?style=flat-square&labelColor=0d0d0d">
</p>

---

Davoid is a **single-binary red team engagement platform** built entirely in Go. 20 offensive modules — recon, MITM, C2, post-exploitation, AD, AI — all compiled into one executable with a built-in engagement management system that tracks every finding and produces client-ready reports.

No Python. No venv. No dependency hell. One binary.

---

## Why Davoid

Most offensive tools do one thing. You end up juggling a terminal full of separate tools with no shared context — Nmap in one window, Responder in another, manual notes in a text file. Davoid fixes that.

- **Single binary.** One `davoid` executable. Cross-compile for any platform. Drop it anywhere, run it.
- **Engagement-first.** Start every op with `davoid new` — every module you run logs findings to that engagement automatically.
- **Client-ready reports.** `davoid report` produces structured Markdown (pipe through `pandoc` for PDF).
- **20 native Go modules.** No subprocess spawning for the core logic — all compiled in.

---

## Installation

The only requirement is [Docker](https://docs.docker.com/get-docker/). No Go, no Python, no system dependencies.

### 1. Clone the repo

```bash
git clone https://github.com/BryanParreira/Davoid.git
cd Davoid
```

### 2. Pick a profile and run

**Safe mode** — OSINT, web recon, AI console, phishing, auditor (no raw network access required):

```bash
docker compose --profile safe up
```

**Full mode** — every module including sniff, mitm, scanner (uses host network + packet capture):

```bash
docker compose --profile full up
```

That's it. Davoid opens in your terminal. Your engagement database and reports persist automatically via Docker volumes — nothing is lost when the container stops.

> **Which profile should I use?**
> Start with `safe`. Switch to `full` only when you need live packet capture or ARP poisoning — those require raw socket access to the host network.

---

## Quick Start

```bash
# 1. Start Davoid
git clone https://github.com/BryanParreira/Davoid.git && cd Davoid
docker compose --profile safe up

# 2. Inside the TUI — navigate with arrow keys, Enter to launch a module
#    Or run a module directly from a second terminal:
docker compose --profile safe run davoid-safe davoid run auditor
docker compose --profile safe run davoid-safe davoid modules
docker compose --profile safe run davoid-safe davoid report
```

---

## The Engagement System

Every module you run is tied to an **engagement** — a named context with a target scope, timeline, and finding log. All findings are stored in `~/.davoid/engagements.db` (SQLite). Reports go to the current directory.

```
davoid new "Acme Corp - External"    →  create engagement, set active
davoid list                          →  all engagements with finding counts
davoid report                        →  Markdown report for active engagement
davoid report <id>                   →  report for specific engagement
```

Log a finding from the CLI:

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

## Modules

| Module | Key | Category | Description |
|--------|-----|----------|-------------|
| **Net-Mapper** | `scanner` | Intelligence & OSINT | Nmap orchestration + live CVE lookup via NVD API |
| **Live Interceptor** | `sniff` | Intelligence & OSINT | Real-time packet capture, DNS tracking, credential extraction |
| **Holmes Engine** | `osint` | Intelligence & OSINT | Username OSINT across 14 platforms, subdomain brute, IP intel |
| **Web Recon** | `web_recon` | Intelligence & OSINT | Security header audit, path fuzzing, sensitive data extraction |
| **MITM Engine** | `mitm` | Offensive Operations | ARP poisoning + IP forwarding (Linux/macOS) |
| **Phantom Cloner** | `phishing` | Offensive Operations | Dynamic page cloning + credential harvesting portal |
| **GHOST-HUB C2** | `ghost_hub` | Offensive Operations | AES-GCM encrypted async HTTP command & control server |
| **Shell Forge** | `payloads` | Post-Exploitation | Payload generator: Bash, Python, PHP, Perl, PowerShell, msfvenom |
| **Crypt-Keeper** | `crypt_keeper` | Post-Exploitation | AES-GCM payload encryption + self-decrypting loader stubs |
| **Persistence Engine** | `persistence` | Post-Exploitation | systemd / cron (Linux), LaunchAgent (macOS), registry / schtasks (Windows) |
| **Hash Cracker** | `bruteforce` | Post-Exploitation | Multi-threaded goroutine dictionary attack — MD5, SHA1, SHA256, NTLM |
| **Looter** | `looter` | Post-Exploitation | SSH-based PrivEsc enum, SUID/sudo/cron, SSH key harvest |
| **Credential Tester** | `cred_tester` | Post-Exploitation | Credential re-use across SSH, FTP, HTTP Basic Auth |
| **AD Ops** | `ad_ops` | Active Directory | LDAP enum, AS-REP roasting, Kerberoasting, spray, BloodHound export |
| **Metasploit Bridge** | `msf_engine` | Advanced | MSF JSONRPC client — session management, exploit execution |
| **AI Console** | `ai_assist` | Advanced | Ollama ReAct agent with 10 built-in pentest tools |
| **Cloud Ops** | `cloud_ops` | Advanced | AWS/Azure/GCP IMDS cred extraction, S3 enum, container escape |
| **Purple Team** | `purple_team` | Advanced | 15 MITRE ATT&CK TTPs, Splunk SPL + Sigma rules, Navigator export |
| **Setup Auditor** | `auditor` | System | Tool check, interface enum, port probe, writability audit |
| **God Mode** | `god_mode` | System | Autonomous campaign: Nmap → AI analysis → vuln correlation → report |

Run any module directly without the TUI:

```bash
davoid run <key>     # e.g. davoid run ad_ops
```

---

## Optional External Tools

Some modules call external tools when present. None are required to run Davoid — they enhance specific modules:

| Tool | Used by | Install |
|------|---------|---------|
| `nmap` | Net-Mapper, God Mode | `brew install nmap` / `apt install nmap` |
| `tcpdump` | Live Interceptor | `brew install tcpdump` / `apt install tcpdump` |
| `arpspoof` | MITM Engine | `brew install dsniff` / `apt install dsniff` |
| `msfvenom` | Metasploit Bridge, Shell Forge | [metasploit.com](https://metasploit.com) |
| `ollama` | AI Console, God Mode | [ollama.com](https://ollama.com) — run `ollama pull llama3` after install |

Linux users: run `davoid run auditor` after install — it sets `CAP_NET_RAW` so sniff/mitm work without sudo.

---

## Architecture

```
cmd/davoid/          CLI entry point (Cobra)
internal/
  tui/               Bubble Tea TUI — menu, views, styles
  engagement/        Engagement & finding management (SQLite)
  runner/            Module registry + dispatcher
  modules/
    ui/              Shared terminal I/O (prompts, tables, colors)
    scanner/         Nmap + NVD CVE
    sniff/           Packet capture
    osint/           OSINT suite
    webrecon/        Web auditor
    mitm/            ARP poisoning
    phishing/        Credential harvester
    ghosthub/        C2 server
    payloads/        Payload generator
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
davoid                           Launch interactive TUI
davoid new <name>                Start a new engagement
  --target <ip/cidr/domain>
  --scope  <description>
davoid list                      List all engagements
davoid report [id]               Generate Markdown report
davoid finding                   Log a finding manually
  --title    <title>
  --severity CRITICAL|HIGH|MEDIUM|INFO
  --module   <module-key>
  --target   <host>
  --desc     <description>
  --evidence <raw evidence>
davoid run <module-key>          Run a module directly (no TUI)
davoid modules                   List all available modules
davoid version                   Print version
```

---

## Contributing

1. Fork the repo and create a feature branch
2. All modules live in `internal/modules/<name>/` — each exports a single `Run() error`
3. Register new modules in `internal/runner/runner.go` (Registry + RunModule switch)
4. Run `go build ./...` and `go vet ./...` before opening a PR

---

## Legal

Davoid is for **authorized penetration testing and security research only**. You must have written permission before testing any system you do not own. The author assumes no liability for misuse.

---

## License

MIT © [BryanParreira](https://github.com/BryanParreira)
