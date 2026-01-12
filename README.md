# DAVOID : GHOST IN THE NET

<p align="center">
  <img src="assets/mainframe.png" alt="Davoid Mainframe Header" width="800">
</p>

> **Professional-grade Terminal User Interface (TUI) toolkit for network discovery, security auditing, and ethical hacking.**

Davoid is a modular security engine built for speed, clarity, and deep-level network manipulation. It leverages **Scapy** for raw packet crafting and **Rich** to provide a high-contrast, modern terminal experience. Whether you are mapping a local subnet or performing authorized man-in-the-middle audits, Davoid provides a unified global interface for offensive and defensive security tasks.

---

## 🚀 One-Liner Installation

Deploy Davoid globally on your Mac or Linux system. This command clones the repository to `/opt/davoid`, configures an isolated Python virtual environment, and links the global `davoid` command to your PATH.

```bash
curl -sL "https://raw.githubusercontent.com/BryanParreira/Davoid/main/install.sh" | bash
```

> **Note:** Root privileges are required for installation and execution due to raw socket operations.

---

## 🛠️ Security Modules

| Module               | Description                     | Technical Engine               |
| -------------------- | ------------------------------- | ------------------------------ |
| **Net-Mapper**       | Advanced ARP-based discovery    | Scapy `ARP()` & `Ether()`      |
| **Live Interceptor** | Real-time packet sniffing       | Scapy `sniff()` Engine         |
| **MITM Engine**      | Automated ARP Poisoning         | Bi-directional Cache Poisoning |
| **Shell Forge**      | Instant reverse shell generator | Python & Bash Payload Gen      |
| **DNS Recon**        | Domain intelligence gathering   | Socket-level DNS Querying      |
| **Hash Cracker**     | Local MD5 wordlist recovery     | Hashlib MD5 Processing         |

---

## 🏗️ Architecture

Davoid is built on a modular engine, ensuring that each security tool operates independently within a unified global interface.

- **Language:** Python 3.x
- **Networking:** Scapy (Raw Packet Manipulation)
- **Interface:** Rich (Terminal Layouts & Gradients)
- **Privilege:** Global Root Execution (required for raw socket access)
- **Path:** Installed to `/opt/davoid` with binary linked to `/usr/local/bin/davoid`

---

## 📋 Requirements

- **Operating System:** macOS or Linux
- **Python:** 3.7 or higher
- **Root Access:** Required for packet manipulation
- **Dependencies:** Automatically installed via virtual environment
  - Scapy
  - Rich
  - Additional dependencies as specified in `requirements.txt`

---

## 🚦 Quick Start

After installation, launch Davoid from any terminal:

```bash
sudo davoid
```

Navigate through the interactive menu to select your desired security module.

---

## 🔄 Maintenance & Updates

Davoid features an integrated auto-update engine. To synchronize your local suite with the latest security tools and patches from the main branch, simply run:

```bash
davoid --update
```

Or update manually:

```bash
cd /opt/davoid
git pull origin main
source venv/bin/activate
pip install -r requirements.txt --upgrade
```

---

## 🎯 Usage Examples

### Network Discovery

```bash
sudo davoid
# Select: Net-Mapper
# Enter target IP range: 192.168.1.0/24
```

### Packet Sniffing

```bash
sudo davoid
# Select: Live Interceptor
# Specify interface: eth0
```

### DNS Reconnaissance

```bash
sudo davoid
# Select: DNS Recon
# Enter domain: example.com
```

---

## 🔐 Security Best Practices

- Always run Davoid in isolated test environments
- Obtain explicit written authorization before testing any network
- Document all security assessments thoroughly
- Follow responsible disclosure practices for any vulnerabilities discovered
- Keep Davoid updated to the latest version

---

## 🐛 Troubleshooting

### Permission Denied

Ensure you're running with root privileges:

```bash
sudo davoid
```

### Module Not Found

Verify the virtual environment is activated:

```bash
source /opt/davoid/venv/bin/activate
```

### Scapy Issues

Reinstall Scapy dependencies:

```bash
pip install --upgrade scapy
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Developer

**Bryan Parreira**  
GitHub: [@BryanParreira](https://github.com/BryanParreira)

---

## ⚠️ Legal Disclaimer

**IMPORTANT:** Davoid is intended for **educational purposes** and **authorized penetration testing only**. Unauthorized access to computer systems or networks is strictly prohibited and illegal under laws including but not limited to the Computer Fraud and Abuse Act (CFAA) and equivalent legislation worldwide.

### Terms of Use:

- ✅ Use only on networks you own or have explicit written permission to test
- ✅ Educational and research purposes in controlled environments
- ✅ Authorized security assessments with proper documentation
- ❌ Unauthorized network scanning or intrusion
- ❌ Malicious attacks or data theft
- ❌ Any illegal activity

**The developer assumes no liability and is not responsible for any misuse or damage caused by this program.** Users are solely responsible for ensuring their actions comply with all applicable laws and regulations.

By using Davoid, you acknowledge that you have read and understood this disclaimer and agree to use this software responsibly and legally.

---

## 🌟 Star History

If you find Davoid useful, please consider giving it a star ⭐

---

<p align="center">
  <sub>Built with ❤️ for the security community</sub>
</p>
