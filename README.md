DAVOID : GHOST IN THE NET

Professional-grade Terminal User Interface (TUI) toolkit for network discovery, security auditing, and ethical hacking.

Davoid is a modular security engine built for speed, clarity, and deep-level network manipulation. It leverages Scapy for raw packet crafting and Rich to provide a high-contrast, modern terminal experience. Whether you are mapping a local subnet or performing authorized man-in-the-middle audits, Davoid provides a unified global interface for offensive and defensive security tasks.

🚀 Secure Installation

Davoid uses a secure installation pipeline. The framework is deployed globally to /opt/davoid and strictly locked down with root:root ownership to prevent local malware or unauthorized users from tampering with your offensive payloads.

Clone the repository and execute the setup script:

git clone https://github.com/BryanParreira/Davoid.git
cd Davoid
sudo bash install.sh

Note: The installer configures an isolated Python virtual environment, installs system dependencies (Tor, Nmap, Aircrack-ng), and links the global davoid command to your PATH.

🚦 Execution & Privilege Requirements

To launch the framework, simply type:

sudo davoid

Why does Davoid require sudo?

Davoid is a professional-grade offensive framework. While standard applications should run rootless, Davoid fundamentally requires raw access to your operating system's network stack to perform its operations:

Stealth Scanning: Nmap requires root to bypass the OS and forge raw half-open TCP packets (-sS) and perform OS fingerprinting (-O).

AitM Web Cloning: Binding to privileged ports (like Port 80 for HTTP interception) is strictly forbidden for standard users.

ARP Poisoning: The MITM engine must dynamically rewrite OS-level IP-forwarding rules (net.inet.ip.forwarding) to keep the victim's internet active during a hijack.

Raw Socket Sniffing: Scapy requires root to put interfaces into monitor mode and capture WPA/EAPOL handshakes.

🛠️ Security Modules

1️⃣ Intelligence & OSINT (The Holmes Engine)

Focused on passive and active information gathering, this hub incorporates elite features from the Mr. Holmes project.

Tool

Key

Description

Net-Mapper

[1]

High-speed L2/L3 discovery with CVE vulnerability mapping and hardware vendor identification

Live Interceptor

[2]

Real-time traffic analysis with DNS query tracking and session token extraction

Holmes Engine

[3]

Advanced profiling including Username Tracking across 10+ platforms, Phone Intelligence, and Geospatial Tracking

Web Recon

[4]

Automated Robots.txt scraping and domain reputation auditing for attack surface mapping

2️⃣ Offensive Operations

A powerhouse for active network manipulation and traffic redirection.

Tool

Key

Description

MITM Engine

[5]

Subnet-wide ARP poisoning with automatic IP forwarding configuration for macOS and Linux

DNS Spoofer

[6]

Real-time hijacking of DNS queries to redirect targets to custom phishing portals

Phantom Cloner

[7]

Dynamic web cloning with JS Form-Hooking for automated credential harvesting

GHOST-HUB C2

[8]

Encrypted Command & Control center for remote session management and orchestration

3️⃣ Payloads & Post-Exploitation

Tools for establishing persistence and maintaining access.

Tool

Key

Description

Shell Forge

[9]

Multipurpose payload generator supporting Bash, Python, PHP, Ruby, and PowerShell

Crypt-Keeper

[0]

Advanced payload encryption and evasion logic with self-decrypting loaders to bypass static AV

Persistence Engine

[P]

Cross-platform backdoor installation via Systemd, Cron (Linux), or Windows Registry Run keys

Hash Cracker

[H]

Multi-threaded bruteforce tool supporting MD5 and SHA256 with optional symmetric salting

4️⃣ System & Stealth

Operational security and environment health.

Tool

Key

Description

Setup Auditor

[A]

Performs "pre-flight check" to verify system dependencies and network interface support

Vanish

[Q]

Instantly shuts down the framework and clears operational traces from the console

🏗️ Architecture

Davoid is built on a modular engine, ensuring that each security tool operates independently within a unified global interface.

Language: Python 3.x

Networking: Scapy (Raw Packet Manipulation)

Interface: Rich (Terminal Layouts & Gradients)

State Storage: Databases and certificates safely isolated in ~/.davoid/

Path: Installed to /opt/davoid with binary linked to /usr/local/bin/davoid

🔄 Maintenance & Updates

Davoid features a seamless, integrated Over-The-Air (OTA) update engine. Because the framework is stored in a protected system directory, the updater will automatically request your local password to safely apply patches from the main branch.

From any terminal, run:

davoid --update

🔐 Security Best Practices

Always run Davoid in isolated test environments.

Obtain explicit written authorization before testing any network.

Document all security assessments thoroughly.

Follow responsible disclosure practices for any vulnerabilities discovered.

Keep Davoid updated to the latest version.

🤝 Contributing

Contributions are welcome! Please follow these guidelines:

Fork the repository

Create a feature branch (git checkout -b feature/AmazingFeature)

Commit your changes (git commit -m 'Add some AmazingFeature')

Push to the branch (git push origin feature/AmazingFeature)

Open a Pull Request

📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

👨‍💻 Developer

Bryan Parreira GitHub: @BryanParreira

⚠️ Legal Disclaimer

IMPORTANT: Davoid is intended for educational purposes and authorized penetration testing only. Unauthorized access to computer systems or networks is strictly prohibited and illegal under laws including but not limited to the Computer Fraud and Abuse Act (CFAA) and equivalent legislation worldwide.

Terms of Use:

✅ Use only on networks you own or have explicit written permission to test.

✅ Educational and research purposes in controlled environments.

✅ Authorized security assessments with proper documentation.

❌ Unauthorized network scanning or intrusion.

❌ Malicious attacks or data theft.

❌ Any illegal activity.

The developer assumes no liability and is not responsible for any misuse or damage caused by this program. Users are solely responsible for ensuring their actions comply with all applicable laws and regulations.

🌟 Star History

If you find Davoid useful, please consider giving it a star ⭐
