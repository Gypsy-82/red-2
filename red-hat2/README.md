# RED HAT v2 — Precision Payload Generator

> Professional-grade penetration testing instrument.
> For authorized security testing only.

---

## What This Tool Is

Most payload generators are template dumpers.
You pick a shell type, fill in an IP and port, copy the output.

**This tool is different.**

You point it at a target. The tool goes and interrogates that target — Nmap scans ports, detects the OS, identifies running services, checks for WAFs. All that intelligence flows back into the tool and builds a profile automatically.

Then the payload builder reads that profile.

It doesn't ask you what shell to use. It already knows Python3 is on the target. It already knows port 443 is the only one allowed outbound. It already knows there's a WAF that needs encoding bypassed.

It makes those decisions for you — based on real data.

Then it outputs one payload. Not a library of options to guess from. A single, precision-crafted payload that says:

> *"Given everything I know about this target — THIS is what will work."*

---

## The Full Chain

```
TARGET IP
    ↓
SCANNER          ← Nmap + wafw00f interrogate the target
    ↓
PROFILE          ← OS, open ports, services, shell availability, WAF
    ↓
DECISION ENGINE  ← selects shell type, outbound port, encoding, stabilization
    ↓
PAYLOAD          ← precision-crafted, ready to deploy
    ↓
SAVE? (y/n)      ← your choice, never automatic
```

---

## Profiler Menu

```
[1] New Target Session   → set target IP or URL
[2] Run Nmap Scan        → auto-fills OS, ports, services, filtering
[3] Run WAF Check        → wafw00f detects WAF presence and type
[4] Manual Input         → fill or override anything the scan missed
[5] Review Profile       → full summary of collected intelligence
[6] Build Payload        → decision engine generates the payload
[7] Switch Target        → profile a new target without restarting
[8] View All Profiles    → compare all targets profiled this session
[0] Exit
```

---

## What the Scanner Collects

| Intelligence        | Source          |
|---------------------|-----------------|
| Operating System    | Nmap -O         |
| Open Ports          | Nmap -p-        |
| Running Services    | Nmap -sV        |
| Firewall Filtering  | Nmap -sA        |
| WAF Presence + Type | wafw00f         |
| Shell Availability  | Banner parsing  |
| Manual Overrides    | User input      |

---

## Payload Types

### Linux / Unix
| Payload              | When Used                            |
|----------------------|--------------------------------------|
| Bash reverse shell   | Bash confirmed, no WAF               |
| Python3 reverse shell| Python3 detected on target           |
| Perl reverse shell   | Perl detected, bash unavailable      |
| PHP reverse shell    | Web service detected (Apache/Nginx)  |

### Windows
| Payload                    | When Used                        |
|----------------------------|----------------------------------|
| PowerShell reverse shell   | Windows OS detected              |
| PowerShell Base64 encoded  | Windows + WAF detected           |
| cmd.exe reverse shell      | PowerShell unavailable           |

---

## Decision Engine Logic

```
OS detected?
    Linux  → bash / python3 / perl / php
    Windows → powershell / cmd.exe

WAF detected?
    Yes → apply Base64 encoding layer
    No  → raw payload

Outbound port?
    Selects from open ports — prioritizes 443, 80, 8080

Shell confirmed?
    Uses confirmed shell binary
    Falls back through: bash → python3 → perl → sh

Stabilization?
    Auto-appends pty upgrade for Linux shells
```

---

## Multiple Target Support

Profile multiple targets in a single session.
Switch between them without restarting.
Build payloads for each independently.
Profiles are held in memory — exported only if you choose to save.

---

## Save Behavior

Every generated payload prompts:

```
Save this payload? (y/n):
```

If yes → saved to `reports/` with target IP and timestamp in the filename.
If no  → displayed only, nothing written to disk.

`reports/` is gitignored. Nothing sensitive ever commits to GitHub.

---

## Platform Support

- Kali Linux
- Ubuntu
- Arch Linux

---

## First Run

```bash
python launcher.py
```

On first run the tool will:
1. Detect missing `.venv` and create it
2. Install all required dependencies automatically
3. Generate `.gitignore`
4. Require `.env` to exist before launching

Copy `.env.example` to `.env` before first run:

```bash
cp .env.example .env
```

---

## Dependencies

```
colorama
requests
python-nmap
python-dotenv
wafw00f
```

All installed automatically on first run.

---

## Project Structure

```
red-hat2/
├── launcher.py        ← entry point
├── .env               ← required (never commit)
├── .env.example       ← safe to commit
├── .gitignore         ← auto-generated on first run
├── requirements.txt   ← dependency list
├── tools/
│   └── payload_gen.py ← full tool
└── reports/           ← saved payloads (gitignored)
```

---

## Legal

This tool is for authorized penetration testing only.
Always obtain written permission before testing any system you do not own.
Unauthorized use is illegal.

---

*RED HAT Security Lab — Built for professional penetration testers.*
