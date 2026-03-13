"""
RED HAT v2 — Precision Payload Generator
Entry point — handles venv, dependencies, .env gate, and launch.
For authorized penetration testing only.
"""

import os
import sys
import subprocess
from pathlib import Path

VENV_DIR   = Path(".venv")
REQ_FILE   = Path("requirements.txt")
ENV_FILE   = Path(".env")
GITIGNORE  = Path(".gitignore")

GITIGNORE_CONTENT = """# RED HAT v2 — Git Ignore
.env
reports/
__pycache__/
*.pyc
*.pyo
.venv/
*.log
*.bak
"""

BANNER = r"""
  ██████╗ ███████╗██████╗      ██╗  ██╗ █████╗ ████████╗    ██╗   ██╗██████╗
  ██╔══██╗██╔════╝██╔══██╗     ██║  ██║██╔══██╗╚══██╔══╝    ██║   ██║╚════██╗
  ██████╔╝█████╗  ██║  ██║     ███████║███████║   ██║       ██║   ██║ █████╔╝
  ██╔══██╗██╔══╝  ██║  ██║     ██╔══██║██╔══██║   ██║       ╚██╗ ██╔╝██╔═══╝
  ██║  ██║███████╗██████╔╝     ██║  ██║██║  ██║   ██║        ╚████╔╝ ███████╗
  ╚═╝  ╚═╝╚══════╝╚═════╝      ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝         ╚═══╝  ╚══════╝
          Precision Payload Generator — Professional Grade Instrument
"""


def create_gitignore():
    if not GITIGNORE.exists():
        GITIGNORE.write_text(GITIGNORE_CONTENT.strip() + "\n")
        print("  [+] .gitignore created.")


def check_env():
    if not ENV_FILE.exists():
        print("\n  [!] .env file not found — tool cannot launch.")
        print("  [*] Set up your environment first:")
        print("      cp .env.example .env")
        print("      Then edit .env with your LHOST and operator details.\n")
        sys.exit(1)


def setup_venv():
    if not VENV_DIR.exists():
        print("  [*] Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
        print("  [+] .venv created.")


def get_pip():
    if sys.platform == "win32":
        return str(VENV_DIR / "Scripts" / "pip")
    return str(VENV_DIR / "bin" / "pip")


def get_python():
    if sys.platform == "win32":
        return str(VENV_DIR / "Scripts" / "python")
    return str(VENV_DIR / "bin" / "python")


def install_deps():
    pip = get_pip()
    print("  [*] Installing dependencies...")
    subprocess.run(
        [pip, "install", "--quiet", "-r", str(REQ_FILE)],
        check=True
    )
    print("  [+] All dependencies installed.")


def is_venv_active():
    return sys.prefix != sys.base_prefix


def print_banner():
    print(BANNER)


def main():
    print_banner()
    print("  Initializing...\n")

    create_gitignore()
    check_env()
    setup_venv()

    if not is_venv_active():
        python = get_python()
        print("\n  [*] Launching inside virtual environment...\n")
        os.execv(python, [python] + sys.argv)
    else:
        install_deps()
        from tools.payload_gen import run
        run()


if __name__ == "__main__":
    main()
