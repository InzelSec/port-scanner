#!/usr/bin/env python3
# InzelSec - Port Scanner
# Description: simple TCP connect() scanner with -T1..-T5 profiles.
#              Shows only OPEN ports by default (Nmap-like).
# Usage:
#   python3 port_scanner.py target.com
#   python3 port_scanner.py target.com -p 22,80,443
#   python3 port_scanner.py target.com -p 20-25,80,443 -T4
#   python3 port_scanner.py target.com --show-all
#
# Notes:
#   - Target is a positional argument (first).
#   - Only OPEN ports are shown by default; use --show-all to also list CLOSED/ERROR.

import socket
import argparse
import shutil
import os
import sys
import time

# Colors
GREEN  = "\033[0;32m"
RED    = "\033[0;31m"
YELLOW = "\033[1;33m"
NC     = "\033[0m"

# === InzelSec banner (centered) ===
def banner_inzelsec():
    width = shutil.get_terminal_size((80, 20)).columns
    line = "=" * width
    print(f"\n{YELLOW}{line}{NC}")
    try:
        # Prefer figlet to preserve camelCase "InzelSec"
        if shutil.which("figlet"):
            output = os.popen('figlet "InzelSec"').read()
        elif shutil.which("toilet") and os.path.exists(os.path.expanduser("~/.toilet/fonts/big.tlf")):
            output = os.popen('toilet -d ~/.toilet/fonts -f big -F metal "INZELSEC"').read()
        elif shutil.which("toilet"):
            output = os.popen('toilet -f standard -F metal "INZELSEC"').read()
        else:
            output = "InzelSec"
        for line_str in output.splitlines():
            pad = max((width - len(line_str)) // 2, 0)
            print(" " * pad + line_str)
    except Exception:
        print("InzelSec".center(width))
    print(f"{YELLOW}{line}{NC}\n")

# Parse ports: "22,80,443" or "20-25,80,443"
def parse_ports(s: str):
    ports = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            ports.extend(range(a, b + 1))
        else:
            ports.append(int(part))
    # Deduplicate, validate range, sort
    return sorted(set(p for p in ports if 1 <= p <= 65535))

# === Timing profiles (-T1..-T5) ===
T_PROFILES = {
    1: {"timeout": 3.0,  "delay": 0.4},
    2: {"timeout": 1.5,  "delay": 0.2},
    3: {"timeout": 0.50, "delay": 0.0},  # default (Nmap-like mid)
    4: {"timeout": 0.20, "delay": 0.0},
    5: {"timeout": 0.05, "delay": 0.0},
}

def scan(target, ports, t_level=3, show_all=False):
    prof = T_PROFILES.get(t_level, T_PROFILES[3])
    timeout = prof["timeout"]
    delay   = prof["delay"]

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{RED}[-] Invalid host: {target}{NC}")
        sys.exit(1)

    print(f"{YELLOW}[+] Target: {target} ({target_ip}) | Ports: {len(ports)} | Profile: T{t_level} (timeout={timeout}s, delay={delay}s){NC}")

    for port in ports:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(timeout)
            code = client.connect_ex((target_ip, int(port)))
            if code == 0:
                try:
                    service = socket.getservbyport(int(port))
                except Exception:
                    service = "unknown"
                print(f"{GREEN}[+] {port:>5}/tcp OPEN   {service}{NC}")
            else:
                if show_all:
                    print(f"{RED}[-] {port:>5}/tcp CLOSED{NC}")
        except KeyboardInterrupt:
            print(f"\n{RED}[-] Interrupted by user.{NC}")
            sys.exit(1)
        except Exception as e:
            if show_all:
                print(f"{YELLOW}[!] {port:>5}/tcp ERROR  ({e}){NC}")
        finally:
            try:
                client.close()
            except Exception:
                pass
        if delay:
            time.sleep(delay)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="InzelSec - Port Scanner (TCP connect). Shows only OPEN ports by default.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", nargs="?", help="Target host or IP")
    parser.add_argument("-p", "--ports", help="Ports (e.g., 22,80,443 or 20-25,80)")
    parser.add_argument("-T", type=int, choices=[1,2,3,4,5], default=3,
                        help="Aggressiveness level (T1..T5). Default: T3")
    parser.add_argument("--show-all", action="store_true",
                        help="Also show CLOSED/ERROR ports (default: only OPEN)")
    parser.add_argument("-v", "--version", action="version", version="InzelSec Port Scanner 1.0")
    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    banner_inzelsec()

    if args.ports:
        ports = parse_ports(args.ports)
        if not ports:
            print(f"{RED}[-] No valid ports after parsing.{NC}")
            sys.exit(1)
    else:
        ports = [21, 22, 23, 25, 80, 443, 445, 8080, 8443, 3306, 139, 135]

    scan(args.target, ports, t_level=args.T, show_all=args.show_all)
