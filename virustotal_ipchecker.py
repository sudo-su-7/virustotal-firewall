#!/usr/bin/env python3
import os
import time
import json
import requests
import subprocess
from pathlib import Path

# --------------------------
# Config
# --------------------------
LOG_FILE = "/var/log/auth.log"   # Adjust for your OS
MALICIOUS_IP_FILE = "malicious_ips.txt"
SLEEP_INTERVAL = 1800            # 30 min between scans

# Load API key from /etc/environment or system env
def load_api_key():
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        raise ValueError("VirusTotal API key not found. Set VT_API_KEY in /etc/environment")
    return api_key

API_KEY = load_api_key()

# --------------------------
# Functions
# --------------------------
def extract_ips_from_log():
    """Parse log file for unique IP addresses."""
    if not os.path.exists(LOG_FILE):
        print(f"[!] Log file not found: {LOG_FILE}")
        return set()

    ips = set()
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "Failed password" in line or "authentication failure" in line:
                parts = line.split()
                for part in parts:
                    if part.count(".") == 3:
                        ips.add(part)
    return ips

def check_ip_virustotal(ip):
    """Check an IP against VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            return malicious_count
        else:
            print(f"[!] API error {r.status_code} for IP {ip}")
            return None
    except requests.RequestException as e:
        print(f"[!] Request failed for {ip}: {e}")
        return None

def load_blocked_ips():
    """Load already-blocked IPs from file."""
    if Path(MALICIOUS_IP_FILE).exists():
        with open(MALICIOUS_IP_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def save_blocked_ips(ips):
    """Save malicious IPs to file."""
    with open(MALICIOUS_IP_FILE, "w") as f:
        for ip in sorted(ips):
            f.write(ip + "\n")

def update_firewall():
    """Run UFW blocking script."""
    subprocess.run(["./block_ips.sh"], check=False)

# --------------------------
# Main loop
# --------------------------
def main():
    print("[+] Starting VirusTotal IP checker...")
    blocked_ips = load_blocked_ips()

    while True:
        print("[+] Extracting IPs from logs...")
        ips = extract_ips_from_log()
        new_malicious = set()

        for ip in ips:
            if ip in blocked_ips:
                continue
            malicious_count = check_ip_virustotal(ip)
            if malicious_count is None:
                continue
            if malicious_count > 0:
                print(f"[!] Malicious IP found: {ip} ({malicious_count} detections)")
                new_malicious.add(ip)
            else:
                print(f"[-] {ip} is clean")

            time.sleep(16)  # API rate limiting

        if new_malicious:
            blocked_ips.update(new_malicious)
            save_blocked_ips(blocked_ips)
            update_firewall()
            print(f"[+] Firewall updated with {len(new_malicious)} new IP(s)")

        print(f"[i] Sleeping for {SLEEP_INTERVAL} seconds...")
        time.sleep(SLEEP_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
