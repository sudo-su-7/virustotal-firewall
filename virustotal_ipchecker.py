#!/usr/bin/env python3
"""
VirusTotal IP Reputation Checker
Outputs a list of malicious IPs to 'malicious_ips.txt'.
"""

import requests
import os
import sys
import time

# ====== CONFIG ======
VT_API_KEY = os.getenv("VT_API_KEY")  # Loaded from /etc/environment
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
MALICIOUS_THRESHOLD = 1  # Vendors flagging before marking as malicious
SUSPICIOUS_IPS = ["8.8.8.8", "1.1.1.1"]  # Replace or load dynamically
RATE_LIMIT_DELAY = 15  # seconds (free API: 4 requests/min)

# ====== SECURITY CHECK ======
if not VT_API_KEY:
    print("[ERROR] Missing VT_API_KEY environment variable.")
    print("Make sure /etc/environment contains: VT_API_KEY=\"your_api_key_here\"")
    sys.exit(1)

HEADERS = {"x-apikey": VT_API_KEY}

def vt_check(ip):
    """Check IP reputation on VirusTotal."""
    try:
        resp = requests.get(VT_URL + ip, headers=HEADERS, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
    except requests.exceptions.RequestException as e:
        print(f"[!] Network/API error for {ip}: {e}")
    except KeyError:
        print(f"[!] Unexpected API response for {ip}")
    return None

def main():
    malicious_ips = []

    for ip in SUSPICIOUS_IPS:
        score = vt_check(ip)
        if score is None:
            continue
        if score >= MALICIOUS_THRESHOLD:
            print(f"[!] {ip} flagged malicious by {score} vendors")
            malicious_ips.append(ip)
        else:
            print(f"[-] {ip} is clean ({score} detections)")
        time.sleep(RATE_LIMIT_DELAY)

    # Write to file
    with open("malicious_ips.txt", "w") as f:
        for ip in malicious_ips:
            f.write(ip + "\n")

    print(f"[*] Saved {len(malicious_ips)} malicious IP(s) to malicious_ips.txt")

if __name__ == "__main__":
    main()
