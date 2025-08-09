#!/bin/bash
# Reads malicious_ips.txt and blocks each IP via UFW

INPUT_FILE="malicious_ips.txt"

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "[!] No malicious IP list found."
    exit 1
fi

while read -r ip; do
    if [[ -n "$ip" ]]; then
        ufw deny from "$ip" comment "Blocked by VirusTotal checker"
    fi
done < "$INPUT_FILE"

ufw reload
echo "[+] Firewall updated."