# 🛡 VirusTotal Firewall Auto-Blocker

A Python + Bash utility that:

- Extracts suspicious IPs from system logs.
- Checks their reputation using the VirusTotal API.
- Saves malicious IPs to a file.
- Blocks them via UFW using a separate shell script.

## ✨ Features

- Automated log scanning.
- Works with Linux servers.
- Respects VirusTotal API rate limits.
- Modular — firewall logic separated from detection.

## 📦 Installation

```bash
git clone https://github.com/sudo-su-7/virustotal-firewall.git
cd virustotal-firewall
pip install -r requirements.txt
```
