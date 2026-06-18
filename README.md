# 🛡️ MikroTik Real-Time Log Monitor with Security Alerts

A **zero-trust, self-hosted** Python service that monitors your MikroTik router logs in real time and instantly alerts you to critical security events – **without ever exposing credentials**.

> Built by a network engineer for network engineers. Your router, your rules.

---

## 🎯 Why This Exists

Most monitoring tools are bloated, cloud-dependent, or require opening additional ports.  
This tool runs **locally on your own server**, connects via the standard RouterOS API, and:
- **Detects threats instantly** (unauthorised logins, rogue WiFi clients, physical port changes, config tampering)
- **Alerts you via email** before the damage spreads
- **Keeps full audit trails** for compliance and forensics
- **Respects your privacy** – credentials never leave your server, never appear in source code, and are never stored in version control

---

## 🚀 Features

- 🔍 **Real‑time log capture** using the lightweight RouterOS API (not SSH, less CPU)
- 🧠 **Smart classification** of every log entry:
  - `[WIFI]` – Wireless client connect/disconnect (with MAC, interface, signal)
  - `[LOGIN]` – All login/logout/failure events (user, IP, method)
  - `[INTERFACE]` – Physical port link changes (**ether1 excluded** to ignore WAN)
  - `[ACTIVITY]` – Configuration changes (who did what)
- 🚨 **Email alerts** via Gmail SMTP with:
  - Per‑category toggle (turn off WiFi alerts, keep login alerts, etc.)
  - Intelligent **cooldown** to prevent spam (configurable)
  - **MAC whitelist** – known devices still logged but **never trigger alerts**
- 📝 **Full audit logging** – every single entry saved to daily `.txt` files
- 🐧 **Runs 24/7 as a systemd service** – auto‑restarts on crash, survives reboots
- 🔐 **Zero hardcoded secrets** – all credentials via environment variables or a local `secrets.json`, both excluded from Git

---

## 📸 How It Looks

2026-05-16 06:45:34 [WIFI] MAC=44:17:93:3E:A5:A1 iface=wlan1 signal=-36dBm | connected
2026-05-16 06:45:32 [WIFI-WL] MAC=AA:BB:CC:DD:EE:FF iface=wlan1 | connected (whitelisted)
2026-05-16 06:44:48 [ACTIVITY] change=(/interface set wlan1 disabled=yes) | device changed
2026-05-16 06:43:00 [INTERFACE] ether4 link up (speed 100M, full duplex)
2026-05-16 06:42:15 [LOGIN] user=admin ip=192.168.1.100 via=ssh | user admin logged in

Email alert example:

Subject: [MikroTik Alert] LOGIN - 2026-05-16 06:42:15
MikroTik Log Alert
Category: LOGIN
Time: 2026-05-16 06:42:15
user=admin ip=192.168.1.100 via=ssh | user admin logged in from 192.168.1.100 via ssh


---

## 🔒 Security First – How Credentials Are Protected

This project is **safe to open‑source** because:

1. **No secrets in code**  
   Router IP, username, password, and email credentials are read from environment variables or a local JSON file (`secrets.json`). These files are **never committed** (see `.gitignore`).

2. **`.env.example` provided**  
   Shows all required variables **with placeholder values**. Copy it to `.env` and fill in your own data.

3. **`.gitignore` enforced**  
   Excludes `.env`, `secrets.json`, log files, and the Python virtual environment.

4. **Least privilege principle**  
   The script only needs **read‑only** access to the router’s log. No write permissions required.

5. **Optional email via App Password**  
   Gmail authentication uses a dedicated **App Password** (not your main password). You can revoke it anytime.

6. **Whitelist reduces noise**  
   Known MAC addresses are logged but never trigger alerts, so you can focus on real threats.

---

## ⚙️ Architecture

[Your Router] ──(API:8728)──> [Python Script] ──(file)──> Daily .txt logs
│
├──(color)──> Terminal output
│
└──(SMTP)──> Email alerts
(whitelist & cooldown filters)


- **API** used instead of SSH for lower CPU load
- **In‑memory state** tracks last seen log ID to fetch only new entries
- **Multi‑threaded** email sending (non‑blocking)
- **Log rotation** at midnight; daily files in `logs/` folder

---

## 📦 Installation

### Prerequisites

- Python 3.7+
- Ubuntu 20.04+ (or any Linux with systemd)
- Access to MikroTik router’s API (port 8728)
- (Optional) Gmail account with App Password for alerts

### 1. Clone the Repository

```bash
git clone https://github.com/Mazak3r/MikroTik-Real-Time-Log-Monitor-with-Security-Alerts
cd mikrotik-monitor

Terminal output with colour-coded flags:
