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

Terminal output with colour-coded flags:
