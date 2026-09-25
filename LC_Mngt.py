#!/usr/bin/env python3


import os
import re
import time
import json
import smtplib
import threading
import queue
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from librouteros import connect

# Optional .env support
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ================= CONFIGURATION (from environment) =================
ROUTER_IP = os.getenv("MIKROTIK_IP", "192.168.101.1")
ROUTER_USERNAME = os.getenv("MIKROTIK_USER", "admin")
ROUTER_PASSWORD = os.getenv("MIKROTIK_PASS", "")
ROUTER_PORT = int(os.getenv("MIKROTIK_PORT", "8728"))

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "2"))
LOG_DIR = os.getenv("LOG_DIR", "logs")
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "true").lower() == "true"
EMAIL_COOLDOWN = int(os.getenv("EMAIL_COOLDOWN", "300"))

SECRETS_FILE = os.getenv("SECRETS_FILE", "secrets.json")
MAC_WHITELIST_FILE = os.getenv("MAC_WHITELIST_FILE", "mac_whitelist.txt")

ALERT_CATEGORIES = {
    'WIFI': os.getenv("ALERT_WIFI", "true").lower() == "true",
    'LOGIN': os.getenv("ALERT_LOGIN", "true").lower() == "true",
    'INTERFACE': os.getenv("ALERT_INTERFACE", "true").lower() == "true",
    'ACTIVITY': os.getenv("ALERT_ACTIVITY", "true").lower() == "true",
    'OTHER': False,
}

# ANSI colors
COLORS = {
    'WIFI': '\033[92m',
    'LOGIN': '\033[93m',
    'INTERFACE': '\033[94m',
    'ACTIVITY': '\033[96m',
    'ALERT': '\033[91m',
    'RESET': '\033[0m',
    'BOLD': '\033[1m',
}

# Patterns
WIFI_PATTERNS = [
    re.compile(r'wireless,info'),
    re.compile(r'@wlan\d'),
    re.compile(r'connected.*signal strength'),
    re.compile(r'disconnected.*signal strength'),
]
INTERFACE_PATTERNS = [
    re.compile(r'interface,info.*(?:link up|link down)'),
    re.compile(r'ether(\d+).*link (up|down)', re.IGNORECASE),
]
LOGIN_PATTERNS = [
    re.compile(r'login failure for user (\S+) from (\S+) via (\S+)'),
    re.compile(r'user (\S+) logged in from (\S+) via (\S+)'),
    re.compile(r'user (\S+) logged out from (\S+) via (\S+)'),
]
ACTIVITY_PATTERNS = [
    re.compile(r'system,info.*device changed by'),
    re.compile(r'system,info.*changed by'),
]

# ====================== Email Alerter ======================
class EmailAlerter:
    def __init__(self):
        self.secrets = self.load_secrets()
        self.email_queue = queue.Queue()
        self.alert_cooldowns = {}
        self.email_thread = None
        self.running = False

    def load_secrets(self):
        # First try environment variables
        gmail_user = os.getenv("GMAIL_USER")
        gmail_pass = os.getenv("GMAIL_APP_PASSWORD")
        alert_emails_str = os.getenv("ALERT_EMAILS", "")
        if gmail_user and gmail_pass and alert_emails_str:
            return {
                "gmail_user": gmail_user,
                "gmail_app_password": gmail_pass,
                "alert_emails": [e.strip() for e in alert_emails_str.split(",") if e.strip()]
            }
        # Fallback to secrets.json
        if os.path.exists(SECRETS_FILE):
            try:
                with open(SECRETS_FILE, 'r') as f:
                    data = json.load(f)
                return data
            except Exception as e:
                print(f"Error loading {SECRETS_FILE}: {e}")
        return None

    def start(self):
        if not self.secrets or not EMAIL_ENABLED:
            print("Email alerts: DISABLED")
            return False
        self.running = True
        self.email_thread = threading.Thread(target=self._email_worker, daemon=True)
        self.email_thread.start()
        print(f"Email alerts: ENABLED -> {', '.join(self.secrets['alert_emails'])}")
        return True

    def stop(self):
        self.running = False
        if self.email_thread:
            self.email_thread.join(timeout=5)

    def send_alert(self, category, message, mac_address=None):
        if not EMAIL_ENABLED or not self.secrets or not ALERT_CATEGORIES.get(category, False):
            return
        alert_key = f"{category}:{mac_address}" if mac_address else f"{category}:{message[:50]}"
        now = time.time()
        if alert_key in self.alert_cooldowns:
            if now - self.alert_cooldowns[alert_key] < EMAIL_COOLDOWN:
                return
        self.alert_cooldowns[alert_key] = now
        self.email_queue.put({
            'category': category,
            'message': message,
            'mac_address': mac_address,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        print(f"{COLORS['ALERT']}[EMAIL SENT] {category} alert queued{COLORS['RESET']}")

    def _email_worker(self):
        while self.running:
            try:
                alert = self.email_queue.get(timeout=1)
                self._send_email(alert)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Email error: {e}")

    def _send_email(self, alert):
        try:
            msg = MIMEMultipart()
            msg['From'] = self.secrets['gmail_user']
            msg['To'] = ', '.join(self.secrets['alert_emails'])
            subject = f"[MikroTik Alert] {alert['category']} - {alert['timestamp']}"
            msg['Subject'] = subject
            body = f"""MikroTik Log Alert
Category: {alert['category']}
Time: {alert['timestamp']}

{alert['message']}
"""
            msg.attach(MIMEText(body, 'plain'))
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(self.secrets['gmail_user'], self.secrets['gmail_app_password'])
            server.send_message(msg)
            server.quit()
        except Exception as e:
            print(f"Failed to send email: {e}")

# ====================== MAC Whitelist ======================
class MACWhitelist:
    def __init__(self):
        self.whitelist = self.load_whitelist()

    def load_whitelist(self):
        if not os.path.exists(MAC_WHITELIST_FILE):
            print(f"Warning: {MAC_WHITELIST_FILE} not found. All WiFi events will be flagged.")
            with open(MAC_WHITELIST_FILE, 'w') as f:
                f.write("# MAC Address Whitelist - one per line\n")
                f.write("# MACs listed here will NOT trigger email alerts\n")
                f.write("# Format: XX:XX:XX:XX:XX:XX\n")
            return set()
        try:
            with open(MAC_WHITELIST_FILE, 'r') as f:
                macs = set()
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        macs.add(line.upper())
                print(f"Loaded {len(macs)} whitelisted MACs")
                return macs
        except Exception as e:
            print(f"Error loading whitelist: {e}")
            return set()

    def is_whitelisted(self, mac):
        return mac and mac.upper() in self.whitelist

# ====================== Helper Functions ======================
def ensure_log_directory():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

def get_log_filepath():
    date_str = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(LOG_DIR, f"mikrotik_logs_{date_str}.txt")

def write_to_file(filepath, line):
    clean_line = re.sub(r'\033\[\d+m', '', line)
    try:
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write(clean_line + '\n')
    except Exception as e:
        print(f"Error writing to file: {e}")

def connect_router():
    try:
        print(f"Connecting to {ROUTER_IP}:{ROUTER_PORT} as {ROUTER_USERNAME}...")
        api = connect(
            host=ROUTER_IP,
            username=ROUTER_USERNAME,
            password=ROUTER_PASSWORD,
            port=ROUTER_PORT
        )
        print("Connected successfully!")
        return api
    except Exception as e:
        print(f"Connection failed: {e}")
        return None

def get_time_offset(api):
    try:
        clock_data = list(api.path("system", "clock"))[0]
        router_time = clock_data.get("time", "")
        router_date = clock_data.get("date", "")
        if router_time and router_date:
            month_map = {
                "jan": "01", "feb": "02", "mar": "03", "apr": "04",
                "may": "05", "jun": "06", "jul": "07", "aug": "08",
                "sep": "09", "oct": "10", "nov": "11", "dec": "12"
            }
            month_str, day, year = router_date.split("/")
            month = month_map[month_str.lower()]
            router_dt = datetime.strptime(f"{year}-{month}-{day} {router_time}", "%Y-%m-%d %H:%M:%S")
        elif router_time:
            router_time_obj = datetime.strptime(router_time, "%H:%M:%S").time()
            router_dt = datetime.combine(datetime.now().date(), router_time_obj)
        else:
            return timedelta(0)
        now = datetime.now()
        offset = now - router_dt
        print(f"Router time: {router_dt}, Local: {now}, Offset: {offset}")
        return offset
    except Exception as e:
        print(f"Time offset error: {e}, using local time")
        return timedelta(0)

def extract_mac_address(text):
    match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', text)
    return match.group(1) if match else None

def classify_log_category(message, topics):
    combined = f"{topics} {message}"
    mac = extract_mac_address(combined)
    # LOGIN
    for pattern in LOGIN_PATTERNS:
        match = pattern.search(message)
        if match:
            groups = match.groups()
            if len(groups) == 3:
                return "LOGIN", f"user={groups[0]} ip={groups[1]} via={groups[2]}", None
    # WIFI
    for pattern in WIFI_PATTERNS:
        if pattern.search(combined):
            iface = re.search(r'@(\S+)', combined)
            signal = re.search(r'signal strength (-?\d+)', combined)
            details = []
            if mac: details.append(f"MAC={mac}")
            if iface: details.append(f"iface={iface.group(1)}")
            if signal: details.append(f"signal={signal.group(1)}dBm")
            return "WIFI", " ".join(details) if details else None, mac
    # INTERFACE (skip ether1)
    for pattern in INTERFACE_PATTERNS:
        match = pattern.search(combined)
        if match:
            eth = re.search(r'ether(\d+)', combined, re.IGNORECASE)
            if eth and eth.group(1) == '1':
                return "SKIP", None, None
            return "INTERFACE", None, None
    # ACTIVITY
    for pattern in ACTIVITY_PATTERNS:
        if pattern.search(combined):
            change = re.search(r'changed by \S+:(.*)', combined)
            return "ACTIVITY", f"change={change.group(1).strip()}" if change else None, None
    return "OTHER", None, None

def format_log_entry(real_dt, topics, message, category, details, is_whitelisted=False):
    time_str = real_dt.strftime("%Y-%m-%d %H:%M:%S")
    if category == "WIFI":
        flag = f"{COLORS['WIFI']}[WIFI-WL]{COLORS['RESET']}" if is_whitelisted else f"{COLORS['WIFI']}[WIFI]{COLORS['RESET']}"
        return f"{time_str} {flag} {details} | {message}" if details else f"{time_str} {flag} {message}"
    elif category == "LOGIN":
        flag = f"{COLORS['LOGIN']}[LOGIN]{COLORS['RESET']}"
        return f"{time_str} {flag} {details} | {message}"
    elif category == "INTERFACE":
        flag = f"{COLORS['INTERFACE']}[INTERFACE]{COLORS['RESET']}"
        return f"{time_str} {flag} {message}"
    elif category == "ACTIVITY":
        flag = f"{COLORS['ACTIVITY']}[ACTIVITY]{COLORS['RESET']}"
        return f"{time_str} {flag} {details} | {message}" if details else f"{time_str} {flag} {message}"
    else:
        return f"{time_str} | {topics} | {message}"

def process_log_entry(entry, offset, mac_whitelist, email_alerter):
    time_str = entry.get("time", "")
    message = entry.get("message", "")
    topics = entry.get("topics", "")
    if not time_str or not message:
        return None
    try:
        try:
            log_dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            log_time = datetime.strptime(time_str, "%H:%M:%S").time()
            now = datetime.now()
            log_dt = datetime.combine(now.date(), log_time)
            if log_dt > now:
                log_dt -= timedelta(days=1)
        real_dt = log_dt + offset
        category, details, mac_address = classify_log_category(message, topics)
        if category == "SKIP":
            return None
        is_whitelisted = (category == "WIFI" and mac_whitelist.is_whitelisted(mac_address))
        # Send email alert if needed
        if email_alerter and EMAIL_ENABLED:
            if category == "WIFI":
                if not is_whitelisted:
                    email_alerter.send_alert(category, message, mac_address)
            elif ALERT_CATEGORIES.get(category):
                email_alerter.send_alert(category, message, mac_address)
        return format_log_entry(real_dt, topics, message, category, details, is_whitelisted)
    except Exception as e:
        return None

def display_and_log(line, filepath):
    print(line)
    write_to_file(filepath, line)

def print_stats(counters):
    return (f"{COLORS['BOLD']}Stats:{COLORS['RESET']} "
            f"{COLORS['WIFI']}WIFI:{counters['WIFI']}{COLORS['RESET']} "
            f"{COLORS['LOGIN']}LOGIN:{counters['LOGIN']}{COLORS['RESET']} "
            f"{COLORS['INTERFACE']}IFACE:{counters['INTERFACE']}{COLORS['RESET']} "
            f"{COLORS['ACTIVITY']}ACT:{counters['ACTIVITY']}{COLORS['RESET']} "
            f"OTHER:{counters['OTHER']}")

def live_log_monitor():
    ensure_log_directory()
    log_filepath = get_log_filepath()
    mac_whitelist = MACWhitelist()
    email_alerter = EmailAlerter()
    if EMAIL_ENABLED:
        email_alerter.start()
    counters = {'WIFI':0, 'LOGIN':0, 'INTERFACE':0, 'ACTIVITY':0, 'OTHER':0}
    session_start = f"{'='*60}\nSession started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*60}"
    print(session_start)
    write_to_file(log_filepath, session_start)
    print(f"Logging to file: {log_filepath}")
    print(f"{COLORS['WIFI']}[WIFI]{COLORS['RESET']} / [WIFI-WL] - Wireless events")
    print(f"{COLORS['LOGIN']}[LOGIN]{COLORS['RESET']} - Login/logout")
    print(f"{COLORS['INTERFACE']}[INTERFACE]{COLORS['RESET']} - Physical interface (excl. ether1)")
    print(f"{COLORS['ACTIVITY']}[ACTIVITY]{COLORS['RESET']} - Configuration changes")
    print()
    api = connect_router()
    if not api:
        email_alerter.stop()
        return
    offset = get_time_offset(api)
    try:
        logs = list(api.path("log"))
    except Exception as e:
        print(f"Failed to fetch logs: {e}")
        api.close()
        email_alerter.stop()
        return
    last_id = logs[-1][".id"] if logs else None
    print(f"Found {len(logs)} existing logs. Monitoring...")
    print("=" * 60)
    current_date = datetime.now().date()
    try:
        while True:
            today = datetime.now().date()
            if today != current_date:
                current_date = today
                log_filepath = get_log_filepath()
                date_msg = f"\n--- Log file rotated: {today} ---"
                print(date_msg)
                write_to_file(log_filepath, date_msg)
            try:
                current_logs = list(api.path("log"))
            except Exception:
                print("Connection lost, reconnecting...")
                api.close()
                time.sleep(3)
                api = connect_router()
                if not api:
                    time.sleep(5)
                    continue
                offset = get_time_offset(api)
                current_logs = list(api.path("log"))
                last_id = current_logs[-1][".id"] if current_logs else None
                print("Reconnected")
            if not current_logs:
                time.sleep(POLL_INTERVAL)
                continue
            if last_id:
                found = False
                new_entries = []
                for entry in current_logs:
                    if found:
                        new_entries.append(entry)
                    elif entry[".id"] == last_id:
                        found = True
                if not found:
                    print("[Log rotation detected]")
                    new_entries = current_logs[-5:] if len(current_logs) > 5 else current_logs
            else:
                new_entries = current_logs
            for entry in new_entries:
                formatted = process_log_entry(entry, offset, mac_whitelist, email_alerter)
                if formatted:
                    display_and_log(formatted, log_filepath)
                    if '[WIFI]' in formatted:
                        counters['WIFI'] += 1
                    elif '[LOGIN]' in formatted:
                        counters['LOGIN'] += 1
                    elif '[INTERFACE]' in formatted:
                        counters['INTERFACE'] += 1
                    elif '[ACTIVITY]' in formatted:
                        counters['ACTIVITY'] += 1
                    else:
                        counters['OTHER'] += 1
            if current_logs:
                last_id = current_logs[-1][".id"]
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\n" + "=" * 60)
        print(print_stats(counters))
        print("=" * 60)
        stop_msg = f"Monitoring stopped at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        print(stop_msg)
        write_to_file(log_filepath, stop_msg)
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        api.close()
        email_alerter.stop()
        print("Connection closed.")

if __name__ == "__main__":
    live_log_monitor()
