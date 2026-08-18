#!/usr/bin/env python3

import os
import re
import time
import subprocess
import threading
import html
import psutil

from datetime import datetime


# ============================================================
# GHOSTWATCH CONFIGURATION
# ============================================================

REPORT_DIR = "/home/kali/GhostWatch"
REPORT_FILE = os.path.join(REPORT_DIR, "report.html")

WATCH_DIRECTORIES = (
    "/home",
    "/root",
)

WATCH_EXTENSIONS = (
    ".txt",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".csv",
    ".json",
    ".env",
    ".pem",
    ".key",
    ".conf",
    ".sql",
    ".db",
    ".sqlite",
    ".sqlite3",
)

DANGER_PORTS = {
    4444,
    1337,
    6666,
    9999,
    31337,
}


# ============================================================
# PROCESS CLASSIFICATION
# ============================================================

SAFE_PROCESSES = {
    "nano",
    "vim",
    "vim.basic",
    "vi",
    "gedit",
    "mousepad",
    "code",
    "code-insiders",
    "kate",

    # Browsers
    "firefox",
    "firefox-esr",
    "chromium",
    "chromium-browser",
    "google-chrome",
}

SUSPICIOUS_PROCESSES = {
    "bash",
    "zsh",
    "sh",
    "dash",
    "python",
    "python3",
    "perl",
    "ruby",
    "php",
}

DANGEROUS_PROCESSES = {
    "ncat",
    "nc",
    "netcat",
    "msfconsole",
}


# ============================================================
# GLOBAL DATA
# ============================================================

ALL_ALERTS = []

ALERT_LOCK = threading.Lock()

STOP_EVENT = threading.Event()

FATRACE_PROCESS = None


# ============================================================
# RECENT SENSITIVE FILE ACCESS
# ============================================================

RECENT_SENSITIVE_ACCESS = {}

SENSITIVE_ACCESS_LOCK = threading.Lock()

SENSITIVE_ACCESS_WINDOW = 30


# ============================================================
# SETUP
# ============================================================

def setup_directories():

    os.makedirs(
        REPORT_DIR,
        exist_ok=True
    )


# ============================================================
# SENSITIVE FILE CHECK
# ============================================================

def is_sensitive_file(filepath):

    if not filepath:
        return False

    filepath = filepath.strip()

    if not any(
        filepath == directory
        or filepath.startswith(directory + "/")
        for directory in WATCH_DIRECTORIES
    ):
        return False

    filename = os.path.basename(
        filepath
    ).lower()

    return filename.endswith(
        WATCH_EXTENSIONS
    )


# ============================================================
# RISK ENGINE
# ============================================================

def get_risk_level(
    process_name,
    action,
    filepath=""
):

    name = process_name.lower().strip()

    # --------------------------------------------------------
    # Dangerous processes
    # --------------------------------------------------------

    if name in DANGEROUS_PROCESSES:

        return (
            "🔴 CRITICAL",
            "Known dangerous process accessed a sensitive file"
        )

    # --------------------------------------------------------
    # Network utilities
    # --------------------------------------------------------

    if name in {
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
    }:

        return (
            "🔴 CRITICAL",
            "Network utility accessed a sensitive file"
        )

    # --------------------------------------------------------
    # Command-line readers
    # --------------------------------------------------------

    if name in {
        "cat",
        "less",
        "more",
        "head",
        "tail",
        "grep",
        "awk",
        "sed",
    }:

        if action in {
            "R",
            "O",
            "RO",
            "RCO",
        }:

            return (
                "🟡 SUSPICIOUS",
                f"Command-line process '{process_name}' "
                "read a sensitive file"
            )

    # --------------------------------------------------------
    # Shells
    # --------------------------------------------------------

    if name in {
        "bash",
        "zsh",
        "sh",
        "dash",
    }:

        return (
            "🟡 SUSPICIOUS",
            f"Shell process '{process_name}' "
            "accessed a sensitive file"
        )

    # --------------------------------------------------------
    # Scripting languages
    # --------------------------------------------------------

    if name in {
        "python",
        "python3",
        "perl",
        "ruby",
        "php",
    }:

        return (
            "🟡 SUSPICIOUS",
            f"Scripting process '{process_name}' "
            "accessed a sensitive file"
        )

    # --------------------------------------------------------
    # Known safe applications
    # --------------------------------------------------------

    if name in SAFE_PROCESSES:

        return (
            "🟢 SAFE",
            f"Known safe application '{process_name}' "
            "accessed the file"
        )

    # --------------------------------------------------------
    # Unknown process
    # --------------------------------------------------------

    return (
        "🟠 UNKNOWN",
        f"Unknown process '{process_name}' "
        "accessed a sensitive file"
    )


# ============================================================
# ACTION DESCRIPTION
# ============================================================

def describe_action(action):

    action = action.upper().strip()

    if "W" in action:
        return "WRITE"

    if "R" in action:
        return "READ"

    if "O" in action:
        return "OPEN"

    if "C" in action:
        return "CLOSE"

    return action


# ============================================================
# ADD FILE ALERT
# ============================================================

def add_file_alert(
    process_name,
    pid,
    action,
    filepath
):

    if not is_sensitive_file(filepath):
        return

    human_action = describe_action(
        action
    )

    risk, reason = get_risk_level(
        process_name,
        action,
        filepath
    )

    # --------------------------------------------------------
    # Remember sensitive READ/OPEN activity
    # --------------------------------------------------------

    if action in {
        "R",
        "O",
        "RO",
        "RCO",
    }:

        try:

            pid_number = int(pid)

            with SENSITIVE_ACCESS_LOCK:

                RECENT_SENSITIVE_ACCESS[
                    pid_number
                ] = {
                    "file": filepath,
                    "time": time.time(),
                    "process": process_name,
                }

        except ValueError:
            pass

    now = datetime.now().strftime(
        "%H:%M:%S"
    )

    alert = {
        "type": "FILE",
        "time": now,
        "process": process_name,
        "pid": pid,
        "action": human_action,
        "file": filepath,
        "risk": risk,
        "reason": reason,
    }

    with ALERT_LOCK:

        # Avoid identical consecutive events
        if ALL_ALERTS:

            previous = ALL_ALERTS[-1]

            if (
                previous.get("type") == "FILE"
                and previous.get("process") == process_name
                and previous.get("pid") == pid
                and previous.get("file") == filepath
                and previous.get("action") == human_action
            ):

                return

        ALL_ALERTS.append(
            alert
        )

        if len(ALL_ALERTS) > 500:

            del ALL_ALERTS[:-500]

    save_report()

    print("=" * 60)
    print("🚨 FILE ACTIVITY DETECTED")
    print(f"⏰ Time      : {now}")
    print(f"💻 Process   : {process_name}")
    print(f"🆔 PID       : {pid}")
    print(f"⚡ Action    : {human_action}")
    print(f"📄 File      : {filepath}")
    print(f"🎯 Risk      : {risk}")
    print(f"💡 Reason    : {reason}")
    print(f"📊 Report    : {REPORT_FILE}")
    print("=" * 60)


# ============================================================
# ADD EXFILTRATION ALERT
# ============================================================

def add_exfiltration_alert(
    process_name,
    pid,
    filepath,
    remote_ip,
    remote_port
):

    now = datetime.now().strftime(
        "%H:%M:%S"
    )

    reason = (
        f"Process '{process_name}' recently read "
        f"'{filepath}' and then opened a network connection"
    )

    alert = {
        "type": "EXFILTRATION",
        "time": now,
        "process": process_name,
        "pid": pid,
        "action": "NETWORK",
        "file": filepath,
        "risk": "🔴 CRITICAL",
        "reason": reason,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
    }

    with ALERT_LOCK:

        # Avoid repeated identical exfiltration alerts
        for previous in reversed(
            ALL_ALERTS[-20:]
        ):

            if (
                previous.get("type")
                == "EXFILTRATION"
                and previous.get("pid")
                == pid
                and previous.get("file")
                == filepath
                and previous.get("remote_ip")
                == remote_ip
                and previous.get("remote_port")
                == remote_port
            ):

                return

        ALL_ALERTS.append(
            alert
        )

        if len(ALL_ALERTS) > 500:

            del ALL_ALERTS[:-500]

    save_report()

    print("=" * 60)
    print("🚨 POSSIBLE DATA EXFILTRATION")
    print(f"⏰ Time      : {now}")
    print(f"💻 Process   : {process_name}")
    print(f"🆔 PID       : {pid}")
    print(f"📄 Sensitive : {filepath}")
    print(f"🌍 Remote IP : {remote_ip}")
    print(f"🔌 Port      : {remote_port}")
    print("🎯 Risk      : 🔴 CRITICAL")
    print(f"💡 Reason    : {reason}")
    print(f"📊 Report    : {REPORT_FILE}")
    print("=" * 60)


# ============================================================
# FATRACE PARSER
# ============================================================

def parse_fatrace_line(line):

    line = line.strip()

    if not line:
        return

    pattern = (
        r"^(.+?)\((\d+)\):\s+"
        r"([A-Za-z]+)\s+(.+)$"
    )

    match = re.match(
        pattern,
        line
    )

    if not match:
        return

    process_name = match.group(
        1
    ).strip()

    pid = match.group(
        2
    ).strip()

    action = match.group(
        3
    ).strip()

    filepath = match.group(
        4
    ).strip()

    if process_name.lower() == "fatrace":
        return

    filepath = filepath.strip(
        '"'
    )

    if is_sensitive_file(
        filepath
    ):

        add_file_alert(
            process_name,
            pid,
            action,
            filepath
        )


# ============================================================
# FATRACE MONITOR
# ============================================================

def fatrace_monitor():

    global FATRACE_PROCESS

    print()
    print("👁️ Starting kernel-level file monitor...")
    print("🔧 Source: fatrace")
    print("📁 Monitoring: /home + /root")
    print()

    try:

        FATRACE_PROCESS = subprocess.Popen(
            [
                "fatrace"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

    except FileNotFoundError:

        print(
            "❌ fatrace is not installed."
        )

        print(
            "Run: sudo apt install fatrace"
        )

        return

    except Exception as error:

        print(
            f"❌ Could not start fatrace: {error}"
        )

        return

    print(
        f"✅ fatrace started "
        f"(PID: {FATRACE_PROCESS.pid})"
    )

    print(
        "🔍 Waiting for sensitive file activity..."
    )

    print()

    try:

        for line in FATRACE_PROCESS.stdout:

            if STOP_EVENT.is_set():
                break

            parse_fatrace_line(
                line
            )

    except Exception as error:

        if not STOP_EVENT.is_set():

            print(
                f"⚠️ fatrace monitor error: {error}"
            )

    finally:

        if FATRACE_PROCESS:

            try:
                FATRACE_PROCESS.terminate()
            except Exception:
                pass


# ============================================================
# NETWORK MONITOR
# ============================================================

def check_network_connections():

    print()
    print("🌐 Checking internet connections...")
    print("=" * 60)

    suspicious_found = False

    try:

        connections = psutil.net_connections(
            kind="inet"
        )

        for connection in connections:

            if connection.status != "ESTABLISHED":
                continue

            if not connection.raddr:
                continue

            remote_ip = connection.raddr.ip

            remote_port = connection.raddr.port

            pid = connection.pid

            if not pid:
                continue

            process_name = "Unknown"

            try:

                process_name = (
                    psutil.Process(
                        pid
                    ).name()
                )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
            ):

                process_name = "Unknown"

            # ==================================================
            # Check recent sensitive-file access
            # ==================================================

            possible_exfiltration = False

            exfiltration_file = None

            try:

                pid_number = int(pid)

                with SENSITIVE_ACCESS_LOCK:

                    access = RECENT_SENSITIVE_ACCESS.get(
                        pid_number
                    )

                if access:

                    age = (
                        time.time()
                        - access["time"]
                    )

                    if age <= SENSITIVE_ACCESS_WINDOW:

                        possible_exfiltration = True

                        exfiltration_file = (
                            access["file"]
                        )

            except Exception:
                pass

            # ==================================================
            # Dangerous port detection
            # ==================================================

            if remote_port in DANGER_PORTS:

                suspicious_found = True

                now = datetime.now().strftime(
                    "%H:%M:%S"
                )

                print(
                    "=" * 60
                )

                print(
                    "🚨 SUSPICIOUS CONNECTION!"
                )

                print(
                    f"⏰ Time      : {now}"
                )

                print(
                    f"💻 Process   : {process_name}"
                )

                print(
                    f"🆔 PID       : {pid}"
                )

                print(
                    f"🌍 Remote IP : {remote_ip}"
                )

                print(
                    f"🔌 Port      : {remote_port}"
                )

                print(
                    "🎯 Risk      : 🔴 CRITICAL"
                )

                print(
                    "=" * 60
                )

            # ==================================================
            # Possible data exfiltration
            # ==================================================

            if (
                possible_exfiltration
                and process_name.lower()
                not in SAFE_PROCESSES
            ):

                suspicious_found = True

                add_exfiltration_alert(
                    process_name,
                    pid,
                    exfiltration_file,
                    remote_ip,
                    remote_port
                )

        # ======================================================
        # Remove expired sensitive access records
        # ======================================================

        current_time = time.time()

        with SENSITIVE_ACCESS_LOCK:

            expired = []

            for stored_pid, access in (
                RECENT_SENSITIVE_ACCESS.items()
            ):

                if (
                    current_time
                    - access["time"]
                    > SENSITIVE_ACCESS_WINDOW
                ):

                    expired.append(
                        stored_pid
                    )

            for stored_pid in expired:

                del RECENT_SENSITIVE_ACCESS[
                    stored_pid
                ]

    except Exception as error:

        print(
            f"⚠️ Network monitor error: {error}"
        )

    if not suspicious_found:

        print(
            "✅ No suspicious connections found"
        )

    print(
        "=" * 60
    )


# ============================================================
# NETWORK THREAD
# ============================================================

def network_monitor():

    while not STOP_EVENT.is_set():

        check_network_connections()

        STOP_EVENT.wait(
            0.2
        )


# ============================================================
# HTML REPORT
# ============================================================

def save_report():

    with ALERT_LOCK:

        alerts = list(
            ALL_ALERTS
        )

    total = len(
        alerts
    )

    critical = sum(
        1
        for alert in alerts
        if "CRITICAL"
        in alert["risk"]
    )

    suspicious = sum(
        1
        for alert in alerts
        if "SUSPICIOUS"
        in alert["risk"]
    )

    safe = sum(
        1
        for alert in alerts
        if "SAFE"
        in alert["risk"]
    )

    unknown = sum(
        1
        for alert in alerts
        if "UNKNOWN"
        in alert["risk"]
    )

    generated = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    page = f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta http-equiv="refresh" content="5">

<title>GhostWatch Security Dashboard</title>

<style>

body {{
    background: #080808;
    color: #eeeeee;
    font-family: monospace;
    margin: 0;
    padding: 30px;
}}

h1 {{
    text-align: center;
    color: #00ff88;
    border-bottom: 2px solid #00ff88;
    padding-bottom: 15px;
}}

.subtitle {{
    text-align: center;
    color: #888888;
    margin-bottom: 30px;
}}

.stats {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 15px;
    margin-bottom: 30px;
}}

.card {{
    background: #111111;
    border: 1px solid #333333;
    border-radius: 8px;
    padding: 20px;
    text-align: center;
}}

.number {{
    font-size: 32px;
    font-weight: bold;
}}

.label {{
    color: #888888;
    margin-top: 8px;
}}

.total {{
    color: #00ff88;
}}

.critical {{
    color: #ff3333;
}}

.suspicious {{
    color: #ffff00;
}}

.safe {{
    color: #00ff88;
}}

.unknown {{
    color: #ff8800;
}}

.alert {{
    background: #111111;
    border-left: 5px solid #555555;
    padding: 18px;
    margin-bottom: 12px;
    border-radius: 5px;
}}

.alert-critical {{
    border-left-color: #ff3333;
}}

.alert-suspicious {{
    border-left-color: #ffff00;
}}

.alert-safe {{
    border-left-color: #00ff88;
}}

.alert-unknown {{
    border-left-color: #ff8800;
}}

.row {{
    margin: 7px 0;
}}

.key {{
    color: #777777;
}}

.value {{
    color: #ffffff;
    font-weight: bold;
}}

.footer {{
    margin-top: 30px;
    color: #666666;
    text-align: center;
}}

</style>

</head>

<body>

<h1>👻 GhostWatch Security Dashboard</h1>

<div class="subtitle">

Live Behavioral File Monitoring

<br>

Last updated: {generated}

</div>

<div class="stats">

<div class="card">
<div class="number total">{total}</div>
<div class="label">TOTAL</div>
</div>

<div class="card">
<div class="number critical">{critical}</div>
<div class="label">CRITICAL</div>
</div>

<div class="card">
<div class="number suspicious">{suspicious}</div>
<div class="label">SUSPICIOUS</div>
</div>

<div class="card">
<div class="number safe">{safe}</div>
<div class="label">SAFE</div>
</div>

<div class="card">
<div class="number unknown">{unknown}</div>
<div class="label">UNKNOWN</div>
</div>

</div>

<h2>🚨 Live Security Activity</h2>
"""

    if not alerts:

        page += """
<div class="alert alert-safe">

<div class="row">
<span class="value">
✅ No suspicious activity detected
</span>
</div>

</div>
"""

    else:

        for alert in reversed(
            alerts
        ):

            risk = alert["risk"]

            if "CRITICAL" in risk:

                css_class = (
                    "alert-critical"
                )

            elif "SUSPICIOUS" in risk:

                css_class = (
                    "alert-suspicious"
                )

            elif "SAFE" in risk:

                css_class = (
                    "alert-safe"
                )

            else:

                css_class = (
                    "alert-unknown"
                )

            page += f"""
<div class="alert {css_class}">

<div class="row">

<span class="key">
TIME:
</span>

<span class="value">
{html.escape(alert["time"])}
</span>

</div>

<div class="row">

<span class="key">
PROCESS:
</span>

<span class="value">
{html.escape(str(alert["process"]))}
</span>

</div>

<div class="row">

<span class="key">
PID:
</span>

<span class="value">
{html.escape(str(alert["pid"]))}
</span>

</div>

<div class="row">

<span class="key">
ACTION:
</span>

<span class="value">
{html.escape(str(alert["action"]))}
</span>

</div>

<div class="row">

<span class="key">
FILE:
</span>

<span class="value">
{html.escape(str(alert["file"]))}
</span>

</div>

<div class="row">

<span class="key">
RISK:
</span>

<span class="value">
{html.escape(str(alert["risk"]))}
</span>

</div>

<div class="row">

<span class="key">
REASON:
</span>

<span class="value">
{html.escape(str(alert["reason"]))}
</span>

</div>
"""

            if alert.get(
                "type"
            ) == "EXFILTRATION":

                page += f"""

<div class="row">

<span class="key">
REMOTE IP:
</span>

<span class="value">
{html.escape(str(alert.get("remote_ip", "")))}
</span>

</div>

<div class="row">

<span class="key">
REMOTE PORT:
</span>

<span class="value">
{html.escape(str(alert.get("remote_port", "")))}
</span>

</div>
"""

            page += """
</div>
"""

    page += """

<div class="footer">

👻 GhostWatch — Behavioral Security Monitor

</div>

</body>

</html>
"""

    try:

        with open(
            REPORT_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                page
            )

    except Exception as error:

        print(
            f"⚠️ Report error: {error}"
        )


# ============================================================
# SHUTDOWN
# ============================================================

def shutdown():

    STOP_EVENT.set()

    global FATRACE_PROCESS

    if FATRACE_PROCESS:

        try:

            FATRACE_PROCESS.terminate()

            FATRACE_PROCESS.wait(
                timeout=2
            )

        except Exception:

            try:
                FATRACE_PROCESS.kill()
            except Exception:
                pass

    save_report()


# ============================================================
# MAIN
# ============================================================

def main():

    setup_directories()

    print("=" * 60)

    print(
        "👻 GhostWatch Started!"
    )

    print(
        "🔍 Behavioral file + network monitoring"
    )

    print(
        "⚙️ File engine: fatrace"
    )

    print(
        "🧠 Behavior engine: file → network correlation"
    )

    print(
        "Press CTRL+C to stop"
    )

    print("=" * 60)

    save_report()

    # --------------------------------------------------------
    # File monitor
    # --------------------------------------------------------

    file_thread = threading.Thread(
        target=fatrace_monitor,
        daemon=True
    )

    file_thread.start()

    # --------------------------------------------------------
    # Network monitor
    # --------------------------------------------------------

    net_thread = threading.Thread(
        target=network_monitor,
        daemon=True
    )

    net_thread.start()

    print()
    print(
        "👁️ GhostWatch is now LIVE..."
    )

    print()
    print(
        f"📊 Dashboard: {REPORT_FILE}"
    )

    print()

    try:

        while True:

            time.sleep(
                1
            )

    except KeyboardInterrupt:

        print()
        print(
            "🛑 Stopping GhostWatch..."
        )

        shutdown()

        print(
            f"📊 Final report: {REPORT_FILE}"
        )

        print(
            "👻 GhostWatch stopped."
        )


# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":

    main()
