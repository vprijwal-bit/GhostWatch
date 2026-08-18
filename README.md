<div align="center">

```
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗    ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██║  ███╗███████║██║   ██║███████╗   ██║       ██║ █╗ ██║███████║   ██║   ██║     ███████║
██║   ██║██╔══██║██║   ██║╚════██║   ██║       ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║       ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝        ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
```

### 👻 Real-Time Behavioral Security Monitor for Linux

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=linux)
![Category](https://img.shields.io/badge/Category-Blue%20Team-00aa00?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Working%20Prototype-brightgreen?style=for-the-badge)
![GitHub Stars](https://img.shields.io/github/stars/vprijwal-bit/GhostWatch?style=for-the-badge)

**GhostWatch watches what no antivirus does — live behavior, not just file signatures.**

[Features](#-features) • [How It Works](#-how-it-works) • [Install](#-installation) • [Usage](#-usage) • [Demo](#-demo-output) • [Roadmap](#-roadmap)

</div>

---

## 🔥 What Is GhostWatch?

Most antivirus tools scan files and check signatures. They tell you what is **already infected**.

**GhostWatch is different.** It watches your system in real time and catches what is happening **right now** — which process is reading your private documents, which app is secretly connecting to the internet, and whether something is trying to steal your data.

This is the same technology that enterprise tools like **CrowdStrike** and **SentinelOne** charge $50,000/year for.

**GhostWatch is free. Forever. Open source.**

---

## ✨ Features

| Feature | Description |
|---|---|
| 👁️ **Live File Watcher** | Detects any process accessing sensitive files instantly |
| 🌐 **Network Spy Catcher** | Scans all internet connections every 10 seconds |
| 🧠 **Smart Risk Engine** | Classifies every event as Safe / Suspicious / Critical |
| 📊 **HTML Dashboard** | Beautiful browser-based security report auto-generated |
| 🔴 **Exfiltration Detection** | Catches when a process reads a file AND connects to internet |
| ⚡ **Zero Configuration** | Run one command — works immediately |

---

## 🧠 How It Works

```
                    File Activity Detected
                            │
                            ▼
                    Sensitive File?
                       /        \
                     No          Yes
                     │            │
                     ▼            ▼
                   Ignore    Identify Process
                                  │
                                  ▼
                           Analyze Behavior
                                  │
                    ┌─────────────┼─────────────┐
                    │             │             │
                    ▼             ▼             ▼
                  SAFE       SUSPICIOUS     UNKNOWN
                    │             │             │
                    └─────────────┼─────────────┘
                                  │
                                  ▼
                           Generate Alert
                                  │
                                  ▼
                       Check Network Activity
                                  │
                                  ▼
                      Possible Exfiltration?
                                  │
                                  ▼
                          🔴 CRITICAL ALERT
```

---

## 🚨 Risk Levels

| Level | Symbol | Meaning |
|---|---|---|
| Critical | 🔴 | Unknown process or known malware tool accessed sensitive file |
| Suspicious | 🟡 | Command-line tool (bash, curl, wget) accessed sensitive file |
| Unknown | 🟠 | Unrecognized process accessed sensitive file |
| Safe | 🟢 | Known safe app (browser, text editor) accessed sensitive file |

---

## 💻 Demo Output

**Terminal — Live Alerts:**
```
==================================================
👻 GhostWatch Started!
🔍 Watching files + internet connections...
Press CTRL+C to stop
==================================================
✅ Watching: /root
✅ Watching: /home
👁  GhostWatch is now LIVE...

==================================================
🚨 FILE ALERT!
⏰ Time      : 09:24:31
📄 File      : /home/kali/passwords.txt
💻 Process   : cat (PID: 2341)
🎯 Risk      : 🟡 SUSPICIOUS
📊 Report    : /home/kali/GhostWatch/report.html
==================================================

🌐 Checking internet connections...
==================================================
✅ No suspicious connections found
==================================================

🚨 POSSIBLE DATA EXFILTRATION!
⏰ Time      : 09:31:12
💻 Process   : python3
📄 Sensitive : /home/kali/passwords.txt
🌍 Remote IP : 192.168.1.45
🔌 Port      : 4444
⚠️  Risk      : 🔴 CRITICAL
==================================================
```

**HTML Dashboard — Auto-Generated Report:**
```
┌─────────────────────────────────────────────┐
│  👻 GhostWatch Security Report               │
│  Generated: 2025-01-15 09:35:00              │
├──────────┬──────────┬────────────┬──────────┤
│  TOTAL   │ CRITICAL │ SUSPICIOUS │   SAFE   │
│    12    │    3     │     7      │    2     │
├──────────┴──────────┴────────────┴──────────┤
│  📋 Alert Log                                │
│                                              │
│  🔴 09:31:12  python3  passwords.txt         │
│  🟡 09:24:31  cat      passwords.txt         │
│  🟢 09:15:44  firefox  report.pdf            │
└─────────────────────────────────────────────┘
```

---

## ⚙️ Installation

**Clone the repository:**
```bash
git clone https://github.com/vprijwal-bit/GhostWatch.git
cd GhostWatch
```

**Install dependencies:**
```bash
pip install watchdog psutil rich --break-system-packages
```

**Verify Python:**
```bash
python3 --version
```

---

## ▶️ Usage

**Run GhostWatch:**
```bash
python3 ghost_watch.py
```

**Run with root (recommended for full access):**
```bash
sudo python3 ghost_watch.py
```

**View your security dashboard:**
```bash
firefox /home/kali/GhostWatch/report.html
```

**Stop GhostWatch:**
```
CTRL + C
```

---

## 🧪 Testing

**Test 1 — Trigger a file alert:**
```bash
echo "password=secret123" > /home/kali/passwords.txt
```

**Test 2 — Read a sensitive file:**
```bash
cat /home/kali/passwords.txt
```

**Test 3 — Create a fake key file:**
```bash
echo "mykey" > /home/kali/id.key
```

Each command above will instantly trigger a GhostWatch alert.

---

## 📁 Project Structure

```
GhostWatch/
│
├── ghost_watch.py                        ← Main monitoring program
├── ghost_watch_working.py                ← Behavioral monitoring version
├── ghost_watch_sensitive_filter.py       ← Sensitive file filter version
├── report.html                           ← Auto-generated dashboard (gitignored)
├── .gitignore                            ← Protects sensitive files
└── README.md                             ← This file
```

---

## 🛡️ Detection Logic

GhostWatch uses **behavioral correlation**, not signatures.

```
Sensitive File Access
        +
Suspicious Process
        +
Network Connection
        =
🔴 Possible Security Incident
```

This means GhostWatch can catch **zero-day threats** that no antivirus signature database has seen yet — because it watches behavior, not file names.

---

## 🔬 Cybersecurity Concepts Demonstrated

- Blue Team security
- Endpoint behavioral monitoring
- Host-based intrusion detection
- File system monitoring
- Process analysis
- Network connection monitoring
- Data exfiltration detection
- Security alert classification
- Linux security automation
- Python security tooling

---

## 🔮 Roadmap

- [ ] Machine learning anomaly detection
- [ ] IP reputation checking (VirusTotal integration)
- [ ] Email / SMS alert notifications
- [ ] SQLite event logging database
- [ ] SIEM integration (Splunk / ELK)
- [ ] Systemd service (auto-start on boot)
- [ ] Windows support
- [ ] Configurable sensitive file rules
- [ ] Automatic incident severity scoring
- [ ] Real-time dashboard with live refresh

---

## 💻 Requirements

| Requirement | Version |
|---|---|
| Operating System | Kali Linux / Ubuntu / Debian |
| Python | 3.x |
| Git | Any |

---

## 🔒 Security Notice

GhostWatch will **never** upload your data anywhere. It runs completely locally on your machine.

The `.gitignore` file prevents sensitive files from being uploaded to GitHub:
```
passwords.txt
*.pem
*.key
*.env
report.html
__pycache__/
```

Never commit real credentials or private keys to any public repository.

---

## ⚠️ Ethical Use

GhostWatch is built for:

- Cybersecurity education
- Blue Team / defensive security
- Endpoint monitoring on systems you own
- Authorized security testing in lab environments

**Only monitor systems you own or have explicit permission to monitor.**

---

## 👨‍💻 Author

**vprijwal-bit**

[![GitHub](https://img.shields.io/badge/GitHub-vprijwal--bit-181717?style=for-the-badge&logo=github)](https://github.com/vprijwal-bit/GhostWatch)

---

## 📌 Project Info

| Field | Info |
|---|---|
| Project Name | GhostWatch |
| Category | Cybersecurity / Blue Team |
| Language | Python 3 |
| Platform | Kali Linux |
| Status | Working Prototype |
| License | MIT |

---

## 📄 Disclaimer

GhostWatch is an educational and defensive cybersecurity project.
Only use GhostWatch on systems where you have full authorization to perform monitoring.
The author is not responsible for any misuse of this tool.

---

<div align="center">

**If GhostWatch helped you learn — give it a ⭐ star on GitHub!**

Made with 🖤 for the cybersecurity community

</div>
