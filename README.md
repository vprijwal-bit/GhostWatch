
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

**Step 1 — Clone the repository:**
```bash
git clone https://github.com/vprijwal-bit/GhostWatch.git
cd GhostWatch
```

**Step 2 — Install Python dependencies:**
```bash
pip install watchdog psutil rich --break-system-packages
```

**Step 3 — Install fatrace:**
```bash
sudo apt update
sudo apt install fatrace -y
```

**Step 4 — Verify fatrace:**
```bash
which fatrace
```
Expected output:
```
/usr/sbin/fatrace
```
> ⚠️ If `which fatrace` returns `fatrace not found` — install it before running GhostWatch.

**Step 5 — Verify Python:**
```bash
python3 --version
```

---

## ▶️ Usage

```bash
cd ~/GhostWatch
```

**Normal run:**
```bash
python3 ghost_watch.py
```

**Recommended (full access):**
```bash
sudo python3 ghost_watch.py
```

> 🔑 `sudo` / root is recommended for full file-monitoring access.

Wait for:
```
👁 GhostWatch is now LIVE...
```
Keep this terminal running.

---

## 📊 Security Dashboard

Open the auto-generated HTML report in your browser:
```bash
firefox /home/kali/GhostWatch/report.html
```
The dashboard shows all detected security events, risk levels, and generated alerts in real time.

---

## ⏹️ Stop GhostWatch

```
CTRL + C
```
GhostWatch stops monitoring and saves the final report automatically.

---

## 🧪 Testing GhostWatch

> ⚠️ The test file is **NOT** included in this repository. Create your own dummy test file on your own Kali Linux system. Never use real passwords.

**Step 1 — Start GhostWatch (Terminal 1):**
```bash
cd ~/GhostWatch
sudo python3 ghost_watch.py
```
Wait for:
```
👁 GhostWatch is now LIVE...
```
Keep it running.

**Step 2 — Create a dummy sensitive file (Terminal 2):**
```bash
echo "password=secret123" > /home/kali/passwords.txt
```
> This creates a dummy test file only. `password=secret123` is fake test data. Never use a real password.

**Step 3 — Read the sensitive file:**
```bash
cat /home/kali/passwords.txt
```
Expected file content:
```
password=secret123
```
Expected GhostWatch detection:
```
🚨 FILE ACTIVITY DETECTED

Process : cat
Action  : READ
File    : /home/kali/passwords.txt
Risk    : 🟡 SUSPICIOUS
```

**Step 4 — Test a key-like file:**
```bash
echo "mykey" > /home/kali/id.key
```
> This is another dummy test file. May trigger an alert if `.key` is in your sensitive-file patterns.

---

## 🔧 Troubleshooting: fatrace not found

If this command:
```bash
which fatrace
```
Returns:
```
fatrace not found
```

Run:
```bash
sudo apt update
sudo apt install fatrace -y
```

Then verify:
```bash
which fatrace
```
Expected:
```
/usr/sbin/fatrace
```

Restart GhostWatch:
```bash
cd ~/GhostWatch
sudo python3 ghost_watch.py
```

Wait for:
```
👁 GhostWatch is now LIVE...
```

Then test again:
```bash
cat /home/kali/passwords.txt
```

> ⚠️ If the file contents are displayed but GhostWatch does not generate a file activity alert — first check that `fatrace` is installed and that GhostWatch was restarted after installing it.

---

## 🔴 Possible Data Exfiltration Detection

GhostWatch can identify a possible data-exfiltration pattern when:
1. A process accesses a sensitive file
2. The same process is associated with network communication

Example alert:
```
🚨 POSSIBLE DATA EXFILTRATION

Process   : python3
Sensitive : /home/kali/passwords.txt
Remote IP : 127.0.0.1
Port      : 8080
Risk      : 🔴 CRITICAL
```

> `127.0.0.1:8080` is used as a controlled local-lab example only.

> ⚠️ Important: `cat /home/kali/passwords.txt` normally demonstrates the 🟡 SUSPICIOUS file-access detection. The 🔴 CRITICAL alert requires the **additional network-activity condition**. Not every `cat` command produces a CRITICAL alert.

---

## 📋 Testing Summary

| Test | Expected Result |
|------|-----------------|
| Install fatrace | File monitoring available |
| Create passwords.txt | Dummy sensitive file created |
| Start GhostWatch | 👁 GhostWatch is LIVE |
| `cat passwords.txt` | 🟡 SUSPICIOUS |
| Create id.key | Sensitive-file test triggered |
| Sensitive file + network activity | 🔴 CRITICAL |
| Open report.html | Security dashboard loads |

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
## 📸 Real Screenshots

### 🔴 Data Exfiltration Caught Live


![Exfiltration](Screenshot%202026-08-18%20090257.png)



### 🚨 Suspicious File Access Detected


![Suspicious](Screenshot%202026-08-18%20085325.png)



### 📊 GhostWatch Security Dashboard


![Dashboard](Screenshot%202026-08-18%20090338.png)



### 🟢 Smart Process Detection


![Smart](Screenshot%202026-08-18%20090404.png)

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
