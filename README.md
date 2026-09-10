# 🛡️ Tier 1-3 SOC Operations Center & Threat Simulator

An advanced, all-in-one Security Operations Center (SOC) desktop application built with **Python**, **PyQt6**, **Nmap**, and **Scapy**. Designed for security analysts and engineers to monitor system logs, analyze threats in real-time, perform network and port scanning, sniff live network packets, and execute incident containment.

---

## 🌟 Features / الميزات الأساسية

1. **Live Log Monitoring & SIEM Triage (Tier 1/2):**
   * Real-time monitoring of system log files with automated parsing of failed login attempts.
   * Automated IP reputation check using the **AbuseIPDB API**.
   * Instant Telegram Bot alerting for high-severity security incidents.

2. **Network & Port Scanning (Tier 3 Reconnaissance):**
   * Integrated asynchronous background worker using **Nmap** to discover live hosts, open ports, and subnet vulnerabilities.

3. **Live Network Traffic Analysis (Packet Sniffing):**
   * Real-time packet capture and protocol analysis (TCP, UDP, IP) powered by **Scapy**.

4. **Incident Forensics & Containment:**
   * Detailed incident triage reports, behavior verification tools, and immediate firewall containment command generation.

5. **Threat Hunting & Export:**
   * Historical IOC (Indicator of Compromise) search engine across live logs and session events.
   * Export fully structured JSON incident reports.

6. **Modern Dark UI:**
   * Professional, sleek Dark Mode interface built with custom PyQt6 QSS styling.

---

## 🛠️ Prerequisites & Installation Requirements / المتطلبات الأساسية وتثبيتها

### 1. Python & Dependencies
* **Python 3.10+** installed on your system.

### 2. Nmap (Required for Network Scans)
* Download and install the official **Nmap** binary from [nmap.org](https://nmap.org/).
* Ensure **"Add to PATH"** is checked during installation.
* Verify with: `nmap --version`

### 3. Npcap / WinPcap (Required for Scapy Packet Sniffing on Windows)
* Download and install **Npcap** from [npcap.com](https://npcap.com/).
* Check the box: **"Install Npcap in WinPcap API-compatible Mode"**.

---

## 🚀 Quick Start / خطوات التشغيل السريعة

1. Open project directory.
2. Install Python dependencies inside your virtual environment:
   ```bash
   pip install PyQt6 requests scapy

   Run the application using the included batch file (Run as Administrator for full network packet capture and Nmap support):

Right-click on run.bat and select Run as Administrator.

👤 Author / المطوّر
Ahmad Nori

📄 License / الترخيص
This project is open-source and available under the MIT License.