# ⚡ Crazy Alchemy v3.0
### Next-Generation Windows 11 Firewall, Threat Defense & Active Cyber Deception Suite

[![Platform](https://img.shields.io/badge/Platform-Windows%2011%20%7C%20Windows%2010%20(x64)-0078D4?style=flat&logo=windows)](https://microsoft.com/windows)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![PyQt](https://img.shields.io/badge/GUI-PyQt6-41CD52?style=flat&logo=qt)](https://riverbankcomputing.com/software/pyqt)
[![YARA](https://img.shields.io/badge/Signatures-YARA%20v4.3%2B-red?style=flat)](https://virustotal.github.io/yara/)
[![Tests](https://img.shields.io/badge/Test%20Suite-Verified%20(100%25)-brightgreen?style=flat)](tests/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 🌟 Executive Summary

**Crazy Alchemy v3.0** (architected by **Vitorius**) is an enterprise-grade endpoint security, firewall orchestration, and proactive deception defense suite engineered specifically for modern Windows 64-bit platforms (Windows 11 & Windows 10). Designed to overcome the opacity, telemetry bloat, and operational limitations of default operating system defenses, Crazy Alchemy combines the granular packet and rule controls of enterprise firewalls with a multi-layered **Tri-Engine Antivirus**, **TrapNet Active Deception Honeypots**, **HoneyToken Ransomware Canaries**, **Cross-Browser Network Guard with Native Ad-Blocking**, and behavioral **Process Lineage Verification**.

Whether deployed in a zero-trust enterprise environment, an untrusted public Wi-Fi hotspot, a developer workstation with local agentic AI tools (Antigravity), or an esports gaming station requiring ultra-low latency, Crazy Alchemy delivers complete situational awareness and autonomous threat neutralization without degrading system performance.

---

## 🚀 What's New in Version 3.0

- 🛡️ **Zero Unintended Tool Blocking (Antigravity & Developer Safety)**:
  - Permanent kernel-level loopback (`127.0.0.1`, `::1`) allow rules ensure local AI assistants (Antigravity), IDE backends, language servers, and IPC sockets never get severed.
  - Protected binary registry (`antigravity.exe`, `code.exe`, `cursor.exe`, `python.exe`, `node.exe`, `git.exe`) prevents automated defensive tarpits from interfering with developer workflows.
- 🎮 **Re-engineered Security Posture Profiles**:
  - **Gaming Profile**: Ultra-low latency packet flow, game server browser ping support, and out-of-the-box whitelisting for Steam, Discord Voice, Battle.net, Epic Games, Riot Games (Valorant/LoL), Minecraft, and Xbox Live / Game Pass.
  - **Corporate Profile**: SOC 2 compliance posture with zero-trust inbound blocking, stealth ICMP suppression, and full outbound enterprise support (HTTP, HTTPS, SSH, Git, NTP, and VPN IPSec).
  - **Home & Public Profiles**: Tailored local sharing vs. untrusted public Wi-Fi drop policies.
  - **Maximum Security**: Hardened fortress posture with strict port whitelisting, explicit loopback protection, and canary tripwires.
- 📡 **Intelligent BeaconEntropyShaper™ (Zero False Positives)**:
  - Distinguishes persistent established sockets from newly created connections, eliminating false-positive C2 alarms on continuous application sessions (e.g. Antigravity API streams, web sockets).
- 🌐 **Web Browser Detection & 1-Click Launch**:
  - Auto-detects installed web browsers via Windows Registry (`StartMenuInternet`, `App Paths`) and filesystem roots (Brave, Google Chrome, Microsoft Edge, Mozilla Firefox, Opera, Vivaldi).
  - Native Windows PE icon extraction (`QFileIconProvider`) displays official browser icons directly in the Settings UI.
- 🗑️ **Robust Native Win32 Uninstaller Engine**:
  - Complete Control Panel / Windows Settings registration removal, service teardown, firewall rule cleanup, and elevated batch self-deletion support.

---

## 🛡️ Core Architectural Pillars

```
                     ┌─────────────────────────────────────────────────────────┐
                     │          Crazy Alchemy Unified Security Engine          │
                     └────────────────────────────┬────────────────────────────┘
                                                  │
         ┌────────────────────────┬───────────────┴───────────────┬────────────────────────┐
         │                        │                               │                        │
         ▼                        ▼                               ▼                        ▼
┌──────────────────┐    ┌──────────────────┐            ┌──────────────────┐    ┌──────────────────┐
│ Windows Firewall │    │    Tri-Engine    │            │     TrapNet      │    │  Browser Shield  │
│  Orchestration   │    │ Antivirus & YARA │            │ Active Deception │    │  & Ad-Block Hub  │
├──────────────────┤    ├──────────────────┤            ├──────────────────┤    ├──────────────────┤
│• netsh Filtering │    │• 500k+ Hash DB   │            │• 9 Decoy Sockets │    │• Chrome/Edge/Brave│
│• Panic Lockdown  │    │• Shannon Entropy │            │• Canary Baits    │    │• Firefox / Opera │
│• Socket Monitor  │    │• Encrypted Vault │            │• Auto-Banning    │    │• Telemetry Strip │
│• 5 Posture Profiles│  │• Offline Cleaner │            │• Payload Sniffer │    │• DNS-Level Drop  │
└──────────────────┘    └──────────────────┘            └──────────────────┘    └──────────────────┘
         │                        │                               │                        │
         └────────────────────────┼───────────────────────────────┼────────────────────────┘
                                  │
         ┌────────────────────────┴───────────────────────────────┐
         ▼                                                        ▼
┌───────────────────────────────────────┐        ┌───────────────────────────────────────┐
│     Novel Breakthrough Defenses       │        │     Adaptive Security Framework       │
├───────────────────────────────────────┤        ├───────────────────────────────────────┤
│• ChronoVault™ CoW Ransomware Rollback │        │• AegisChameleon™ Intent Hardening     │
│• GhostGate™ Unbacked Stack Telemetry  │        │• Financial Bastion Mode               │
│• LineageGuard™ LOLBin Ancestry Shield │        │• Ephemeral Dev-Port Leases            │
│• BeaconEntropyShaper™ C2 Tarpit       │        │• MirageNet™ Virtual Decoy Shell & Maze│
└───────────────────────────────────────┘        └───────────────────────────────────────┘
```

---

## 🚀 Key Feature Breakdown

### 1. Dual-Engine Firewall & Network Orchestration
- **Native WFP & AdvFirewall Control:** Direct interface with the Windows Advanced Firewall and Windows Filtering Platform (`netsh advfirewall` & native APIs). Programmatically manages inbound and outbound rules, custom port policies, executable permissions, and protocol filtering.
- **Loopback & Developer Tool Protection:** Automatically reserves loopback traffic (`127.0.0.1`, `::1`) in both directions. Never severs local agent communication or development servers.
- **Panic Lockdown Protocol (`Alt + P`):** Immediate emergency circuit breaker. Instantly severs network communications across all adapters without crashing active network interfaces.
- **ICMP Stealth Masking:** One-click suppression of ICMPv4 and ICMPv6 echo requests, rendering your machine invisible to unauthorized reconnaissance scans on local area networks.
- **Live Socket & Bandwidth Forensics:** High-frequency socket watcher displaying remote IPs, destination ports, connection state (`ESTABLISHED`, `LISTENING`), real-time transfer speeds, and executable paths mapped directly to PID.

### 2. Tri-Engine Antivirus & Threat Protection Subsystem
- **500,000+ Verified Signature SQLite Database:** Local, offline-capable database indexing verified malware hashes (SHA-256 and MD5) compiled from trusted intelligence feeds including Abuse.ch MalwareBazaar.
- **YARA Dynamic Heuristic Scanner:** Embedded YARA v4.3+ ruleset specifically tuned for detecting malicious payloads, process injection tools, ransomware ransom notes, infostealers, Discord token extractors, and cryptocurrency miners.
- **Shannon Entropy Analysis:** Deep Portable Executable (PE) inspection calculating file section entropy. Flags stealthy, packed, crypted, or obfuscated payloads (entropy score > 7.2) typically missed by standard signature scanning.
- **Encrypted Quarantine Vault:** Malicious binaries are instantly isolated, neutralized via XOR scrambling, and safely indexed in a secure vault under `.vitorius_quarantine` extensions. Supports deep forensic header viewing, permanent deletion, or verified false-positive restoration with automated whitelist integration.
- **Offline Boot Remediator (Defender-Style):** Schedules an isolated, zero-network sanitization routine executed at system reboot via Windows `RunOnce` and Task Scheduler. Force-terminates persistent rootkits, removes malicious autoruns, and executes low-level `MoveFileExW` boot-time purges.

### 3. TrapNet™ Active Deception & HoneyToken Defense
Instead of merely defending against attacks, Crazy Alchemy actively deceives and entraps network intruders:
- **Multi-Port Decoy Listeners:** Dynamically binds simulated deception honeypots across high-value attack surfaces (SSH, Telnet, SMB, SQL, RDP, VNC).
- **Autonomous Threat Neutralization:** Sockets utilize `SO_EXCLUSIVEADDRUSE` to prevent binding conflicts. Intruder packets are sniffed, logged in raw hex/ASCII, and the attacker's IP is automatically blacklisted with immediate Windows Firewall blocking rules.
- **HoneyToken Canary Baits:** Deploys simulated high-value target files (e.g., `passwords_production_backup.xlsx`, `aws_master_keys.json`, `corporate_vpn_credentials.env`) into sensitive user directories. Constantly monitored by low-level filesystem watchers; any modification, unauthorized read, or ransomware encryption attempt immediately raises a critical incident alarm.

### 4. Cross-Browser Security Companion & Native Ad Blocker
A unified, private security bridge linking your desktop security engine directly with all major web browsers:
- **Broad Browser Ecosystem Support:** Ready-to-deploy, Manifest V3-compatible companions for **Brave**, **Google Chrome**, **Microsoft Edge**, **Opera**, **Mozilla Firefox**, and **Vivaldi**.
- **Real-Time Malicious URL Filtering:** Browser navigation requests are audited locally against threat feeds to stop phishing campaigns, drive-by downloads, zero-day exploit kits, and malicious redirectors.
- **Ad & Tracker Blocking:** High-throughput declarative network request filtering stops intrusive video ads, display banners, tracking beacons, cross-site telemetry, and cryptojacking scripts.

### 5. Calibrated Security Profiles & Disaster Recovery
Rapidly switch the entire host security posture with a single click:
- **Home (Private):** Permits local network discovery, trusted file and printer sharing, and home media streaming while maintaining robust inbound protection.
- **Public (Untrusted Hotspot):** Aggressive drop-all inbound policy; closes NetBIOS, SMB, and discovery ports; enables ICMP ping suppression; arms TrapNet decoy listeners.
- **Corporate (Strict Compliance):** Aligned with SOC 2, ISO 27001, and NIST guidelines. Zero-trust inbound, verified corporate egress (DNS, HTTPS, HTTP, SSH, Git, NTP, IPSec VPN).
- **Gaming (Low-Latency Ultra):** Authorizes legitimate multiplayer gaming traffic, pauses background update tasks, suppresses desktop notification popups, and minimizes network jitter while keeping baseline firewall shields active.
- **Maximum Security (Paranoid / HIPAA):** Complete zero-trust drop-all posture with strict port whitelisting, loopback protection, and full canary baiting.

---

## 💻 Technical Specifications

| Component | Technical Implementation |
| :--- | :--- |
| **GUI Framework** | PyQt6 with custom dynamic QSS stylesheet engine |
| **Target OS** | Windows 11 (21H2, 22H2, 23H2, 24H2) / Windows 10 (64-bit) |
| **Signature Engine** | SQLite3 indexing 500,000+ SHA-256 & MD5 hashes |
| **Heuristics & Rules** | YARA v4.3+ engine with custom rule compiler |
| **Filesystem Watcher** | Multi-threaded Windows `ReadDirectoryChangesW` via `watchdog` |
| **Network Control** | Windows Filtering Platform (WFP) & `netsh advfirewall` CLI |
| **Deception Layer** | Python `socket` with `SO_EXCLUSIVEADDRUSE` & WFP rule injector |
| **Browser Bridge** | Localhost HTTP / WebSocket companion daemon with Manifest V3 |
| **Runtime Dependencies** | `PyQt6`, `psutil`, `watchdog`, `yara-python`, `pywin32` |
| **Build Dependency** | `pyinstaller>=6.0.0` (packaging only, separated from runtime) |

---

## 📥 Installation & Quick Start

### Quick 1-Click Setup (Recommended)
1. Clone or download the repository to your local drive (e.g., `D:\Crazy_Alchemy_3_0`).
2. *(Optional - For Offline/Air-gapped Setups)* Run `download_prerequisites.bat` to automatically download the official Python installer and all binary wheels into `prerequisites\`.
3. Double-click `setup.bat` (or execute `CrazyAlchemy.bat`) to install or launch the application.

### Manual Setup via Command Prompt
```powershell
# 1. Clone repository
git clone https://github.com/Vitorius-Crazy-Alchemy/Crazy_Alchemy.git
cd Crazy_Alchemy

# 2. Install runtime dependencies
pip install -r requirements.txt

# 3. Seed baseline malware signatures (if not pre-populated)
python data\signatures\seed_hashes.py

# 4. Launch Crazy Alchemy v3.0
python main_win.py
```

### Uninstallation
Run `uninstall.bat` as Administrator or launch uninstaller via Windows Control Panel / Installed Apps.

---

## 🔒 Security & Privacy Guarantee

- **Zero Cloud Data Telemetry:** Crazy Alchemy collects zero personal files, browsing histories, or user identifiers. All hash lookups, entropy analyses, and firewall decisions execute 100% locally on your machine.
- **Open-Source Transparency:** Every component—from quarantine vault XOR routines to deception decoy listeners—is fully auditable in pure Python and Win32 APIs.

---

## 📄 License & Credits

- **Author & Architect:** Vitorius
- **Edition:** Crazy Alchemy v3.0
- **License:** Released under the [MIT License](LICENSE).
