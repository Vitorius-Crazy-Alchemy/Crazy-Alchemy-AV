Crazy Alchemy v2.0 "LudaCris" changed to v2.0 "LadyZi"
# ⚡ Crazy Alchemy v2.0 "LadyZi"
### Next-Generation Windows 11 Endpoint Security, Tri-Engine Antivirus & Active Deception Defense Suite



---

## 🌟 Executive Summary

**Crazy Alchemy v2.0 "LadyZi"** (architected by **Vitorius**) is an enterprise-grade endpoint security, firewall orchestration, and proactive deception defense suite engineered specifically for modern Windows 64-bit platforms. Designed to overcome the opacity, telemetry bloat, and operational limitations of default operating system defenses, Crazy Alchemy combines the granular packet and rule controls of enterprise firewalls with a multi-layered **Tri-Engine Antivirus**, **TrapNet Active Deception Honeypots**, **HoneyToken Ransomware Canaries**, **Cross-Browser Web Defense with Native Crazy-Style Ad-Blocking**, and behavioral **Process Lineage Verification**.

Official Source Code & Updates: **[https://github.com/Vitorius-Crazy-Alchemy/Crazy-Alchemy-AV](https://github.com/Vitorius-Crazy-Alchemy/Crazy-Alchemy-AV)**

Whether deployed in a zero-trust enterprise environment, an untrusted public Wi-Fi hotspot, or an esports gaming station requiring ultra-low latency, Crazy Alchemy delivers complete situational awareness and autonomous threat neutralization without degrading system performance.

---

## 🛡️ Core Architectural Overview

```
                     ┌─────────────────────────────────────────────────────────┐
                     │          Crazy Alchemy Unified Security Engine          │
                     │  https://github.com/Vitorius-Crazy-Alchemy/Crazy-Alchemy-AV │
                     └────────────────────────────┬────────────────────────────┘
                                                  │
         ┌────────────────────────┬───────────────┴───────────────┬────────────────────────┐
         │                        │                               │                        │
         ▼                        ▼                               ▼                        ▼
┌──────────────────┐    ┌──────────────────┐            ┌──────────────────┐    ┌──────────────────┐
│ Windows Firewall │    │    Tri-Engine    │            │     TrapNet      │    │  Browser Shield  │
│  Orchestration   │    │ Antivirus & YARA │            │ Active Deception │    │  & Ad-Block Hub  │
├──────────────────┤    ├──────────────────┤            ├──────────────────┤    ├──────────────────┤
│• netsh Filtering │    │• 500k+ Hash DB   │            │• 9 Decoy Sockets │    │• Chrome/Edge/Crazy│
│• Panic Lockdown  │    │• Shannon Entropy │            │• Canary Baits    │    │• Firefox / Opera │
│• Socket Monitor  │    │• Encrypted Vault │            │• Auto-Banning    │    │• Abuse.ch Feeds  │
│• 5 Posture Profiles│  │• Offline Cleaner │            │• Payload Sniffer │    │• Crazy AdBlock   │
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
- **Panic Lockdown Protocol (`Alt + P`):** Immediate emergency circuit breaker. Instantly severs 100% of all inbound and outbound network communications across all physical, wireless, and virtual network adapters without crashing active network interfaces.
- **ICMP Stealth Masking:** One-click suppression of ICMPv4 and ICMPv6 echo requests, rendering your machine invisible to unauthorized reconnaissance scans on local area networks.
- **Live Socket & Bandwidth Forensics:** High-frequency socket watcher displaying remote IPs, destination ports, connection state (`ESTABLISHED`, `LISTENING`, `TIME_WAIT`), real-time transfer speeds, and executable paths mapped directly to PID.

### 2. Tri-Engine Antivirus & Threat Protection Subsystem
- **500,000+ Verified Signature SQLite Database:** Local, offline-capable database indexing verified malware hashes (SHA-256 and MD5) compiled from trusted intelligence feeds including Abuse.ch MalwareBazaar and ClamAV.
- **YARA Dynamic Heuristic Scanner:** Embedded YARA v4.3+ ruleset specifically tuned for detecting malicious payloads, process injection tools, ransomware ransom notes, infostealers, Discord token extractors, and cryptocurrency miners.
- **Shannon Entropy Analysis:** Deep Portable Executable (PE) inspection calculating file section entropy. Flags stealthy, packed, crypted, or obfuscated payloads (entropy score > 7.2) typically missed by standard signature scanning.
- **Encrypted Quarantine Vault:** Malicious binaries are instantly isolated, neutralized via XOR scrambling, and safely indexed in a secure vault under `.vitorius_quarantine` extensions. Supports deep forensic header viewing, permanent deletion, or verified false-positive restoration with automated whitelist integration.
- **Offline Boot Remediator (Defender-Style):** Schedules an isolated, zero-network sanitization routine executed at system reboot via Windows `RunOnce` and Task Scheduler. Force-terminates persistent rootkits, removes malicious autoruns, and executes low-level `MoveFileExW` boot-time purges.

### 3. TrapNet™ Active Deception & HoneyToken Defense
Instead of merely defending against attacks, Crazy Alchemy actively deceives and entraps internal and external network intruders:
- **Multi-Port Decoy Listeners:** Dynamically binds simulated deception honeypots across high-value attack surfaces:
  - **Port 21:** Decoy FTP service simulating anonymous logins and credential capture.
  - **Port 22 & 23:** Emulated SSH and Telnet login shells that log authentication attacks.
  - **Port 80:** Deceptive HTTP administrator portal and API reconnaissance trap.
  - **Port 445:** Decoy SMB file share detecting lateral movement and EternalBlue scans.
  - **Port 1433 & 3306:** Honeypot Microsoft SQL and MySQL database services.
  - **Port 3389 & 5900:** Emulated Remote Desktop (RDP) and VNC access points.
- **Autonomous Threat Neutralization:** Sockets utilize `SO_EXCLUSIVEADDRUSE` to prevent binding conflicts. Intruder packets are sniffed, logged in raw hex/ASCII, and the attacker's IP is automatically blacklisted with immediate Windows Firewall blocking rules.
- **HoneyToken Canary Baits:** Deploys simulated high-value target files (e.g., `passwords_production_backup.xlsx`, `aws_master_keys.json`, `corporate_vpn_credentials.env`, `executive_audit_q4.docx`) into sensitive user directories. Constantly monitored by low-level filesystem watchers; any modification, unauthorized read, or ransomware encryption attempt immediately raises a critical incident alarm and locks down the offending process.
- **Canary Tripwire Simulation & Removal:** Full GUI control allowing instant testing of deployed canaries with non-destructive tripwire simulation, as well as 1-click disarming and removal of deployed canary presets.

### 4. Cross-Browser Security Companion & Native Crazy AdBlock
A unified, private security bridge linking your desktop security engine directly with all major web browsers:
- **Broad Browser Ecosystem Support:** Ready-to-deploy, Manifest V3-compatible companions for **Crazy Browser**, **Google Chrome**, **Microsoft Edge**, **Opera / Opera GX**, and **Mozilla Firefox**.
- **Abuse.ch Live ThreatFox & URLhaus C2/Domain Interception:** Live synchronization of malicious command-and-control (C2), infostealer, and malware domains from Abuse.ch using your shared Auth-Key (or verified community threat feeds).
- **Crazy-Style Request-Level Ad & Tracker Blocking:** High-throughput declarative network request filtering stops intrusive video ads, display banners, tracking beacons, cross-site telemetry, and cryptojacking scripts directly inside the browser pipeline.
- **Cosmetic Element Hiding CSS:** Native cosmetic stylesheet injection eliminates sponsored banners, overlay popups, and ad wrapper containers.
- **One-Click Extension Management:** Built-in settings tool allowing instantaneous generation, inspection, clipboard path copying, and packaging of companion extensions directly from the GUI.

### 5. Windows Defender Dynamic Co-Existence & Parallel Antivirus Mode
Crazy Alchemy respects existing enterprise environments and user preferences:
- **Co-Active Parallel Antivirus Mode:** Runs smoothly alongside Microsoft Defender Antivirus without triggering mutual quarantine conflicts, CPU spikes, or false positive warnings.
- **Clean Configuration Management:** Utilizes safe WMI commands and native registry calls to configure security modes cleanly without leaving temporary PowerShell script artifacts that trip heuristic alerts.
- **Live Telemetry & Status Verification:** Constantly tracks real-time engine states, definition ages, tamper protection statuses, and active scan rings across both engines simultaneously.

### 6. Calibrated Security Profiles & Disaster Recovery
Rapidly switch the entire host security posture with a single click:
- **Home (Private):** Permits local network discovery, trusted file and printer sharing, and home media streaming while maintaining robust inbound protection.
- **Public (Untrusted Hotspot):** Aggressive drop-all inbound policy; closes NetBIOS, SMB, and discovery ports; enables ICMP ping suppression; arming TrapNet decoy listeners for untrusted environments.
- **Corporate (Strict Compliance):** Aligned with SOC 2, ISO 27001, and NIST guidelines. Restricts non-standard egress, enforces strict application allowlists, and logs all network socket transitions.
- **Gaming (Low-Latency Ultra):** Authorizes legitimate multiplayer gaming traffic, pauses background update tasks, suppresses desktop notification popups, and minimizes network jitter while keeping baseline firewall shields active.
- **Maximum Security (Paranoid / HIPAA):** Complete zero-trust drop-all posture. Locks down all ports, isolates the system, enforces strict YARA validation on all executed processes, and activates full canary baiting.
- **Automated Backup & Rollback (`WindowsProfileManager`):** Automatically snapshots the current Windows Firewall ruleset before any profile transition, enabling instant, lossless rollback in the event of configuration errors.

### 7. Process Forensics: ChainGuard™ & AppPrint™
- **ChainGuard Process Ancestry Validation:** Evaluates the complete parent-child-grandparent execution tree of every network-active process. Detects weaponized Office macros, unauthorized script interpreters (`powershell.exe`, `wscript.exe`, `cmd.exe`), and Living-off-the-Land Binaries (LOLBins) masquerading under legitimate Windows names.
- **AppPrint Network DNA Profiling:** Learns the baseline communications fingerprint of your installed applications (standard ports, subnet ranges, and connection frequencies). Flags zero-day anomalies, unexpected remote IP drift, and unauthorized command-and-control (C2) beaconing.

### 8. Clean Lifecycle Management & Complete Uninstaller
- **Zero-Residual Uninstallation (`uninstall.bat`):** Uninstallation completely removes application components, cleans local AppData/Temp caches, purges scheduled tasks and registry keys, and safely restores Windows Advanced Firewall back to factory default posture (`netsh advfirewall reset`).

---

## 💻 Technical Specifications

| Component | Technical Implementation |
| :--- | :--- |
| **Repository** | [https://github.com/Vitorius-Crazy-Alchemy/Crazy-Alchemy-AV](https://github.com/Vitorius-Crazy-Alchemy/Crazy-Alchemy-AV) |
| **GUI Framework** | PyQt6 with custom dynamic high-contrast QSS stylesheet engine |
| **Target OS** | Windows 11 (21H2, 22H2, 23H2, 24H2) / Windows 10 (64-bit) |
| **Signature Engine** | SQLite3 indexing 500,000+ SHA-256 & MD5 hashes |
| **Threat Intelligence** | Abuse.ch unified Auth-Key (MalwareBazaar, ThreatFox, URLhaus) |
| **Heuristics & Rules** | YARA v4.3+ engine with custom compiled ruleset |
| **Filesystem Watcher** | Multi-threaded Windows `ReadDirectoryChangesW` via `watchdog` |
| **Network Control** | Windows Filtering Platform (WFP) & `netsh advfirewall` CLI |
| **Deception Layer** | Multi-port decoy sockets with `SO_EXCLUSIVEADDRUSE` & WFP rule injector |
| **Browser Bridge** | Localhost HTTP companion daemon (127.0.0.1:49211) & Manifest V3 WebExtension |
| **Runtime Dependencies** | `PyQt6`, `psutil`, `watchdog`, `yara-python`, `pywin32` |
| **Build Dependency** | `pyinstaller>=6.0.0` (packaging only, separated from runtime) |

---

## 📥 Installation & Quick Start

### Quick 1-Click Launch (Recommended)
1. Clone the repository from GitHub:
   ```powershell
   git clone https://github.com/Vitorius-Crazy-Alchemy/Crazy-Alchemy-AV.git
   cd Crazy-Alchemy-AV
   ```
2. *(Optional - For Offline/Air-gapped Setups)* Run `download_prerequisites.bat` to automatically download the official Python installer and all binary wheels into a dedicated `prerequisites\` folder.
3. Double-click `CrazyAlchemy.bat` (or run `setup.bat`) to launch the application.

### Manual Setup via Python
```powershell
# 1. Clone repository
git clone https://github.com/Vitorius-Crazy-Alchemy/Crazy-Alchemy-AV.git
cd Crazy-Alchemy-AV

# 2. Install runtime dependencies
pip install -r requirements.txt

# 3. Seed baseline malware signatures (if not already initialized)
python data\signatures\seed_hashes.py

# 4. Launch Crazy Alchemy
python main_win.py
```

### Packaging as Standalone Windows Executable
To compile Crazy Alchemy into a self-contained `.exe` installer or portable executable:
```powershell
pip install -r requirements-build.txt
build_setup_exe.bat
```

---

## 🔒 Security & Privacy Guarantee

- **Zero Cloud Data Telemetry:** Crazy Alchemy collects zero personal files, browsing histories, or user identifiers. All hash lookups, entropy analyses, and firewall decisions execute 100% locally on your machine.
- **Open-Source Transparency:** Every component—from quarantine vault XOR routines to deception decoy listeners—is fully auditable in pure Python and Win32 APIs.

---

## 📄 License & Credits

- **Author & Architect:** [Vitorius](https://github.com/Vitorius-Crazy-Alchemy)
- **Project Repository:** [https://github.com/Vitorius-Crazy-Alchemy/Crazy-Alchemy-AV](https://github.com/Vitorius-Crazy-Alchemy/Crazy-Alchemy-AV)
- **Edition:** Crazy Alchemy v2.0 "LadyZi"
- **License:** Released under the [MIT License](https://github.com/Vitorius-Crazy-Alchemy/Crazy-Alchemy-AV/blob/main/LICENSE).
