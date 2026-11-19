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
### 4. Cross-Browser Security Companion & Native Ad Blocker
A unified, private security bridge linking your desktop security engine directly with all major web browsers:
- **Broad Browser Ecosystem Support:** Ready-to-deploy, Manifest V3-compatible companions for **Google Chrome**, **Brave**, **Microsoft Edge**, **Opera**, and **Mozilla Firefox**.
- **Real-Time Malicious URL Filtering:** Browser navigation requests are audited locally against local threat feeds to stop phishing campaigns, drive-by downloads, zero-day exploit kits, and malicious redirectors before page rendering begins.
- **Brave-Style Request-Level Ad & Tracker Blocking:** High-throughput declarative network request filtering stops intrusive video ads, display banners, tracking beacons, cross-site telemetry, and cryptojacking scripts directly inside the browser pipeline.
- **One-Click Extension Management:** Built-in settings tool allowing instantaneous generation, inspection, and packaging of companion extensions directly from the GUI.
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
### 8. Modern UI, Dual Theme Engine & Shell Integration
- **High-Contrast Theme System:** Seamlessly toggle between **Dark Mode** (deep obsidian `#0f172a` slate with emerald and cyan status indicators) and **Light Mode** (clean Nordic silver with crisp charcoal typography). Meticulously styled to guarantee maximum legibility and zero washed-out labels across all resolutions.
- **Persistent First-Run Workflow:** Remembers your launch configuration and window preferences permanently after the initial startup—no repetitive modal dialogs or setup prompts on reboot.
- **Windows 11 Native Integration:** Native Windows Taskbar progress integration via `ITaskbarList3` (showing active scan progress directly on the taskbar icon), animated system tray shield indicator, and Explorer right-click context menu integration ("*Scan with Vitorius Antivirus*").
- **Windows System Service (`NT AUTHORITY\LocalSystem`):** Can be installed as a background service (`VitoriusFirewallService`) to safeguard the endpoint even before user login.
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
| **Test Verification** | 170 comprehensive unit tests with 100% pass rate |
---
## 📥 Installation & Quick Start
### Quick 1-Click Setup (Recommended)
1. Clone or download the repository to your local drive (e.g., `D:\Crazy_Alchemy`).
2. Double-click `install_prerequisites.bat` to automatically install all required packages (`PyQt6`, `psutil`, `watchdog`, `yara-python`, `pywin32`).
3. Double-click `setup.bat` (or execute `CrazyAlchemy.bat`) to launch the application.
### Manual Setup via Command Prompt
```powershell
# 1. Clone repository
git clone https://github.com/YourUsername/Crazy_Alchemy.git
cd Crazy_Alchemy
# 2. Install runtime dependencies
pip install -r requirements.txt
# 3. Seed baseline malware signatures (if not pre-populated)
python data\signatures\seed_hashes.py
# 4. Launch Crazy Alchemy
python main_win.py
