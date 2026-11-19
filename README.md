Crazy Alchemy v2.0 "LudaCris"
Complete Application Overview & Technical Capabilities

Crazy Alchemy v2.0 "LudaCris" (architected by Vitorius) is an enterprise-grade Windows 11 endpoint security, personal firewall, threat protection, and proactive cyber deception suite. Engineered in pure Python and Win32 APIs with a high-performance PyQt6 interface, Crazy Alchemy unifies low-level network packet filtering, multi-layered signature and heuristic malware detection, active honeypot deception, cross-browser security with request-level ad blocking, and process behavioral forensics into a single, cohesive desktop platform.

Unlike conventional consumer firewalls that only react to known outbound connections, Crazy Alchemy combines deep operating system telemetry with novel deception mechanisms that lure, detect, and neutralize adversaries both locally and across the network.

1. Dual-Engine Firewall & Network Orchestration

At its core, Crazy Alchemy orchestrates the Windows Filtering Platform (WFP) and the Windows Advanced Firewall (netsh advfirewall) through a dual-engine architecture:

Granular Traffic Control: Dynamically inspects, generates, and enforces bidirectional packet filtering rules. Users can whitelist or blacklist specific executables, port ranges, protocols (TCP, UDP, ICMP), and remote subnets.
Panic Lockdown Circuit Breaker (Alt + P): In the event of an active intrusion, zero-day compromise, or ransomware outbreak, Panic Lockdown instantly drops 100% of all inbound and outbound network traffic across all physical, wireless, and virtual network adapters without crashing active network interfaces.
ICMP Echo Suppression (Stealth Mode): Silently blocks incoming ICMPv4 and ICMPv6 ping requests with a single click, rendering the endpoint invisible to port scanners and reconnaissance probes across untrusted networks.
Real-Time Socket & Bandwidth Forensics: Live monitoring of all active TCP and UDP sockets with immediate PID-to-process attribution, remote IP geolocation identification, connection states (ESTABLISHED, LISTENING, TIME_WAIT), and per-adapter throughput diagnostics.
2. Tri-Engine Antivirus & Threat Protection Subsystem

Crazy Alchemy features an integrated, multi-layered threat scanner that operates completely offline without external cloud dependencies:

500,000+ Hash Signature SQLite Engine: Curated offline database compiling verified MD5 and SHA-256 hashes from Abuse.ch MalwareBazaar and ClamAV intelligence feeds. Supports instant hash lookup and incremental delta synchronization.
Dynamic YARA Heuristic Scanning: Built-in YARA v4.3+ rules detect complex malware families, infostealers, Discord webhook scrapers, cryptocurrency miners, and process hollowing shellcode patterns.
Shannon Entropy Analysis: Section-by-section entropy inspection calculates mathematical randomness across Portable Executable (PE) binaries. Any sample scoring an entropy level greater than 7.2 is flagged as packed, crypted, or obfuscated.
Encrypted Quarantine Vault: Quarantined files are immediately neutralized using XOR scrambling and given a .vitorius_quarantine extension. Threats can be safely inspected via raw hex views, permanently destroyed, or restored with automated whitelist integration.
Defender-Style Offline Boot Sanitizer: Schedules an isolated, zero-network pre-boot sweep via Windows RunOnce and Task Scheduler. This environment forcibly terminates stubborn rootkits, removes persistence registry keys, and invokes low-level MoveFileExW boot-time file purges.
3. TrapNet™ Active Cyber Deception & HoneyToken Baits

A major hallmark of Crazy Alchemy is its active deception technology, which shifts endpoint defense from passive monitoring to offensive counter-reconnaissance:

9 Decoy Service Listeners: Emulates real, vulnerable network services bound with SO_EXCLUSIVEADDRUSE across high-value ports:
Port 21: Decoy FTP service simulating authentication attempts and credential harvesting.
Ports 22 & 23: Emulated SSH and Telnet login shells logging remote brute-force activity.
Port 80: Deceptive HTTP administrative portal and API reconnaissance trap.
Port 445: Decoy SMB share detecting lateral movement and SMB exploits.
Ports 1433 & 3306: Emulated Microsoft SQL and MySQL database listeners.
Ports 3389 & 5900: Honeypot Remote Desktop (RDP) and VNC access ports.
Autonomous Attacker Banning: Decoy sockets sniff incoming payloads, log raw ASCII/hex communications, and immediately inject temporary or permanent blocking rules into the Windows Firewall.
HoneyToken Canary Baits: Deploys simulated sensitive files (passwords_backup.xlsx, aws_master_keys.json, corporate_vpn.env, executive_audit.docx) across user directories. Monitored in real time by file-system hooks; any unauthorized access, tampering, or ransomware encryption immediately raises an alarm and locks down the offending process.
4. Cross-Browser Security Companion & Built-in Ad Blocker

Crazy Alchemy bridges desktop endpoint protection directly into web browsers via a local, high-speed HTTP/WebSocket companion service:

Ecosystem Compatibility: Supports Google Chrome, Brave, Microsoft Edge, Opera, and Mozilla Firefox using Manifest V3 architectures.
Real-Time Malicious URL Filtering: Intercepts browser navigation requests and checks target domains against local threat intelligence before pages load, blocking phishing campaigns, drive-by exploit kits, and malicious redirects.
Request-Level Ad & Tracker Blocking: High-throughput declarative network request filtering blocks intrusive video ads, floating banners, tracking beacons, telemetry endpoints, and browser cryptominers directly inside the browser pipeline.
Instant Extension Packaging: A built-in management utility in the Settings window enables one-click deployment and inspection of browser extension packages.
5. Behavioral Forensics: ChainGuard™ & AppPrint™
ChainGuard Process Lineage Verification: Traverses the complete parent-child-grandparent process execution tree of all network-active applications. Accurately flags Living-off-the-Land Binaries (LOLBins) and suspicious execution chains (such as winword.exe spawning cmd.exe or powershell.exe).
AppPrint Network DNA Profiling: Automatically learns normal network communication baselines for every installed application (destination ports, standard subnets, connection frequency) and alerts administrators to zero-day deviations or C2 beaconing.
6. Calibrated Security Postures & Windows Defender Co-Existence
5 Security Profiles: Switch entire security configurations with a single click:
Home (Private): Permits local file sharing, network discovery, and media streaming.
Public (Hotspot): Enforces a drop-all inbound policy, enables ICMP stealth, and arms TrapNet deception listeners.
Corporate (SOC 2): Strict outbound filtering, audit logging, and approved application allowlists.
Gaming (Ultra Low-Latency): Unblocks multiplayer game ports, suppresses notifications, and minimizes CPU overhead.
Maximum Security (HIPAA / Zero-Trust): Total network isolation with full Canary and YARA enforcement.
Safe Windows Defender Coordination: Supports Co-Active Parallel execution and Passive Secondary Scanning. Adjusts configurations purely via native Windows Group Policy (winreg), eliminating noisy PowerShell command-line scripts and preventing AMSI false-positive alerts.
7. Modern Shell Integration & User Experience
High-Contrast Theme Engine: Seamlessly toggle between Dark Mode (deep obsidian slate #0f172a with vibrant emerald accents) and Light Mode (clean Nordic silver with crisp charcoal typography), guaranteeing readability on all monitors.
Persistent First-Run Settings: Automatically saves initial launch preferences, preventing repetitive modal dialogs across system reboots.
Windows 11 Native Integration: Dynamic taskbar scan progress bars via Windows COM ITaskbarList3, system tray status shield icons, Explorer right-click context menu integration, and an optional Windows Background Service (NT AUTHORITY\LocalSystem).
Summary Matrix

Crazy Alchemy v2.0 represents a modern defense model: zero telemetry, 100% local execution, multi-layered threat mitigation, and active cyber deception tailored for modern Windows environments.
