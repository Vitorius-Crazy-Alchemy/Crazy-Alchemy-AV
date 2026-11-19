; Inno Setup 6 Script for Crazy Alchemy
; Enterprise-Grade Windows 11 Firewall & Antivirus Installer
; Generates standalone setup.exe with Desktop Icon and System Tray Startup

#define MyAppName "Crazy Alchemy"
#define MyAppVersion "2.0"
#define MyAppCodename "LudaCris"
#define MyAppPublisher "Crazy Alchemy"
#define MyAppExeName "CrazyAlchemy.exe"

[Setup]
AppId={{E72F9A3B-4D1C-4B33-90AE-8B7C2A1E5092}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=..\dist_installer
OutputBaseFilename=setup
SetupIconFile=..\data\icons\vitorius-firewall.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "Start Crazy Alchemy automatically on Windows startup (Silent Zero-UAC System Tray Mode)"; GroupDescription: "Startup Options"
Name: "installservice"; Description: "Register Crazy Alchemy Background Service (Enterprise Protection)"; GroupDescription: "Windows Service Configuration"; Flags: unchecked

[Files]
; Dist payload or source files
Source: "..\dist\CrazyAlchemy\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: DirExists(ExpandConstant('{src}\..\dist\CrazyAlchemy'))
Source: "..\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: ".git*,dist*,build\dist*,*.spec,*.pyc,__pycache__"

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\data\icons\vitorius-firewall.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; IconFilename: "{app}\data\icons\vitorius-firewall.ico"

[Registry]
; Windows Explorer Context Menu on Files: "Scan with Crazy Alchemy"
Root: HKCR; Subkey: "*\shell\CrazyAlchemyScan"; ValueType: string; ValueName: ""; ValueData: "Scan with Crazy Alchemy"; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\CrazyAlchemyScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\data\icons\vitorius-firewall.ico"""
Root: HKCR; Subkey: "*\shell\CrazyAlchemyScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan ""%1"""

; Windows Explorer Context Menu on Directories: "Scan with Crazy Alchemy"
Root: HKCR; Subkey: "Directory\shell\CrazyAlchemyScan"; ValueType: string; ValueName: ""; ValueData: "Scan with Crazy Alchemy"; Flags: uninsdeletekey
Root: HKCR; Subkey: "Directory\shell\CrazyAlchemyScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\data\icons\vitorius-firewall.ico"""
Root: HKCR; Subkey: "Directory\shell\CrazyAlchemyScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan ""%1"""

[Run]
; Seed signatures database
Filename: "{app}\{#MyAppExeName}"; Parameters: "--offline-scan --init-only"; Flags: runhidden

; Register elevated Task Scheduler entries with HighestAvailable privileges (Zero UAC Prompts)
Filename: "schtasks"; Parameters: "/create /tn ""CrazyAlchemy"" /tr """"{app}\{#MyAppExeName}"""" /sc ONCE /st 00:00 /it /rl HIGHEST /f"; Flags: runhidden
Filename: "schtasks"; Parameters: "/create /tn ""CrazyAlchemyAutostart"" /tr """"{app}\{#MyAppExeName}"""" --minimized /sc ONLOGON /delay 0000:03 /it /rl HIGHEST /f"; Tasks: autostart; Flags: runhidden

; Optional Background Service Installation
Filename: "{app}\{#MyAppExeName}"; Parameters: "--service install"; Tasks: installservice; Flags: runhidden
Filename: "net"; Parameters: "start CrazyAlchemyService"; Tasks: installservice; Flags: runhidden

; Launch Application post-install via silent elevated task
Filename: "schtasks"; Parameters: "/run /tn ""CrazyAlchemy"""; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Terminate running Crazy Alchemy application instances before uninstallation
Filename: "taskkill"; Parameters: "/F /IM {#MyAppExeName} /T"; Flags: runhidden
; Remove elevated Task Scheduler bypass entries
Filename: "schtasks"; Parameters: "/delete /tn ""CrazyAlchemy"" /f"; Flags: runhidden
Filename: "schtasks"; Parameters: "/delete /tn ""CrazyAlchemyAutostart"" /f"; Flags: runhidden
; Gracefully stop and unregister Windows Service if active
Filename: "net"; Parameters: "stop CrazyAlchemyService"; Flags: runhidden
Filename: "sc"; Parameters: "delete CrazyAlchemyService"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Parameters: "--service remove"; Flags: runhidden

; Remove residual Windows Firewall rules created during runtime
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=all profile=any program=""{app}\{#MyAppExeName}"""; Flags: runhidden
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=VitoriusFW_PANIC_IN"; Flags: runhidden
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=VitoriusFW_PANIC_OUT"; Flags: runhidden
Filename: "netsh"; Parameters: "advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"; Flags: runhidden
