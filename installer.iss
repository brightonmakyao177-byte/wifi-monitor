; Builds WiFiMonitor-Setup.exe. Installs for the current user, so no admin rights are needed.
[Setup]
AppId={{7E1C5B52-3F0A-4C57-9D7E-5C1B6A2F4E10}
AppName=Wi-Fi Monitor
AppVersion=1.0
AppPublisher=Wi-Fi Monitor
DefaultDirName={localappdata}\Programs\WiFiMonitor
DefaultGroupName=Wi-Fi Monitor
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=lowest
OutputDir=dist
OutputBaseFilename=WiFiMonitor-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\WiFiMonitor.exe
CloseApplications=force

[Tasks]
Name: "autostart"; Description: "Start monitoring automatically when I log in"

[Files]
Source: "dist\WiFiMonitor\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\Wi-Fi Monitor"; Filename: "{app}\WiFiMonitor.exe"
Name: "{group}\Stop Wi-Fi Monitor"; Filename: "{app}\WiFiMonitor.exe"; Parameters: "--stop"
Name: "{userstartup}\Wi-Fi Monitor"; Filename: "{app}\WiFiMonitor.exe"; Parameters: "--background"; Tasks: autostart

[Run]
Filename: "{app}\WiFiMonitor.exe"; Description: "Open Wi-Fi Monitor now"; Flags: nowait postinstall

[UninstallRun]
Filename: "{app}\WiFiMonitor.exe"; Parameters: "--stop"; Flags: runhidden; RunOnceId: "StopMonitor"
