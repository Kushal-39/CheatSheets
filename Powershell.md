# PowerShell Blue Team Cybersecurity Cheat Sheet

**Author:** Kushal Arora  
**Last-updated:** 2025-08-19

## TLDR - Run these first on a suspected host

| Command | Description |
|---------|-------------|
| `Get-Process \| Sort-Object CPU -Descending \| Select-Object -First 10` | Top CPU consuming processes |
| `Get-CimInstance Win32_Process \| Where-Object {$_.CommandLine -like "*powershell*" -and $_.CommandLine -like "*-enc*"}` | Encoded PowerShell commands |
| `Get-NetTCPConnection -State Established \| Select-Object LocalPort, RemoteAddress, RemotePort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}` | Active network connections |
| `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -MaxEvents 50` | Recent PowerShell script blocks |
| `Get-ChildItem -Path C:\Users\*\AppData\Roaming -Include *.exe -Recurse -ErrorAction SilentlyContinue \| Where-Object {$_.CreationTime -gt (Get-Date).AddHours(-24)}` | New executables in user profiles |
| `Get-CimInstance Win32_Process \| Where-Object {$_.ExecutablePath -like "*\temp\*" -or $_.ExecutablePath -like "*\tmp\*"}` | Processes from temp directories |
| `Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 20` | Recent failed logins |
| `Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue` | Local administrators |
| `Get-ScheduledTask \| Where-Object {$_.State -eq "Running" -and $_.TaskPath -notlike "\Microsoft\*"}` | Non-Microsoft running tasks |
| `Get-CimInstance Win32_StartupCommand` | Startup programs |

## Table of Contents
- [PowerShell Basics](#powershell-basics)
- [System Information Gathering](#system-information-gathering)
- [Process and Service Analysis](#process-and-service-analysis)
- [Network Analysis](#network-analysis)
- [File System and Registry Analysis](#file-system-and-registry-analysis)
- [Event Log Analysis](#event-log-analysis)
- [User and Account Analysis](#user-and-account-analysis)
- [Threat Hunting](#threat-hunting)
- [Detection Recipes](#detection-recipes)
- [Incident Response Checklist](#incident-response-checklist)
- [Forensics and Evidence Collection](#forensics-and-evidence-collection)
- [ANALYSIS ONLY Commands](#analysis-only-commands)
- [Sysmon and EDR Primer](#sysmon-and-edr-primer)
- [PowerShell Security Features](#powershell-security-features)

## PowerShell Basics

### Core Commands
```powershell
# Get help for any command
Get-Help Get-Process
Get-Help Get-Process -Examples
Get-Help Get-Process -Full

# List available commands
Get-Command
Get-Command *network*

# Get object properties and methods
Get-Process | Get-Member
Get-Service | Get-Member

# Format output
Get-Process | Format-Table
Get-Process | Format-List
Get-Process | Out-GridView

# Session transcripts for logging
Start-Transcript -Path "C:\IR\powershell-session_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
# Your analysis commands here
Stop-Transcript

# Central transcript logging
Start-Transcript -Path "\\server\logs\powershell-$env:COMPUTERNAME_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
```

### Pipeline and Objects
```powershell
# Pipeline basics
Get-Process | Where-Object {$_.CPU -gt 100}
Get-Service | Select-Object Name, Status, StartType

# Filtering and sorting
Where-Object {$_.Property -eq "value"}
Sort-Object Property
Select-Object Property1, Property2

# Convert to JSON for API ingestion
Get-Process | Select-Object ProcessName, Id, CPU | ConvertTo-Json
```

### Variables and Special Objects
```powershell
# Variables
$variable = "value"
$array = @("item1", "item2", "item3")
$hashtable = @{key1="value1"; key2="value2"}

# Special variables
$_ # Current object in pipeline
$args # Function arguments
$error # Last error
$PSVersionTable # PowerShell version info
```

## System Information Gathering

```powershell
# Computer information (modern approach)
Get-ComputerInfo
Get-CimInstance -ClassName Win32_ComputerSystem
Get-CimInstance -ClassName Win32_OperatingSystem

# Hardware information
Get-CimInstance -ClassName Win32_Processor
Get-CimInstance -ClassName Win32_PhysicalMemory
Get-CimInstance -ClassName Win32_LogicalDisk

# Installed software (safer approach)
Get-CimInstance -ClassName Win32_Product -ErrorAction SilentlyContinue
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue

# Environment variables
Get-ChildItem Env:
$env:PATH
$env:COMPUTERNAME

# System configuration
Get-HotFix | Sort-Object InstalledOn -Descending
Get-WindowsFeature -ErrorAction SilentlyContinue
Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue
```

## Process and Service Analysis

```powershell
# List all processes with safe error handling
Get-Process -ErrorAction SilentlyContinue
Get-CimInstance -ClassName Win32_Process

# Detailed process information
Get-Process | Where-Object {$_.Path} | Select-Object ProcessName, Id, CPU, WorkingSet, StartTime, Path
Get-CimInstance -ClassName Win32_Process | Select-Object Name, ProcessId, CommandLine, CreationDate, ExecutablePath

# Process with network connections
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}

# Suspicious process indicators
Get-Process | Where-Object {$_.ProcessName -notmatch "^[a-zA-Z0-9._-]+$"}
Get-CimInstance Win32_Process | Where-Object {$_.CommandLine -like "*powershell*" -and $_.CommandLine -like "*-encoded*"}

# Service analysis
Get-Service
Get-CimInstance -ClassName Win32_Service

# Service details with safe error handling
Get-Service | Select-Object Name, Status, StartType, ServiceType
Get-CimInstance -ClassName Win32_Service | Select-Object Name, State, StartMode, PathName, StartName

# Suspicious services
Get-CimInstance Win32_Service | Where-Object {$_.PathName -notlike "C:\Windows\*" -and $_.State -eq "Running"}

# Startup programs
Get-CimInstance Win32_StartupCommand
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
```

## Network Analysis

```powershell
# Network adapters
Get-NetAdapter
Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration

# IP configuration
Get-NetIPAddress
Get-NetIPConfiguration
Get-NetRoute

# Active connections
Get-NetTCPConnection
Get-NetUDPEndpoint

# Connections with process information
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}

# Listening ports
Get-NetTCPConnection -State Listen
Get-NetUDPEndpoint | Where-Object {$_.LocalAddress -eq "0.0.0.0"}

# DNS and network security
Get-DnsClientCache
Get-NetNeighbor
Get-NetFirewallRule -Enabled True

# Export network data
Get-NetTCPConnection | Export-Csv "network-connections_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
```

## File System and Registry Analysis

```powershell
# File searches with error handling
Get-ChildItem -Path C:\ -Recurse -Include *.exe -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}

# File hashes
Get-FileHash -Path "C:\file.exe" -Algorithm SHA256
Get-ChildItem *.exe -ErrorAction SilentlyContinue | Get-FileHash

# Hidden files and alternate data streams
Get-ChildItem -Force -Hidden -ErrorAction SilentlyContinue
Get-Item -Path "file.txt" -Stream * -ErrorAction SilentlyContinue

# Registry analysis
Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue

# Registry monitoring locations
Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\exefile\shell\open\command" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue

# File integrity
Get-CimInstance -ClassName Win32_SystemDriver | Where-Object {$_.State -eq "Running"}
```

## Event Log Analysis

```powershell
# List available logs
Get-WinEvent -ListLog * -ErrorAction SilentlyContinue

# Modern event log reading with time filtering
$StartTime = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$StartTime} -MaxEvents 100 -ErrorAction SilentlyContinue

# Security event analysis
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 50 | Select-Object TimeCreated, Id, LevelDisplayName, Message

# Failed logons
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50

# Account lockouts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740} -MaxEvents 50

# Process creation events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 100

# PowerShell execution events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -MaxEvents 100

# Multiple event IDs
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4634} -MaxEvents 100

# Export event logs
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 1000 | Export-Csv "failed-logins_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
```

## User and Account Analysis

```powershell
# Local users
Get-LocalUser -ErrorAction SilentlyContinue
Get-CimInstance -ClassName Win32_UserAccount

# Current user context
whoami
[System.Security.Principal.WindowsIdentity]::GetCurrent()

# User sessions
Get-CimInstance -ClassName Win32_LogonSession
query user

# Group membership
Get-LocalGroup -ErrorAction SilentlyContinue
Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

# User group membership
Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {Get-LocalGroupMember -Member $_.Name -ErrorAction SilentlyContinue}

# Password policy
Get-LocalUser | Select-Object Name, PasswordRequired, PasswordExpires
net accounts

# Last logon times
Get-CimInstance -ClassName Win32_NetworkLoginProfile -ErrorAction SilentlyContinue
```

## Threat Hunting

```powershell
# Processes with suspicious names
Get-Process | Where-Object {$_.ProcessName -match "(mimikatz|psexec|meterpreter|cobalt)"}

# Processes running from temp directories
Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -like "*\temp\*" -or $_.ExecutablePath -like "*\tmp\*"}

# Unsigned processes
Get-Process | Where-Object {$_.Path} | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue
    if ($sig.Status -ne "Valid") { $_ }
}

# PowerShell with encoded commands
Get-CimInstance Win32_Process | Where-Object {$_.CommandLine -like "*powershell*" -and $_.CommandLine -like "*-enc*"}

# Unusual network connections
Get-NetTCPConnection | Where-Object {$_.RemotePort -in @(1337, 4444, 5555, 8080, 8888)}

# High number of connections from single process
Get-NetTCPConnection | Group-Object OwningProcess | Where-Object {$_.Count -gt 10}

# Recently modified executables
Get-ChildItem -Path C:\ -Include *.exe -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}

# Files in suspicious locations
Get-ChildItem -Path @("C:\Windows\Temp", "C:\Temp", "$env:APPDATA") -Include *.exe,*.bat,*.ps1 -Recurse -ErrorAction SilentlyContinue

# Large files in temp directories
Get-ChildItem -Path "$env:TEMP" -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Length -gt 10MB}
```

## Detection Recipes

### 1. Encoded PowerShell Commands
**PowerShell Detection:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | 
Where-Object {$_.Message -like "*-EncodedCommand*" -or $_.Message -like "*-enc*"}
```
**Splunk Query:**
```
index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 (Message="*-EncodedCommand*" OR Message="*-enc*")
```

### 2. Invoke-Expression and IEX Usage
**PowerShell Detection:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | 
Where-Object {$_.Message -like "*Invoke-Expression*" -or $_.Message -like "*IEX*"}
```
**Elastic Query:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"winlog.channel": "Microsoft-Windows-PowerShell/Operational"}},
        {"term": {"winlog.event_id": 4104}},
        {"bool": {"should": [
          {"wildcard": {"message": "*Invoke-Expression*"}},
          {"wildcard": {"message": "*IEX*"}}
        ]}}
      ]
    }
  }
}
```

### 3. PowerShell from User Temp Folders
**PowerShell Detection:**
```powershell
Get-CimInstance Win32_Process | Where-Object {
    $_.Name -eq "powershell.exe" -and 
    ($_.ExecutablePath -like "*\Users\*\AppData\Local\Temp\*" -or $_.ExecutablePath -like "*\Users\*\Temp\*")
}
```
**Splunk Query:**
```
index=windows source="WinEventLog:Security" EventCode=4688 Process_Name=powershell.exe (Process_Command_Line="*\\Users\\*\\AppData\\Local\\Temp\\*" OR Process_Command_Line="*\\Users\\*\\Temp\\*")
```

### 4. Certutil Download Usage
**PowerShell Detection:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | 
Where-Object {$_.Message -like "*certutil*" -and ($_.Message -like "*-urlcache*" -or $_.Message -like "*-split*")}
```
**Elastic Query:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"winlog.event_id": 4688}},
        {"wildcard": {"winlog.event_data.NewProcessName": "*certutil*"}},
        {"bool": {"should": [
          {"wildcard": {"winlog.event_data.CommandLine": "*-urlcache*"}},
          {"wildcard": {"winlog.event_data.CommandLine": "*-split*"}}
        ]}}
      ]
    }
  }
}
```

### 5. Unusual Parent-Child Relationships
**PowerShell Detection:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | 
Where-Object {
    ($_.Message -like "*winword.exe*" -or $_.Message -like "*excel.exe*" -or $_.Message -like "*outlook.exe*") -and
    ($_.Message -like "*powershell.exe*" -or $_.Message -like "*cmd.exe*" -or $_.Message -like "*wscript.exe*")
}
```
**Splunk Query:**
```
index=windows source="WinEventLog:Security" EventCode=4688 (Creator_Process_Name="*winword.exe" OR Creator_Process_Name="*excel.exe" OR Creator_Process_Name="*outlook.exe") (Process_Name="*powershell.exe" OR Process_Name="*cmd.exe" OR Process_Name="*wscript.exe")
```

### 6. Suspicious Rundll32 Usage
**PowerShell Detection:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | 
Where-Object {$_.Message -like "*rundll32.exe*" -and $_.Message -notlike "*shell32.dll*" -and $_.Message -notlike "*user32.dll*"}
```
**Elastic Query:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"winlog.event_id": 4688}},
        {"wildcard": {"winlog.event_data.NewProcessName": "*rundll32.exe*"}}
      ],
      "must_not": [
        {"wildcard": {"winlog.event_data.CommandLine": "*shell32.dll*"}},
        {"wildcard": {"winlog.event_data.CommandLine": "*user32.dll*"}}
      ]
    }
  }
}
```

### 7. Regsvr32 Scriptlet Execution
**PowerShell Detection:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | 
Where-Object {$_.Message -like "*regsvr32*" -and ($_.Message -like "*scrobj.dll*" -or $_.Message -like "*/u*" -or $_.Message -like "*/s*")}
```
**Splunk Query:**
```
index=windows source="WinEventLog:Security" EventCode=4688 Process_Name="*regsvr32*" (Process_Command_Line="*scrobj.dll*" OR Process_Command_Line="*/u*" OR Process_Command_Line="*/s*")
```

### 8. Living Off The Land Binaries (LOLBins)
**PowerShell Detection:**
```powershell
$LOLBins = @("bitsadmin.exe", "regasm.exe", "regsvcs.exe", "installutil.exe", "msbuild.exe")
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | 
Where-Object {
    $Message = $_.Message
    $LOLBins | ForEach-Object { if ($Message -like "*$_*") { return $true } }
}
```
**Elastic Query:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"winlog.event_id": 4688}},
        {"bool": {"should": [
          {"wildcard": {"winlog.event_data.NewProcessName": "*bitsadmin.exe*"}},
          {"wildcard": {"winlog.event_data.NewProcessName": "*regasm.exe*"}},
          {"wildcard": {"winlog.event_data.NewProcessName": "*regsvcs.exe*"}},
          {"wildcard": {"winlog.event_data.NewProcessName": "*installutil.exe*"}},
          {"wildcard": {"winlog.event_data.NewProcessName": "*msbuild.exe*"}}
        ]}}
      ]
    }
  }
}
```

## Incident Response Checklist

### First Response Commands (Run in Order)
```powershell
# 1. Create IR directory with timestamp
$IRDir = "C:\IR_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $IRDir

# 2. Start transcript logging
Start-Transcript -Path "$IRDir\powershell-session_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# 3. Collect volatile data immediately
Get-Process | Export-Csv "$IRDir\processes_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
Get-NetTCPConnection | Export-Csv "$IRDir\network-connections_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
Get-Service | Export-Csv "$IRDir\services_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation

# 4. Collect recent PowerShell activity
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -MaxEvents 500 | 
Export-Csv "$IRDir\powershell-scriptblocks_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation

# 5. Collect system information
Get-ComputerInfo | Out-File "$IRDir\system-info_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Get-LocalUser | Export-Csv "$IRDir\local-users_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
Get-LocalGroupMember -Group "Administrators" | Export-Csv "$IRDir\local-admins_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation

# 6. Collect security events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4648,4720,4726} -MaxEvents 1000 | 
Export-Csv "$IRDir\security-events_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation

# 7. Stop transcript
Stop-Transcript
```

### IR Sequence (Recommended Order)
1. **Isolate** - Document but do not disconnect network yet
2. **Collect Volatile** - Run the commands above immediately
3. **Capture Memory** - If authorized, use tools like DumpIt or WinPmem
4. **Image Disk** - Create forensic image if authorized
5. **Preserve Logs** - Export all relevant event logs
6. **Contain** - Isolate system after data collection

### Memory Capture (If Authorized)
```powershell
# Using DumpIt (download first)
.\DumpIt.exe /OUTPUT C:\IR\memory-dump_$(Get-Date -Format 'yyyyMMdd_HHmmss').dmp /QUIET

# Using WinPmem (download first)
.\winpmem.exe C:\IR\memory-dump_$(Get-Date -Format 'yyyyMMdd_HHmmss').aff4
```

## Forensics and Evidence Collection

```powershell
# File system timeline
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue | 
Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime, Length | 
Export-Csv "$IRDir\file-timeline_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation

# Registry forensics
# USB device history
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue | 
Export-Csv "$IRDir\usb-history_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation

# Recently accessed files
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -ErrorAction SilentlyContinue | 
Out-File "$IRDir\recent-docs_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Run key persistence
$RunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($Key in $RunKeys) {
    Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue | 
    Out-File "$IRDir\run-keys_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Append
}

# File metadata analysis
Get-ItemProperty -Path "C:\suspicious_file.exe" -ErrorAction SilentlyContinue | 
Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime, Length

# File hashes for known files
$SuspiciousFiles = @("C:\Windows\Temp\*.exe", "C:\Users\*\AppData\*.exe")
foreach ($Pattern in $SuspiciousFiles) {
    Get-ChildItem -Path $Pattern -Recurse -ErrorAction SilentlyContinue | 
    Get-FileHash | Export-Csv "$IRDir\file-hashes_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation -Append
}

# Alternate data streams
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | 
ForEach-Object { Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue } | 
Where-Object { $_.Stream -ne ":$DATA" } | 
Export-Csv "$IRDir\alternate-data-streams_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
```

## ANALYSIS ONLY Commands

**⚠️ WARNING: Do not run these commands on production systems without proper approval. These commands can change system state, disable protections, or modify persistence mechanisms.**

### System Isolation Commands
```powershell
# Disable network adapters (RISK: System isolation, loss of remote access)
Get-NetAdapter | Disable-NetAdapter -Confirm:$false
# MITIGATION: Use only when authorized. Consider selective interface disabling.

# Kill processes (RISK: System instability, data loss)
Stop-Process -Name "suspicious_process" -Force
Get-Process "malware*" | Stop-Process -Force
# MITIGATION: Verify process before killing. Use Get-Process first to confirm target.

# Disable services (RISK: System functionality loss)
Stop-Service -Name "SuspiciousService" -Force
Set-Service -Name "SuspiciousService" -StartupType Disabled
# MITIGATION: Document original service state. Use Get-Service first to verify.
```

### Security Control Modifications
```powershell
# Disable Windows Defender (RISK: Removes malware protection)
Set-MpPreference -DisableRealtimeMonitoring $true
# MITIGATION: Only for isolated analysis systems. Re-enable immediately after analysis.

# Execution policy bypass (RISK: Allows unsigned script execution)
Set-ExecutionPolicy Bypass -Scope Process
powershell -ExecutionPolicy Bypass -File script.ps1
# MITIGATION: Use minimal scope. Prefer -Scope Process over system-wide changes.

# Registry modifications (RISK: System instability, security bypass)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
# MITIGATION: Document original values. Test in isolated environment first.
```

### PowerShell Remoting (Network Exposure Risk)
```powershell
# Enable PowerShell remoting (RISK: Network attack surface increase)
Enable-PSRemoting -Force
# MITIGATION: Use only when necessary. Configure firewall rules appropriately.

# Configure trusted hosts (RISK: Authentication bypass)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*"
# MITIGATION: Use specific hostnames instead of wildcards.
```

## Sysmon and EDR Primer

For comprehensive blue team operations, deploy Sysmon with these critical event types:
- **Process Create (ID 1)** - Track all process executions with command lines
- **Network Connect (ID 3)** - Monitor outbound network connections
- **Image Load (ID 7)** - Detect DLL injection and suspicious library loads
- **Driver Load (ID 6)** - Identify malicious driver installations
- **File Create (ID 11)** - Monitor file system changes in critical directories
- **Registry Events (ID 12-14)** - Track registry modifications for persistence

**Recommended Sysmon Config:** Use SwiftOnSecurity's sysmon-config or Olaf Hartong's sysmon-modular configurations available on GitHub for enterprise-ready detection rules.

## PowerShell Security Features

### Execution Policy
```powershell
# Check current execution policy
Get-ExecutionPolicy
Get-ExecutionPolicy -List

# View PowerShell version (v5+ recommended for security features)
$PSVersionTable.PSVersion
```

### Script Block Logging
```powershell
# View PowerShell script block logs
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4104}

# Check if script block logging is enabled
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
```

### Constrained Language Mode
```powershell
# Check current language mode
$ExecutionContext.SessionState.LanguageMode

# Verify if constrained language mode is active (should show "ConstrainedLanguage" in secure environments)
if ($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage") {
    Write-Host "Constrained Language Mode is active"
} else {
    Write-Host "Full Language Mode is active - review security configuration"
}
```

### PowerShell Transcript Logging
```powershell
# Check if transcript logging is configured
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue

# Manual session transcript (always use during IR)
Start-Transcript -Path "C:\IR\powershell-transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
# Analysis commands here
Stop-Transcript
```

### Module Logging
```powershell
# View module loading events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103}

# Check module logging configuration
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
```

## Quick Reference

### Essential Exports for Documentation
```powershell
# Complete system snapshot
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$IRDir = "C:\IR_$Timestamp"
New-Item -ItemType Directory -Path $IRDir

# Core system data
Get-Process | Export-Csv "$IRDir\processes_$Timestamp.csv" -NoTypeInformation
Get-Service | Export-Csv "$IRDir\services_$Timestamp.csv" -NoTypeInformation
Get-NetTCPConnection | Export-Csv "$IRDir\connections_$Timestamp.csv" -NoTypeInformation
Get-CimInstance Win32_StartupCommand | Export-Csv "$IRDir\startup_$Timestamp.csv" -NoTypeInformation
Get-ScheduledTask | Export-Csv "$IRDir\scheduled-tasks_$Timestamp.csv" -NoTypeInformation

# Security events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4648} -MaxEvents 1000 | 
Export-Csv "$IRDir\security-events_$Timestamp.csv" -NoTypeInformation

# PowerShell activity
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -MaxEvents 500 | 
Export-Csv "$IRDir\powershell-activity_$Timestamp.csv" -NoTypeInformation
```

### One-Liner Threat Hunting
```powershell
# Quick suspicious process check
Get-CimInstance Win32_Process | Where-Object {$_.CommandLine -like "*powershell*" -and ($_.CommandLine -like "*-enc*" -or $_.CommandLine -like "*invoke-expression*" -or $_.CommandLine -like "*downloadstring*")} | Select-Object Name, ProcessId, CommandLine

# Quick network anomaly check
Get-NetTCPConnection | Where-Object {$_.State -eq "Established" -and $_.RemotePort -in @(4444,5555,1337,8080,8888)} | Select-Object LocalPort, RemoteAddress, RemotePort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}

# Quick file system check
Get-ChildItem -Path @("C:\Windows\Temp", "C:\Users\*\AppData\Local\Temp") -Include *.exe,*.ps1,*.bat -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.CreationTime -gt (Get-Date).AddHours(-24)} | Select-Object FullName, CreationTime, Length
```

---

*This cheat sheet provides practical PowerShell commands for blue team operations. Always verify you have proper authorization before running any commands, especially those in the ANALYSIS ONLY section. Document all actions during incident response.*