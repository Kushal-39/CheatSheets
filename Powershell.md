# PowerShell Blue Team Cybersecurity Cheat Sheet

## Table of Contents
- [PowerShell Basics](#powershell-basics)
- [Security & Execution Policy](#security--execution-policy)
- [System Information Gathering](#system-information-gathering)
- [Process & Service Analysis](#process--service-analysis)
- [Network Analysis](#network-analysis)
- [File System & Registry Analysis](#file-system--registry-analysis)
- [Event Log Analysis](#event-log-analysis)
- [User & Account Analysis](#user--account-analysis)
- [Threat Hunting](#threat-hunting)
- [Incident Response](#incident-response)
- [Forensics & Evidence Collection](#forensics--evidence-collection)
- [Security Monitoring](#security-monitoring)
- [Malware Analysis](#malware-analysis)
- [Active Directory Security](#active-directory-security)
- [PowerShell Security Features](#powershell-security-features)

---

## PowerShell Basics

### Core Commands
```powershell
# Get help for any command
Get-Help <CommandName>
Get-Help <CommandName> -Examples
Get-Help <CommandName> -Full

# List all available commands
Get-Command
Get-Command *network*

# Get object properties and methods
Get-Member
<object> | Get-Member

# Format output
Format-Table, Format-List, Format-Wide
Out-GridView
```

### Pipeline & Objects
```powershell
# Pipeline basics
Get-Process | Where-Object {$_.CPU -gt 100}
Get-Service | Select-Object Name, Status, StartType

# Filtering and sorting
Where-Object {condition}
Sort-Object Property
Select-Object Property1, Property2
```

### Variables & Data Types
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

---

## Security & Execution Policy

### Execution Policy Management
```powershell
# Check current execution policy
Get-ExecutionPolicy
Get-ExecutionPolicy -List

# Set execution policy
Set-ExecutionPolicy RemoteSigned
Set-ExecutionPolicy Bypass -Scope Process

# Run script bypassing execution policy
powershell -ExecutionPolicy Bypass -File script.ps1
```

### PowerShell Security Features
```powershell
# Check PowerShell version (v5+ has better security)
$PSVersionTable.PSVersion

# Enable script block logging (Windows Event Log)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Enable module logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
```

---

## System Information Gathering

### Basic System Information
```powershell
# Computer information
Get-ComputerInfo
Get-WmiObject -Class Win32_ComputerSystem
systeminfo

# Operating system details
Get-WmiObject -Class Win32_OperatingSystem
Get-CimInstance -ClassName Win32_OperatingSystem

# Hardware information
Get-WmiObject -Class Win32_Processor
Get-WmiObject -Class Win32_PhysicalMemory
Get-WmiObject -Class Win32_LogicalDisk

# Installed software
Get-WmiObject -Class Win32_Product
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
```

### Environment & Configuration
```powershell
# Environment variables
Get-ChildItem Env:
$env:PATH
$env:COMPUTERNAME

# System configuration
Get-HotFix # Installed updates
Get-WindowsFeature # Windows features
Get-WindowsOptionalFeature -Online
```

---

## Process & Service Analysis

### Process Analysis
```powershell
# List all processes
Get-Process
Get-WmiObject -Class Win32_Process

# Detailed process information
Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet, StartTime
Get-WmiObject -Class Win32_Process | Select-Object Name, ProcessId, CommandLine, CreationDate

# Process with network connections
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}

# Suspicious process indicators
Get-Process | Where-Object {$_.ProcessName -notmatch "^[a-zA-Z0-9\-_\.]+$"}
Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -like "*powershell*" -and $_.CommandLine -like "*-encoded*"}
```

### Service Analysis
```powershell
# List all services
Get-Service
Get-WmiObject -Class Win32_Service

# Service details
Get-Service | Select-Object Name, Status, StartType, ServiceType
Get-WmiObject -Class Win32_Service | Select-Object Name, State, StartMode, PathName, StartName

# Suspicious services
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "C:\Windows\*" -and $_.State -eq "Running"}
```

### Startup Programs
```powershell
# Startup programs
Get-WmiObject Win32_StartupCommand
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

---

## Network Analysis

### Network Configuration
```powershell
# Network adapters
Get-NetAdapter
Get-WmiObject -Class Win32_NetworkAdapterConfiguration

# IP configuration
Get-NetIPAddress
Get-NetIPConfiguration
ipconfig /all
```

### Network Connections
```powershell
# Active connections
Get-NetTCPConnection
Get-NetUDPEndpoint
netstat -an

# Connections with process information
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}

# Listening ports
Get-NetTCPConnection -State Listen
Get-NetUDPEndpoint | Where-Object {$_.LocalAddress -eq "0.0.0.0"}
```

### DNS & Network Security
```powershell
# DNS cache
Get-DnsClientCache
ipconfig /displaydns

# ARP table
Get-NetNeighbor
arp -a

# Routing table
Get-NetRoute
route print

# Firewall rules
Get-NetFirewallRule
Get-NetFirewallRule -Enabled True
```

---

## File System & Registry Analysis

### File System Analysis
```powershell
# File searches
Get-ChildItem -Path C:\ -Recurse -Include *.exe
Get-ChildItem -Path C:\ -Recurse | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}

# File hashes
Get-FileHash -Path "C:\file.exe" -Algorithm SHA256
Get-ChildItem *.exe | Get-FileHash

# Hidden files and alternate data streams
Get-ChildItem -Force -Hidden
Get-Item -Path "file.txt" -Stream *
```

### Registry Analysis
```powershell
# Registry key enumeration
Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Registry monitoring locations
Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\exefile\shell\open\command"
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services"

# Registry searches
Get-ChildItem -Path HKLM:\ -Recurse | Where-Object {$_.Name -like "*malware*"}
```

### File Integrity
```powershell
# System file checker
sfc /scannow

# Windows file integrity
Get-WmiObject -Class Win32_SystemDriver | Where-Object {$_.State -eq "Running"}
```

---

## Event Log Analysis

### Event Log Basics
```powershell
# List available logs
Get-EventLog -List
Get-WinEvent -ListLog *

# Read event logs
Get-EventLog -LogName System -Newest 100
Get-EventLog -LogName Security -Newest 50
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational"
```

### Security Event Analysis
```powershell
# Logon events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Select-Object TimeCreated, Id, LevelDisplayName, Message

# Failed logons
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}

# Account lockouts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740}

# Process creation events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688}

# PowerShell execution events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104}
```

### Event Log Filtering
```powershell
# Time-based filtering
$StartTime = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$StartTime}

# Multiple event IDs
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4634}

# Keyword filtering
Get-WinEvent -FilterHashtable @{LogName='System'} | Where-Object {$_.Message -like "*error*"}
```

---

## User & Account Analysis

### User Account Information
```powershell
# Local users
Get-LocalUser
Get-WmiObject -Class Win32_UserAccount

# Current user context
whoami
[System.Security.Principal.WindowsIdentity]::GetCurrent()

# User sessions
Get-WmiObject -Class Win32_LogonSession
query user
```

### Group Membership
```powershell
# Local groups
Get-LocalGroup
Get-LocalGroupMember -Group "Administrators"

# User group membership
Get-LocalUser | ForEach-Object {Get-LocalGroupMember -Member $_.Name -ErrorAction SilentlyContinue}
```

### Account Security
```powershell
# Password policy
Get-LocalUser | Select-Object Name, PasswordRequired, PasswordExpires
net accounts

# Last logon times
Get-WmiObject -Class Win32_NetworkLoginProfile
```

---

## Threat Hunting

### Suspicious Process Hunting
```powershell
# Processes with suspicious names
Get-Process | Where-Object {$_.ProcessName -match "(mimikatz|psexec|meterpreter|cobalt)"}

# Processes running from temp directories
Get-WmiObject Win32_Process | Where-Object {$_.ExecutablePath -like "*\temp\*" -or $_.ExecutablePath -like "*\tmp\*"}

# Unsigned processes
Get-Process | Where-Object {$_.Path} | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.Path
    if ($sig.Status -ne "Valid") { $_ }
}

# PowerShell with encoded commands
Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -like "*powershell*" -and $_.CommandLine -like "*-enc*"}
```

### Network Threat Hunting
```powershell
# Unusual network connections
Get-NetTCPConnection | Where-Object {$_.RemotePort -in @(1337, 4444, 5555, 8080, 8888)}

# Connections to suspicious IPs
$SuspiciousIPs = @("192.168.1.100", "10.0.0.50")
Get-NetTCPConnection | Where-Object {$_.RemoteAddress -in $SuspiciousIPs}

# High number of connections from single process
Get-NetTCPConnection | Group-Object OwningProcess | Where-Object {$_.Count -gt 10}
```

### File System Threat Hunting
```powershell
# Recently modified executables
Get-ChildItem -Path C:\ -Include *.exe -Recurse | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}

# Files in suspicious locations
Get-ChildItem -Path @("C:\Windows\Temp", "C:\Temp", "$env:APPDATA") -Include *.exe,*.bat,*.ps1 -Recurse

# Large files in temp directories
Get-ChildItem -Path "$env:TEMP" -Recurse | Where-Object {$_.Length -gt 10MB}
```

---

## Incident Response

### Immediate Response
```powershell
# System isolation (disable network adapters)
Get-NetAdapter | Disable-NetAdapter -Confirm:$false

# Kill suspicious processes
Stop-Process -Name "malicious_process" -Force
Get-Process "suspicious*" | Stop-Process -Force

# Disable services
Stop-Service -Name "SuspiciousService" -Force
Set-Service -Name "SuspiciousService" -StartupType Disabled
```

### Data Collection
```powershell
# Create incident response directory
$IRDir = "C:\IR_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $IRDir

# Collect system information
Get-ComputerInfo | Out-File "$IRDir\system_info.txt"
Get-Process | Export-Csv "$IRDir\processes.csv" -NoTypeInformation
Get-Service | Export-Csv "$IRDir\services.csv" -NoTypeInformation
Get-NetTCPConnection | Export-Csv "$IRDir\network_connections.csv" -NoTypeInformation
```

### Timeline Creation
```powershell
# File system timeline
Get-ChildItem -Path C:\ -Recurse | Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime | Export-Csv "$IRDir\file_timeline.csv"

# Event log timeline
Get-WinEvent -LogName Security | Select-Object TimeCreated, Id, LevelDisplayName, Message | Export-Csv "$IRDir\security_events.csv"
```

---

## Forensics & Evidence Collection

### Memory Analysis
```powershell
# Running processes with memory usage
Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet, PagedMemorySize | Sort-Object WorkingSet -Descending

# Process modules and DLLs
Get-Process -Name "notepad" | Select-Object -ExpandProperty Modules
```

### Registry Forensics
```powershell
# USB device history
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" | Select-Object PSChildName, FriendlyName

# Recently accessed files
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

# Run key persistence
$RunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($Key in $RunKeys) {
    Get-ItemProperty -Path $Key
}
```

### File Analysis
```powershell
# File metadata
Get-ItemProperty -Path "C:\file.exe" | Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime, Length

# File signatures
Get-Content -Path "C:\file.exe" -Encoding Byte -ReadCount 16 -TotalCount 16

# Alternate data streams
Get-Item -Path "C:\file.txt" -Stream *
Get-Content -Path "C:\file.txt:stream_name"
```

---

## Security Monitoring

### Continuous Monitoring Scripts
```powershell
# Monitor new processes
Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
    $Event = $Event.SourceEventArgs.NewEvent
    Write-Host "New Process: $($Event.ProcessName) PID: $($Event.ProcessID)"
}

# Monitor file system changes
$Watcher = New-Object System.IO.FileSystemWatcher
$Watcher.Path = "C:\Windows\System32"
$Watcher.Filter = "*.exe"
$Watcher.EnableRaisingEvents = $true
```

### Log Monitoring
```powershell
# Real-time event log monitoring
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 1 | ForEach-Object {
    Write-Host "Failed logon attempt detected: $($_.Message)"
}
```

---

## Malware Analysis

### Static Analysis
```powershell
# File information
Get-ItemProperty -Path "C:\malware.exe" | Format-List
Get-FileHash -Path "C:\malware.exe" -Algorithm MD5,SHA1,SHA256

# PE header analysis (requires additional modules)
# Import-Module PETools
# Get-PEHeader -Path "C:\malware.exe"

# Strings extraction (basic)
Get-Content -Path "C:\malware.exe" -Encoding Byte | ForEach-Object {[char]$_} | Out-String
```

### Dynamic Analysis Setup
```powershell
# Create isolated environment
# Disable Windows Defender (for analysis only)
Set-MpPreference -DisableRealtimeMonitoring $true

# Enable process monitoring
$ProcessWatch = Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
    $Event = $Event.SourceEventArgs.NewEvent
    Add-Content -Path "C:\analysis\process_log.txt" -Value "$(Get-Date): $($Event.ProcessName) started"
}
```

---

## Active Directory Security

### AD Enumeration
```powershell
# Domain information
Get-ADDomain
Get-ADForest

# Domain controllers
Get-ADDomainController -Filter *

# Users and groups
Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet
Get-ADGroup -Filter * | Select-Object Name, GroupScope, GroupCategory

# Computer accounts
Get-ADComputer -Filter * -Properties LastLogonDate, OperatingSystem
```

### AD Security Analysis
```powershell
# Privileged accounts
Get-ADGroupMember -Identity "Domain Admins"
Get-ADGroupMember -Identity "Enterprise Admins"

# Service accounts
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName

# Stale accounts
Get-ADUser -Filter * -Properties LastLogonDate | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)}
Get-ADComputer -Filter * -Properties LastLogonDate | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)}
```

---

## PowerShell Security Features

### Constrained Language Mode
```powershell
# Check language mode
$ExecutionContext.SessionState.LanguageMode

# Set constrained language mode
$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
```

### Script Block Logging
```powershell
# Enable script block logging via registry
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# View PowerShell logs
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4104}
```

### PowerShell Remoting Security
```powershell
# Enable PowerShell remoting
Enable-PSRemoting -Force

# Configure trusted hosts
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "server1,server2"

# Use SSL for remoting
New-PSSession -ComputerName "server" -UseSSL
```

---

## Advanced Techniques

### WMI Queries for Security
```powershell
# Detect lateral movement
Get-WmiObject -Class Win32_LogonSession | Where-Object {$_.LogonType -eq 3}

# Network shares
Get-WmiObject -Class Win32_Share

# Scheduled tasks
Get-WmiObject -Class Win32_ScheduledJob
Get-ScheduledTask | Where-Object {$_.State -eq "Running"}
```

### PowerShell Empire Detection
```powershell
# Detect Empire agents
Get-Process | Where-Object {$_.ProcessName -eq "powershell"} | ForEach-Object {
    $proc = Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)"
    if ($proc.CommandLine -match "empire|invoke-|downloadstring") {
        Write-Host "Suspicious PowerShell process detected: $($proc.CommandLine)"
    }
}
```

### Memory Forensics with PowerShell
```powershell
# Process memory dump (requires additional tools)
# Get-Process -Name "suspicious_process" | Out-Minidump -DumpFilePath "C:\memory_dump.dmp"

# Analyze loaded modules
Get-Process -Name "notepad" | Select-Object -ExpandProperty Modules | Select-Object ModuleName, FileName
```

---

## Quick Reference Commands

### Essential One-Liners
```powershell
# Quick system triage
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
Get-NetTCPConnection -State Established | Select-Object LocalPort, RemoteAddress, RemotePort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
Get-EventLog -LogName Security -InstanceId 4625 -Newest 10

# Suspicious activity detection
Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -like "*invoke-expression*" -or $_.CommandLine -like "*iex*"}
Get-ChildItem -Path C:\Users\*\AppData\Roaming -Include *.exe -Recurse | Where-Object {$_.CreationTime -gt (Get-Date).AddHours(-1)}

# Network analysis
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Group-Object RemoteAddress | Sort-Object Count -Descending
```

### PowerShell for Blue Team Automation
```powershell
# Automated threat hunting script template
function Hunt-Threats {
    $Results = @()
    
    # Check for suspicious processes
    $SuspiciousProcs = Get-Process | Where-Object {$_.ProcessName -match "(mimikatz|psexec|procdump)"}
    if ($SuspiciousProcs) {
        $Results += "Suspicious processes detected: $($SuspiciousProcs.ProcessName -join ', ')"
    }
    
    # Check for unusual network connections
    $UnusualConns = Get-NetTCPConnection | Where-Object {$_.RemotePort -in @(4444, 5555, 1337)}
    if ($UnusualConns) {
        $Results += "Unusual network connections detected on ports: $($UnusualConns.RemotePort -join ', ')"
    }
    
    return $Results
}

# Run threat hunt
Hunt-Threats
```

---

## Best Practices for Blue Team

1. **Always run PowerShell as Administrator** for full system access
2. **Use -WhatIf parameter** when testing potentially destructive commands
3. **Log all activities** during incident response
4. **Create snapshots** before making system changes
5. **Use transcript logging** to record PowerShell sessions:
   ```powershell
   Start-Transcript -Path "C:\IR\powershell_session.txt"
   # Your commands here
   Stop-Transcript
   ```
6. **Validate findings** with multiple data sources
7. **Document everything** during investigations
8. **Use signed scripts** in production environments
9. **Implement least privilege** for PowerShell execution
10. **Monitor PowerShell usage** with appropriate logging

---

*This cheat sheet provides a comprehensive reference for PowerShell commands useful in blue team cybersecurity operations. Always ensure you have proper authorization before running these commands in any environment.*