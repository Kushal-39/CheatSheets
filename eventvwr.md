# Windows Event Viewer and Sysmon Event ID Reference

## Table of Contents
- [Account Logon Events](#account-logon-events)
- [Logon Types Reference](#logon-types-reference)
- [Account Management](#account-management)
- [Logon/Logoff](#logonlogoff)
- [Object Access](#object-access)
- [Policy Change](#policy-change)
- [Privilege Use](#privilege-use)
- [Process Tracking](#process-tracking)
- [System Events](#system-events)
- [Detailed Tracking](#detailed-tracking)
- [Sysmon Event IDs](#sysmon-event-ids)

---

## Account Logon Events
| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon with explicit credentials |
| 4672 | Special privileges assigned to new logon |
| 4634 | Logoff |
| 4647 | User-initiated logoff |
| 4776 | NTLM authentication |
| 4771 | Kerberos pre-auth failed |
| 4770 | Kerberos ticket renewal |
| 4768 | Kerberos TGT requested |
| 4769 | Kerberos service ticket requested |
| 4800 | Workstation locked |
| 4801 | Workstation unlocked |

## Logon Types Reference

| Type               | Value | Description                                         |
|--------------------|-------|-----------------------------------------------------|
| Interactive        | 2     | Local logon at keyboard/console                     |
| Network            | 3     | Logon over network (e.g., SMB, RDP without /admin)  |
| Batch              | 4     | Scheduled task                                      |
| Service            | 5     | Service logon                                       |
| Unlock             | 7     | Unlock workstation                                  |
| NetworkCleartext   | 8     | Network logon with cleartext credentials            |
| NewCredentials     | 9     | RunAs with /netonly                                 |
| RemoteInteractive  | 10    | RDP/Terminal Services (remote interactive)           |
| CachedInteractive  | 11    | Cached credentials (disconnected domain)            |
## Account Management
| Event ID | Description |
|----------|-------------|
| 4720 | User account created |
| 4722 | User account enabled |
| 4723 | User changed own password |
| 4724 | User changed another's password |
| 4725 | User account disabled |
| 4726 | User account deleted |
| 4738 | User account changed |
| 4740 | Account locked out |
| 4767 | Account unlocked |
| 4781 | Name of an account changed |

## Logon/Logoff
| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4647 | User-initiated logoff |
| 4649 | Logon attempt using explicit credentials |
| 4675 | SIDs were filtered |
| 4778 | Session reconnected |
| 4779 | Session disconnected |
| 4800 | Workstation locked |
| 4801 | Workstation unlocked |
| 4802 | Screen saver invoked |
| 4803 | Screen saver dismissed |

## Object Access
| Event ID | Description |
|----------|-------------|
| 4656 | Handle to object requested |
| 4663 | Object accessed |
| 4670 | Permissions on object changed |
| 4660 | Object deleted |
| 4661 | Handle to object requested (directory service) |
| 4662 | Operation performed on object (directory service) |
| 4690 | Backup of data protection master key attempted |

## Policy Change
| Event ID | Description |
|----------|-------------|
| 4719 | System audit policy changed |
| 4739 | Domain policy changed |
| 4902 | Audit policy changed |
| 4906 | Trust policy changed |
| 4907 | Auditing settings on object changed |
| 4715 | Audit policy on object changed |

## Privilege Use
| Event ID | Description |
|----------|-------------|
| 4672 | Special privileges assigned to new logon |
| 4673 | Privileged service called |
| 4674 | Privileged object operation attempted |

## Process Tracking
| Event ID | Description |
|----------|-------------|
| 4688 | New process created |
| 4689 | Process ended |
| 4696 | Token assigned to process |
| 4697 | Service installed |
| 4698 | Scheduled task created |
| 4699 | Scheduled task deleted |
| 4700 | Scheduled task enabled |
| 4701 | Scheduled task disabled |
| 4702 | Scheduled task updated |

## System Events
| Event ID | Description |
|----------|-------------|
| 4608 | Windows started |
| 4609 | Windows shutdown |
| 6005 | Event log service started |
| 6006 | Event log service stopped |
| 6008 | Unexpected shutdown |
| 6013 | System uptime |

## Detailed Tracking
| Event ID | Description |
|----------|-------------|
| 5140 | Network share object accessed |
| 5142 | Network share created |
| 5143 | Network share deleted |
| 5144 | Network share modified |
| 5145 | Network share checked for access |

---

## Sysmon Event IDs
| Sysmon ID | Description |
|-----------|-------------|
| 1 | Process creation |
| 2 | File creation time changed |
| 3 | Network connection detected |
| 4 | Sysmon service state changed |
| 5 | Process terminated |
| 6 | Driver loaded |
| 7 | Image loaded |
| 8 | CreateRemoteThread detected |
| 9 | Raw disk access detected |
| 10 | Process accessed another process |
| 11 | File created |
| 12 | Registry object created or deleted |
| 13 | Registry value set |
| 14 | Registry key/values renamed |
| 15 | File stream created |
| 16 | Sysmon configuration change |
| 17 | Pipe created |
| 18 | Pipe connected |
| 19 | WMI event filter activity |
| 20 | WMI event consumer activity |
| 21 | WMI event consumer to filter |
| 22 | DNS query |
| 23 | File delete archived |
| 24 | Clipboard changed |
| 25 | Process tampering |
| 26 | File delete detected |

---
