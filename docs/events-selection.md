<!--
  Copyright (C) 2026 https://github.com/cw-l
  SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Event Selection

What the pipeline collects, and why. `config/inputs.yaml` is the source of truth for the event IDs. This document explains the choices.

- **Responders:** use it to know what evidence exists and what does not.
- **IT admin:** use it to understand why each event is collected before adding or removing any.
- How to enable the Security-channel events: [audit-policy.md](audit-policy.md), which has the subcategory-to-event table.

Events are grouped by what they help you detect. Each event appears once, under its main purpose. ATT&CK references (Enterprise ATT&CK v19, April 2026) name techniques an event can help evidence. They are pointers, not coverage claims, and a single event rarely proves a technique. Re-check the IDs after major ATT&CK releases: older mappings used IDs such as T1562.004 and T1070.001, now replaced by T1686.003 and T1685.005.

**Volume** is a rough expectation per active endpoint: Low (a few per day), Medium (dozens to hundreds), High (thousands). It is not measured. Validate it in your pilot (see the capacity notes in the README).

Where the Channel column identifies a provider, the query should filter on both channel and provider. The System and Application logs contain events from multiple providers, so event ID alone is not sufficient: an unrelated event with the same ID can be collected. The current queries filter on channel and event ID only; provider filters are planned.

---

## 1. Execution and scripting

Supports analysis of: T1059.001 (PowerShell) and other Execution techniques, when the process or script content shows them. Volume: Medium to High (4688, 4689 and 4104 dominate).

| Event | Channel | Records | Why |
|---|---|---|---|
| 4688 | Security | Process created (with command line if enabled) | Generic process-creation record and the backbone of any timeline: what ran, from which parent, with which arguments. Evidence for T1059.001 when the process or command line shows PowerShell |
| 4689 | Security | Process exited | Process lifetime, pairs with 4688 |
| 4104 | PowerShell/Operational | Script block content | Often includes de-obfuscated text. Captures script activity that 4688 may not show, such as interactive input |
| 8193, 8194, 8197 | PowerShell/Operational | Runspace created (8193), runspace pool created (8194), runspace state changed (8197) | Marks PowerShell sessions, including hosts other than `powershell.exe` |
| 24577 | PowerShell/Operational | PowerShell ISE ran a script file (script name and user) | Interactive script execution from the ISE |
| 400, 403 | Windows PowerShell | Engine started or stopped | Session boundaries and host version (spots a downgrade to PowerShell 2.0) |
| 8003, 8004 | AppLocker/EXE and DLL | Executable or DLL would be blocked (audit) or was blocked | Unapproved program execution. Needs an AppLocker policy |
| 8005, 8006, 8007 | AppLocker/MSI and Script | Script or installer allowed, would be blocked (audit), blocked | Unapproved scripts and installers. Needs an AppLocker policy |
| 865, 866, 867, 868, 882 | Application (Microsoft-Windows-SoftwareRestrictionPolicies) | Execution blocked by Software Restriction Policy: default security level (865), path rule (866), publisher rule (867), hash or Internet zone rule (868), other policy rule (882) | Blocked execution under SRP. SRP is deprecated since Windows 10 1803, and these events appear only if SRP is configured |

## 2. Logon, authentication and sessions

Supports analysis of: T1078 (Valid Accounts) and T1110 (Brute Force). A pattern of events, not one event, supports those conclusions. Volume: Medium to High (4624, 4634 and 4672 are frequent).

| Event | Channel | Records | Why |
|---|---|---|---|
| 4624 | Security | Logon succeeded | Who logged on, from where, and how (Logon Type: for example Interactive, Network, RemoteInteractive for RDP) |
| 4625 | Security | Logon failed | Failed logons. Repeated failures can support investigation of brute force and password spraying |
| 4634, 4647 | Security | Logoff, user-initiated logoff | Session end and dwell time |
| 4648 | Security | Logon with explicit credentials | Explicit credential use, including RunAs. Useful for investigating credential use and possible lateral movement |
| 4672 | Security | Special privileges assigned to a new logon | Logons receiving sensitive privileges (for example SeDebugPrivilege). Look for unexpected accounts. SYSTEM and service logons generate many of these |
| 4964 | Security | Special groups assigned to a new logon | Logon by a member of a monitored privileged group |
| 4627 | Security | Group membership of a logon | Which groups the session carried |
| 4776 | Security | NTLM credential validation | Traces NTLM credential validation. Repeated failures can support investigation of credential guessing |
| 4774 | Security | Account mapped for logon | Alternate account mapping (rare) |
| 4740, 4767 | Security | Account locked out (4740), unlocked (4767) | Lockout and unlock activity. A lockout can follow repeated failed logons: check the source computer in 4740 and the 4625 events before it |
| 4778, 4779 | Security | Session reconnected, disconnected | RDP and fast-user-switch session hopping |
| 4801, 4802, 4803 | Security | Workstation unlocked, screensaver invoked, dismissed | User presence: separates a person at the keyboard from activity while locked |

## 3. Account and group changes

Supports analysis of: T1136.001 (Create Account: Local Account) and T1098 (Account Manipulation). Volume: Low.

| Event | Channel | Records | Why |
|---|---|---|---|
| 4720 | Security | User account created | New account creation. Investigate unexpected accounts and account creation during an incident |
| 4722, 4725 | Security | Account enabled, disabled | Account state changes. Investigate unexpected enabling or disabling |
| 4723, 4724 | Security | Password change (4723) or reset (4724) attempted | Investigating credential changes and possible account compromise |
| 4726 | Security | Account deleted | Account deletion. Investigate unexpected deletion of accounts |
| 4738 | Security | Account changed | Attribute changes (for example password-never-expires) |
| 4732, 4733 | Security | Member added to, removed from a local group | Local-group membership changes. Especially important for local Administrators |

## 4. Persistence

Supports analysis of: T1053.005 (Scheduled Task), T1543.003 (Windows Service) and T1547 (Boot or Logon Autostart Execution). Volume: Low to Medium.

| Event | Channel | Records | Why |
|---|---|---|---|
| 4698, 4699 | Security | Scheduled task created, deleted | Task creation and removal. Needs "Other Object Access Events" |
| 4700, 4701, 4702 | Security | Scheduled task enabled, disabled, updated | Task changes |
| 106, 140, 141, 142 | TaskScheduler/Operational | Task registered, updated, deleted, disabled | Second source for the same changes, independent of the Security audit setting |
| 100, 102, 129, 200, 201 | TaskScheduler/Operational | Task started, completed, process launched, action started, completed | Proof that a task actually ran, and what it launched |
| 4697 | Security | Service installed | Service installation. Useful for investigating service-based persistence and possible remote execution |
| 7040 | System (Service Control Manager) | Service start type changed | Service start type changes. Investigate unexpected changes, especially to security services |
| 9707, 9708 | Shell-Core/Operational | Autostart command execution (for example Run and RunOnce entries) started (9707), finished (9708) | Autostart entries actually executing |
| 1033 | Application (MsiInstaller) | Windows Installer installed a product (includes its success or error status) | Software installed, including attacker tooling |
| 1034 | Application (MsiInstaller) | Windows Installer removed a product | Software removal |
| 1022 | Application (MsiInstaller) | An update (patch) was installed successfully for a product | Patching activity. Investigate unexpected updates |
| 1040, 1042 | Application (MsiInstaller) | Beginning (1040) and ending (1042) of a Windows Installer transaction | Brackets an install or removal and names the package and client process |
| 11707, 11724 | Application (MsiInstaller) | Installation operation completed successfully (11707), removal completed successfully (11724) | Success confirmation for an install or removal |
| 4610, 4611, 4614, 4622 | Security | LSA authentication package loaded (4610), logon process registered (4611), SAM notification package loaded (4614), LSA security package loaded (4622) | Changes or loading of LSA and SAM authentication components. Rare, and useful as supporting evidence when investigating authentication-component modification or credential-access activity. Check the package name: legitimate software also loads packages |

## 5. Defence evasion and tampering

Supports analysis of: T1685.005 (Clear Windows Event Logs), T1685.001 (Disable or Modify Windows Event Log), T1685 (Disable or Modify Tools) and T1686.003 (Windows Host Firewall), under the Defense Impairment tactic (TA0112). An invalid image hash (5038) can also have benign causes. Volume: Low.

| Event | Channel | Records | Why |
|---|---|---|---|
| 1102 | Security | Audit log cleared | Classic anti-forensics. Logged whenever the Security log is cleared, regardless of audit policy |
| 104 | System (Microsoft-Windows-Eventlog) | Event log cleared | Same, for non-Security logs |
| 4719 | Security | System audit policy changed | Logging switched off or reduced |
| 4715 | Security | Audit policy (SACL) on an object changed | Audit rules on an object added, changed or removed |
| 4817 | Security | Auditing settings on an object changed | Audit configuration change on an object. Read the object name and the account |
| 4902, 4912 | Security | Per-user audit policy created, changed | Selective blind spots |
| 4904, 4905 | Security | Security event source registration attempted (4904), unregistration attempted (4905) | Changes to which sources can write to the Security log |
| 4906, 4908 | Security | CrashOnAuditFail value changed, special groups table modified | Audit and privileged-group behaviour changes |
| 4612 | Security | Audit queue resources exhausted | Events were lost |
| 4615, 4618 | Security | Invalid use of an LPC port (4615), monitored security event pattern occurred (4618) | Security-subsystem events that are rarely seen. Supporting context only |
| 5038 | Security | Code integrity found an invalid image hash for a file | Possible tampering with a binary. Can also indicate a disk error |
| 1005 | Defender/Operational | Antimalware scan failed | A scan did not complete |
| 1006 | Defender/Operational | Malware or unwanted software found | Detection |
| 1008 | Defender/Operational | Action against malware failed | Detected but not remediated |
| 1010 | Defender/Operational | Failed to restore an item from quarantine | Quarantine handling. Investigate unexpected restore attempts |
| 2001, 2003 | Defender/Operational | Definition update failed (2001), engine update failed (2003) | Defender left out of date |
| 3002 | Defender/Operational | Real-time protection error | Protection failed |
| 5001 | Defender/Operational | Real-time protection scanning disabled | Defender switched off |
| 5010 | Defender/Operational | Scanning for spyware and other unwanted software disabled | Protection reduced |
| 5012 | Defender/Operational | Scanning for viruses disabled | Protection reduced |
| 5007 | Defender/Operational | Antimalware configuration changed | Includes exclusion changes |
| 4946, 4947, 4948, 4950, 4954, 4956 | Security | Firewall rule added (4946), modified (4947), deleted (4948); settings changed (4950); group policy settings changed (4954); active profile changed (4956) | Firewall configuration and rule changes. Investigate unexpected changes that could alter network filtering. Needs "MPSSVC Rule-Level Policy Change" |
| 2004, 2005, 2006, 2009 | Firewall | Rule added (2004), modified (2005), deleted (2006); firewall service failed to load Group Policy (2009) | Second source for rule changes (2005 also records the modifying user and application). 2009 means a firewall policy was not applied |

## 6. Privilege and permission changes

Supports analysis of: T1222.001 (File and Directory Permissions Modification) for 4670. 4673, 4674 and 4705 are context for privilege use and are not tied to one technique. Volume: Medium (4673 and 4674 can be noisy).

| Event | Channel | Records | Why |
|---|---|---|---|
| 4673 | Security | Privileged service called | Privileged service operations. Investigate unexpected use of sensitive privileges |
| 4674 | Security | Operation attempted on a privileged object | Same, at object level |
| 4705 | Security | User right removed | Rights tampering |
| 4670 | Security | Permissions on an object changed | ACL changes, including on files |

## 7. Remote access, lateral movement and network

Supports analysis of: T1021.001 (Remote Desktop Protocol) via 1149 and 22-25, 39, 40, and T1021.006 (Windows Remote Management) via 6, 81, 168, 169. 5712 and the WLAN events are context and map to no single technique. Volume: Low to Medium.

| Event | Channel | Records | Why |
|---|---|---|---|
| 1149 | TerminalServices-RemoteConnectionManager | RDP user authentication succeeded (before the session logon) | Source address of an RDP connection. Correlate with 4624 and the session events below: on its own it does not prove a session was created |
| 22, 23, 24, 25, 39, 40 | TerminalServices-LocalSessionManager | RDP shell start, logoff, disconnect, reconnect, disconnected by another session, reason code | RDP session lifecycle |
| 6, 81, 168, 169 | WinRM/Operational | WinRM session created, request processed, authentication started and succeeded | Remote PowerShell and WinRM access |
| 5712 | Security | RPC call attempted | Remote procedure call use (needs "RPC Events") |
| 8001, 8003 | WLAN-AutoConfig/Operational | Connected to, disconnected from a wireless network | Which networks a laptop joined, and when |

## 8. Files and devices

Supports analysis of: T1486 (Data Encrypted for Impact), T1485 (Data Destruction) and T1091 (Replication Through Removable Media). Volume: depends on scope.

| Event | Channel | Records | Why |
|---|---|---|---|
| 4663 | Security | Access attempt on an audited object | File access history, for reconstructing which audited files were accessed or modified. Read it with the file path, access mask, process and user. Fires only for folders with an audit rule (see audit-policy.md, Recommended A), plus removable storage |
| 6416 | Security | New external device recognized | New device connected. Useful for investigating removable-media and device activity. Needs "Plug and Play Events" |

## 9. System state and timeline anchors

Volume: Low, except 5056 and 5061 (varies: check in your pilot).

| Event | Channel | Records | Why |
|---|---|---|---|
| 4608, 4609 | Security | Windows starting up, shutting down | Boot and shutdown markers |
| 12, 13 | System (Microsoft-Windows-Kernel-General) | Operating system start (12), shutdown (13) | OS lifecycle events. Timeline anchors |
| 41, 107 | System (Microsoft-Windows-Kernel-Power) | Restart after an unclean shutdown (41), resume from sleep (107) | Unexpected reboot and resume events. Timeline anchors |
| 27 | System (Microsoft-Windows-Kernel-Boot) | Boot type: normal (0), fast startup (1) or hibernation resume (2) | Shows how the machine started, which changes how to read uptime and boot time |
| 4616 | Security | System time changed | Timestamp manipulation breaks timeline analysis |
| 4621 | Security | Administrator recovered the system from CrashOnAuditFail | Follows an audit failure |
| 5056, 5061 | Security | Cryptographic self-test (5056), cryptographic operation (5061) | Cryptographic subsystem activity, supporting timeline context. Not a primary signal |

---

## Domain-controller events in the query

These IDs fire on domain controllers, not on endpoints: 4728, 4729, 4756, 4757 (domain group membership), 4741, 4742, 4743 (computer accounts), 4777, 4780, 4706, 4713, 4716, 4864. They cost nothing on an endpoint and are kept from the baseline. Domain controllers are not a supported target for this pipeline.

## Not collected

- **Network connection events (5156, 5157, 5158):** too noisy for the value. See [audit-policy.md](audit-policy.md), Recommended C, for the reasoning and the alternative.
- **Security 4703 (token privileges adjusted):** removed. Microsoft rates its volume High, because applications and services adjust token privileges routinely, and it would share the `windows.*` throttle with 4688 and 4624.

## Changing the event set

1. Edit the `event_query` in `config/inputs.yaml`.
2. Check that the audit setting the event depends on is enabled in [audit-policy.md](audit-policy.md), and update the table there.
3. Add or remove the event in this document, under the group it belongs to.
4. Re-estimate volume in a pilot before rollout, because it changes the free-tier host count.
5. Bump `ir_metadata.pipeline_version` in `config/filters.yaml`, so responders can tell which event set produced a given log.