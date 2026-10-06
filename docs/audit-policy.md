<!--
  Copyright (C) 2026 https://github.com/cw-l
  SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Windows Audit Policy Setup - DFIR Baseline

Target: Windows 10/11 endpoints, workgroup or domain-joined (not domain controllers).
Reference: Malware Archaeology "Windows Logging Cheat Sheet" baseline. The "Advanced" tier is out of scope: higher DFIR value, much higher event volume.

Run every command from an **elevated** Command Prompt or PowerShell, unless a block says PowerShell.

Without this setup, most of the Security, PowerShell script-block and Task Scheduler events are never generated. The pipeline runs without errors and ships only what Windows logs by default.

- **Implemented**: required for the pipeline to collect what `config/inputs.yaml` asks for.
- **Recommended**: optional additions that add visibility. The pipeline works without them.

---

# Implemented (required)

## 1. Audit policy (auditpol)

Stops a legacy category policy from overriding the subcategory settings below:

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
```

Baseline subcategories:

```
auditpol /set /subcategory:"Group Membership" /success:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
```

Subcategory names are English. On a non-English Windows, `auditpol /set` needs the subcategory GUID instead: list them with `auditpol /list /subcategory:* /v`.

Notes on the less obvious ones:

- **Other Object Access Events**: required for scheduled task creation and modification (4698-4702). Without it only task *runs* are visible, via the TaskScheduler channel.
- **MPSSVC Rule-Level Policy Change**: required for firewall rule and profile changes (4946-4956). Catches an attacker opening an outbound hole for C2 or disabling a firewall profile.
- **Authorization Policy Change**: required for 4670 and 4705 (permission changes and user-right removal).
- **Plug and Play Events**: required for 6416 (new external device recognized).
- **File System**: on its own only permits file auditing. Events (4663) appear only for folders that carry an audit rule. See Recommended A.

## 2. Registry keys

**Command-line logging.** Adds the command line to every 4688 event. Without it, 4688 shows *that* a process ran, not *what it was told to do*:

```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

**PowerShell Script Block Logging.** Logs de-obfuscated script content (event 4104) for every account. Without it, anything typed inside an open PowerShell session or run via `-EncodedCommand` is invisible, because 4688 only captures the launch:

```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

## 3. Enable the Task Scheduler log

`Microsoft-Windows-TaskScheduler/Operational` is disabled by default. Without this, the Task Scheduler events collected (100, 102, 106, 129, 140-142, 200, 201) never appear:

```
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
```

## 4. Increase the Security log size

The default (20 MB) can wrap within hours on a busy host once command-line logging is on. Events overwritten before Fluent Bit reads them are lost. 256 MB is a reasonable SMB setting:

```
wevtutil sl Security /ms:268435456
```

## 5. Domain-joined machines (Group Policy)

Apply the same settings through a GPO instead of per-host commands, so a domain policy does not overwrite local settings:

- Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies: enable the subcategories in section 1.
- Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options: "Audit: Force audit policy subcategory settings ... to override audit policy category settings" = Enabled.
- Computer Configuration > Administrative Templates > System > Audit Process Creation: "Include command line in process creation events" = Enabled.
- Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell: "Turn on PowerShell Script Block Logging" = Enabled.
- Task Scheduler log (section 3) and Security log size (section 4): run the `wevtutil` commands through a startup script, or use the Event Log Service GPO for log size.

## 6. Verify everything applied

```
auditpol /get /category:*
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging
wevtutil gl Microsoft-Windows-TaskScheduler/Operational
wevtutil gl Security
```

In the `wevtutil gl` output, confirm `enabled: true` for the Task Scheduler log and the new `maxSize` for Security.

## 7. Test that it works

**Process creation and command line (4688):**

```
whoami
```

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 1 | Format-List Message
```

Confirm the newest entry has a populated command line.

**Script Block Logging (4104):**

```
powershell -Command "Write-Host 'test script block logging'"
```

Event Viewer > Applications and Services Logs > Microsoft > Windows > PowerShell > Operational > Event ID 4104.

**Scheduled task (4698/4699 and the Task Scheduler log):**

```
schtasks /create /tn "audit-test" /tr "cmd.exe" /sc once /st 23:59
schtasks /delete /tn "audit-test" /f
```

Expect 4698 and 4699 in Security, and task events in the Task Scheduler Operational log.

**Removable storage:** plug in a USB device and check for Event ID 6416 (Device Plug and Play) in the Security log. File activity could be correlated with process execution if a payload runs.

---

# Recommended (optional)

## A. Scoped file auditing (ransomware visibility)

Full-drive file auditing is far too noisy. Auditing a few high-value folders stays low-volume and gives IR a timestamped record of what an encryptor touched. Nothing else in this baseline provides that.

**How it works:** the `File System` subcategory (section 1) only permits file auditing. Event 4663 fires only for folders that carry an audit rule (SACL). No rule on a folder means no events from it.

**What you lose without it:** no record of which files a ransomware run touched. The pipeline runs fine either way.

Run in an elevated PowerShell. It audits **success** only, on write, delete and permission-change rights, never reads (reads would flood the log with antivirus and indexer activity). It covers Documents and Desktop of every local profile under `C:\Users`, including OneDrive-redirected copies:

```powershell
$Rights = [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions'
$Everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$Rule = New-Object System.Security.AccessControl.FileSystemAuditRule($Everyone, $Rights, 'ContainerInherit, ObjectInherit', 'None', 'Success')
$Skip = 'Public', 'Default', 'Default User', 'All Users'

Get-ChildItem "$env:SystemDrive\Users" -Directory -Force |
    Where-Object { $Skip -notcontains $_.Name } |
    ForEach-Object {
        $Roots = @($_.FullName) + @(Get-ChildItem $_.FullName -Directory -Filter 'OneDrive*' -ErrorAction SilentlyContinue | ForEach-Object FullName)
        foreach ($Root in $Roots) {
            foreach ($Sub in 'Documents', 'Desktop') {
                $Path = Join-Path $Root $Sub
                if (Test-Path -LiteralPath $Path -PathType Container) {
                    $Acl = Get-Acl -LiteralPath $Path -Audit
                    $Acl.AddAuditRule($Rule)
                    Set-Acl -LiteralPath $Path -AclObject $Acl
                    "Audited: $Path"
                }
            }
        }
    }
```

**Test:** create and delete a file in your Documents folder, then check for 4663:

```powershell
New-Item "$env:USERPROFILE\Documents\sacl-test.txt" -Force | Out-Null
Remove-Item "$env:USERPROFILE\Documents\sacl-test.txt"
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663} -MaxEvents 5 | Format-List Message
```

**Undo:** in the same script, replace `$Acl.AddAuditRule($Rule)` with `$Acl.RemoveAuditRuleAll($Rule)`.

**Limits:**
- Profiles created later are not covered: re-run the script.
- A ransomware burst hits the pipeline throttle (`config/filters.yaml`), so you will see when it started, not the complete list of files.
- Domain-joined machines can use GPO instead: Security Settings > File System.
- Network and shared drives are not covered. The path varies per customer.

## B. AppLocker (audit mode)

The AppLocker events collected (8003-8007) appear only if an AppLocker policy exists. Without one those channels stay empty.

AppLocker policy enforcement is an Enterprise/Education feature: not verified on Windows Pro. On supported editions:

1. Open Local Security Policy (`secpol.msc`) > Application Control Policies > AppLocker.
2. For each rule collection (Executable, Windows Installer, Script, Packaged app): right-click > Create Default Rules, then in AppLocker properties set enforcement to **Audit only**.
3. Start the Application Identity service:

```
sc.exe config appidsvc start= auto
sc.exe start appidsvc
```

Audit-only mode logs what would be blocked and blocks nothing.

## C. Network connections (5156, 5157, 5158)

Not collected, deliberately.

**Why:** these events need the `Filtering Platform Connection` subcategory, which logs every allowed (5156) and blocked (5157) connection and local port bind (5158) on the host. That is one of the four noisiest event types in the cheat sheet, often thousands of events per hour. Collecting them would:

- inflate R2 storage and the write-operation estimate for the free tier
- share one throttle budget with `windows.*` records, so a flood can starve high-value events such as 4688 and 4624
- bury the useful records in routine traffic, since the pipeline stores raw logs and does not parse or alert

5156 and 5157 do carry the process path and the remote address, which is real IR value. 5158 has no remote address. The cost is volume, not lack of value.

**Alternative:** if you want network visibility, do it on the network side (router or firewall logs). To collect from endpoints, enable the subcategory, collect 5156 through its own input with its own throttle (a tag not starting with `windows.`, or it shares the existing throttle), and re-run the capacity numbers first:

```
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

Sysmon Event ID 3 is the closest equivalent and is deliberately not used (see "Explicitly not configured").

---

# What each setting feeds

Security channel events in `config/inputs.yaml`. Update this table when event IDs change.

| Subcategory | Events |
|---|---|
| Credential Validation | 4774, 4776, 4777 |
| User Account Management | 4720, 4722-4726, 4738, 4767, 4780 |
| Security Group Management | 4728, 4729, 4732, 4733, 4756, 4757 |
| Computer Account Management | 4741-4743 |
| Process Creation | 4688 |
| Process Termination | 4689 |
| RPC Events | 5712 |
| Logon | 4624, 4625, 4648 |
| Logoff | 4634, 4647 |
| Account Lockout | 4740 |
| Special Logon | 4672, 4964 |
| Other Logon/Logoff Events | 4778, 4779, 4801-4803 |
| Group Membership | 4627 |
| Audit Policy Change | 4715, 4719, 4817, 4902, 4904, 4905, 4906, 4908, 4912 |
| Authentication Policy Change | 4706, 4713, 4716, 4864 |
| Authorization Policy Change | 4670, 4705 |
| Sensitive Privilege Use | 4673, 4674 |
| Security State Change | 4608, 4609, 4616, 4621 |
| Security System Extension | 4610, 4611, 4614, 4622, 4697 |
| System Integrity | 4612, 4615, 4618, 5038, 5056, 5061 |
| Plug and Play Events | 6416 |
| Other Object Access Events | 4698-4702 |
| MPSSVC Rule-Level Policy Change | 4946-4948, 4950, 4954, 4956 |
| File System / Removable Storage | 4663 (File System also needs an audit rule) |
| Application Group Management | none yet (baseline) |
| Always logged | 1102 (audit log cleared) |

---

# Explicitly not configured

- **Unscoped File System / Registry auditing:** enabling the subcategory globally does nothing on its own, and setting audit rules on every folder or key is the noise problem the baseline avoids. Scoped file auditing is in Recommended A. Registry auditing has no scoped use case identified yet.
- **Sysmon:** deliberately dropped (too many moving parts, not guaranteed present on SMB endpoints). Native Windows auditing is the primary layer regardless: Malware Archaeology states Sysmon should supplement built-in auditing, never replace it.