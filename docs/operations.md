<!--
  Copyright (C) 2026 https://github.com/cw-l
  SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Operations

For the IT admin. Five short items.

## 1. Is a host working?

Check both. A running service alone proves nothing: an expired token or no internet leaves it running while nothing uploads.

1. **Service running:**

```powershell
Get-CimInstance Win32_Service |
    Where-Object { $_.PathName -match 'fluent-bit\.exe' } |
    Select-Object Name, State, StartMode
```

Expected: `State`:`Running`, `StartMode`:`Auto`.

2. **Files in R2:** in the Cloudflare dashboard, open the bucket and the folder `telemetry/<hostname>/`. New objects with recent dates mean it works. Dates are UTC.

## Logs are not round-the-clock

Endpoints sleep, hibernate, shut down and travel offline. Some only have internet through the corporate VPN. A host produces and uploads logs only while it is on, and uploads only while it can reach R2, so gaps in the bucket (nights, weekends, holidays) are normal and do not mean logs are missing. When a host wakes or reconnects, it uploads what it was holding, and the objects carry the upload date, not the event date.

Only worry when a host that was clearly on and able to reach R2 (someone used it today, on the VPN if that is required) has no objects from today.

## 2. A host stopped uploading

Usual causes: the R2 token expired or was revoked, or the host cannot reach the internet (or the VPN, if it needs one). Check connectivity first. If it is the token, replace it (item 3).

The engine log helps confirm:

```powershell
Get-Content "$env:ProgramData\fluent-bit\logs\fluent-bit.log" -Tail 20
```

Recent `warn` or `error` lines usually mean uploads are failing. A healthy host writes almost nothing.

## 3. Change config, upgrade, or replace the R2 token

Re-run `install.ps1` from the repo folder, in an elevated PowerShell:

```
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

It validates the config before applying it and rolls back if the service fails to start.

- **Config change:** edit the files in `config\`, then re-run.
- **Upgrade Fluent Bit:** change `$FluentBitVersion` in `install.ps1`, then re-run.
- **New R2 token:** delete `%ProgramData%\fluent-bit\secrets\aws-credentials`, then re-run. It prompts for the new keys. If you skip the delete, a valid file is kept and the old keys stay in use. Revoke the old token in Cloudflare afterwards.

## 4. Uninstall

Run in an elevated PowerShell and follow the on-screen prompts:

```
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall.ps1
```

Then revoke the host's token in Cloudflare. Logs already in R2 are not removed.

## 5. Nothing else to maintain

Log rotation runs weekly by itself, and the local buffer is capped at 500 MB.