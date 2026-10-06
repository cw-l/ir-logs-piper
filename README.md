# IR Logs Piper

Ships selected Windows Event Logs from endpoints to Cloudflare R2, so you have evidence off the machine after an incident.

## Who is this for

- Solo or small IT teams at Small Medium Businesses (SMBs) with Windows 10/11 endpoints, workgroup or Active Directory joined.
- No existing SIEM, EDR log collection, or Windows Event Forwarding (WEF) collector.
- You want free/low-cost, off-host log retention for resilience and incident response (DFIR), not live monitoring.

**Not a fit if:** you have a SIEM, EDR/MDR or WEF in operations; policy requires on-premises log storage; or you need real-time alerting. This is store-and-retrieve for IR only.

## What it does

```
Windows Event Logs -> Fluent Bit (Windows service) -> gzip -> Cloudflare R2
```

- Reads a pre-selected set of event IDs from `Security`, `PowerShell`, `Shell-Core`, `System`, `Application`, `Task Scheduler`, `WinRM`, `RDP`, `Firewall`, `Defender`, `AppLocker` and `WLAN` channels.
- Tags each record with the hostname and pipeline version, and throttles event storms.
- Buffers to local disk (500 MB cap) and retries indefinitely if the network or R2 is unavailable.
- Uploads in batches (about every 2 minutes) to `telemetry/<hostname>/<date>/` in your bucket.

**Does not:** parse, alert, or analyze. Logs arrive as gzip-compressed JSON for you to review during an investigation.

## Free-tier capacity

On the R2 free tier (10 GB storage, 1M write operations per month), the current settings support roughly **45 hosts** before write operations exceed the free limit (worst case, 2-minute upload interval). Storage is usually the tighter limit: it depends on MB per host per day and how many days you retain. Pilot on a few hosts for a week and measure before rolling out. See [docs/capacity-planning.md](docs/capacity-planning.md).

## Prerequisites

- Windows 10/11 (tested on Windows 10 Pro), local administrator, outbound HTTPS.
- A Cloudflare R2 bucket and an API token with **Workers R2 Storage Bucket Item Write**, scoped to that bucket.
- Audit policy configured on each endpoint (commands for a workgroup, GPO for a domain). Without it, most `Security`, `PowerShell` script-block and `Task Scheduler` events are never generated, so key evidence will be missing. The pipeline still runs and ships whatever Windows logs by default. Follow the **Implemented** section of [docs/audit-policy.md](docs/audit-policy.md). The **Recommended** section is optional.
- Endpoints only. Do not install on domain controllers: the event set does not cover Kerberos or directory-service events.

## Quick Start

1. **Set your bucket.** In `config/outputs.yaml`, set `bucket` and `endpoint` to your R2 bucket and account endpoint.
2. **Copy the repo** (`scripts/` and `config/`) to the endpoint.
3. **Run as Administrator:**
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
   ```
   On a fresh install, or missing credential file, it prompts for the R2 Access Key ID and Secret Access Key, stores them in `%ProgramData%\fluent-bit\secrets` (SYSTEM and Administrators only), installs Fluent Bit, deploys the config and starts the `fluent-bit` service.
4. **Verify.**
   ```powershell
   Get-Service fluent-bit
   ```
   Within a few minutes, objects should appear in your bucket under `telemetry/<hostname>/`.

The first start also uploads existing events still in the logs, so expect an initial burst.

See [docs/operations.md](docs/operations.md) for details.

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall.ps1
```

Removes the log rotation scheduled task, the service, the Fluent Bit program and `%ProgramData%\fluent-bit` (including unsent buffered logs). It does not delete logs already in R2 and does not revoke the R2 token: revoke that in Cloudflare.

## Guides
Read [docs/events-selection.md](docs/events-selection.md) to find out what Windows Events were collected and [docs/retrieving-logs.md](docs/retrieving-logs.md) on what to do, before and during an incident.

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE).

Installs Fluent Bit (Apache-2.0), downloaded from its vendor at install time and not included in this repository.