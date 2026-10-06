<!--
  Copyright (C) 2026 https://github.com/cw-l
  SPDX-License-Identifier: AGPL-3.0-or-later
-->


# Security Model

What this pipeline protects, what it does not, what an endpoint credential exposes, and the options for reducing that exposure.

The options in section 4 are described with their trade-offs. None is presented as a required step.

---

## 1. What it protects, and what it does not

**Protects:**

- **Evidence survives the endpoint.** Events are uploaded about every 2 minutes and buffered on disk while the host is offline. An attacker who later wipes or encrypts the machine cannot remove what was already shipped.
- **Tampering leaves a trace.** Log clearing (1102, 104) and audit policy changes (4719) are collected, and shipped if the service is still running.

**Does not protect:**

- **A compromised endpoint.** An attacker with local administrator or SYSTEM rights can stop or delete the service, edit the configuration, read the stored credentials, or switch off auditing. Events after that point may never be shipped, and events not yet uploaded (up to about 2 minutes) can be lost.
- **The uploaded logs themselves.** See section 3.
- **Detection.** The pipeline stores logs. It does not alert.

## 2. Credentials on the endpoint

- The R2 key pair is stored in `%ProgramData%\fluent-bit\secrets\aws-credentials`. The installer creates it on a fresh install and preserves it on re-runs.
- The service runs as SYSTEM, the default for a service created this way. Its environment holds only the path to the credentials file, not the secret.
- The installer disables inheritance and grants full control to SYSTEM and Administrators only. It aborts if any other account has access. Verify the result:

```
icacls "%ProgramData%\fluent-bit\secrets\aws-credentials"
```

Expected: only SYSTEM and Administrators. If anything else appears (for example `BUILTIN\Users`), the permissions were changed after install: re-run `install.ps1` to restore them.

- Anyone with local administrator rights can read the file. Treat the token as exposed if any administrator account on an endpoint is compromised.

## 3. What a stolen token allows

The API token permission is **Workers R2 Storage Bucket Item Write**, scoped to a specific bucket. Cloudflare documents this permission as read, write and list for objects in that bucket. There is no write-only token option. So whoever holds the token can:

- **Read** every log in the bucket, including other hosts' logs (confidentiality).
- **Overwrite or delete** existing objects (integrity), unless a bucket lock is in place.
- **Write** unlimited data: plant false logs, fill the free tier, or run up cost.

Section 4 reduces some of this. The options differ in what they limit, and none of the first six removes read access.

## 4. Options for reducing the exposure

### Available with the current design

| Option | Limits | Does not limit | Cost |
|---|---|---|---|
| **Object Read & Write, not Admin** | Admin permissions are account-wide and cannot be scoped to a bucket. Object permissions can. | The read, write and list access above | None |
| **Scope the token to the one bucket** | A stolen token cannot reach other buckets | For the long-lived R2 API token used by this design, scope is per bucket, not per prefix. Cloudflare also supports temporary credentials with prefix-level scoping, but the current Fluent Bit design does not use them. | None |
| **Token expiry (TTL)** | The lifetime of a stolen token. The dashboard offers a TTL, and the API accepts an expiry time | An active token | An expired token causes uploads to fail; without external monitoring or alerting, the failure may not be noticed until the local buffer fills. Logs buffer on disk and can be lost once the 500 MB cap is reached, so an expiry needs a reminder and a way to notice that uploads stopped |
| **Rotate on a schedule** | How long a leaked token stays useful | An attacker who acts before the next rotation | Rotation is manual on every endpoint today |
| **Token per endpoint group** | Revocation: one compromised group needs only its own token replaced | Data access within a group's bucket. Isolating data between groups needs a bucket per group, since scope is per bucket | More tokens, and optionally more buckets, to manage |
| **Bucket Lock** | Deletion and overwriting of matching objects during the configured retention period; retention can be time-based, date-based, or indefinite. | Lock rules take precedence over lifecycle rules, so the lock period should not exceed your retention window or storage will not expire. A bucket cannot be emptied while lock rules exist. | None |

Uploads use a timestamp and a unique ID in every object key, so each upload creates a new object and a lock does not block legitimate writes.

### Alternative designs (not implemented)

| Option | What changes | Limits | Trade-offs |
|---|---|---|---|
| **Proxy uploads through a Cloudflare Worker** | The endpoint holds a revocable per-host secret instead of R2 keys. The Worker holds the R2 access | A stolen secret could be limited to writing under one host's prefix, with no reads and no overwrites | On the Fluent Bit side the `s3` output is replaced by the `http` output. `flush` must be raised to batch, the object naming and the secret handling move elsewhere, and request volume depends on the number of active inputs. A server-side component must be built and maintained |
| **Relay through a central collector** | Endpoints send to a collector you run. Only the collector holds the R2 token | No R2 credential on endpoints | You run and patch a server, which this design otherwise avoids. Roaming laptops need a route to it. The collector becomes a single point of failure and a high-value target |

## 5. Log sensitivity

The collected events can contain secrets and personal data:

- **4104 script blocks** and **4688 command lines** can include passwords, tokens and keys typed into scripts or arguments.
- **Account and logon events** carry usernames, hostnames and source addresses (4624, 1149).
- **File events (4663)** carry file paths and names, which may reveal personal or client data.
- **Wireless events (8001)** record network names a laptop joined.

Things to decide per deployment:

- **Who can read the bucket.** Anyone with the token, or with access to the Cloudflare account, can read everything. Protect the Cloudflare account itself, for example with multi-factor authentication.
- **Retention.** A longer retention window means more exposure and more stored data.
- **Obligations.** Data-protection rules may apply to logs that contain personal data, and customer agreements may restrict where logs are stored.

## 6. If an endpoint is compromised

1. **Treat that host's credential as exposed.** Revoke the token in Cloudflare. If other endpoints share it, their uploads fail until each gets a new token. They buffer on disk meanwhile, up to the 500 MB cap.
2. **Assume the bucket was readable.** A token can read all logs it is scoped to, so other hosts' logs in the same bucket may have been exposed.
3. **Review the bucket** for unexpected objects, deletions and overwrites. Objects under a bucket lock cannot have been deleted or overwritten during the lock.
4. **Treat that host's logs after the compromise time as untrusted.** An attacker with administrator rights could have stopped the service or forged events.
5. **Issue new tokens** and redeploy the credentials.