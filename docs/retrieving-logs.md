<!--
  Copyright (C) 2026 https://github.com/cw-l
  SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Retrieving Logs

For the IT admin (owns the Cloudflare account) and the IR team. Logs sit in the R2 bucket. The IR team needs read access for the length of the engagement, nothing more.

Downloading from R2 carries no egress fee, so the IR team can pull as much as the investigation needs without a transfer bill landing on the IT admin. See [Cloudflare's R2 pricing](https://developers.cloudflare.com/r2/pricing/) for what is billed.

## IT admin: give the IR team access

Create a new R2 API token for the IR team, following [Cloudflare's R2 API token documentation](https://developers.cloudflare.com/r2/api/tokens/), with:

- **Object Read only** permission
- scope limited to the logs bucket
- an expiry matching the engagement period agreed with the IR team (for example one week or one month)

Do not hand over the pipeline's own token. It has write access and sits on every endpoint.

Give the IR team the Access Key ID, the Secret Access Key, the bucket name and the account's S3 endpoint. How to pass these over is for you and the IR team to agree before the engagement starts. When the engagement ends, revoke the token; the expiry is only the backstop.

## IR team: read the logs

Get the credentials from the IT admin. Any S3-compatible client works; see [Cloudflare's R2 documentation](https://developers.cloudflare.com/r2/) for connecting one.

**Layout:** `telemetry/<hostname>/<YYYY-MM-DD>/<HHMMSS>_<id>.json.gz`. The date and time are UTC and mark when the object was written, not when the events happened.

**Each object:** gzip, newline-delimited JSON, one event per line. Each log source is batched separately, so an object does not map to one channel and its name does not say what it holds.

**What is available:** see [events-selection.md](events-selection.md).

**Do not assume completeness:**

- Bursts above an average of 100 events per second are rate-limited, so a flood may be incomplete.
- A host that is offline buffers locally (500 MB cap) and uploads when it reconnects.
- No objects for a period means the host was off, offline or the pipeline stopped. The logs cannot tell you which.