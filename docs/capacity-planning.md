<!--
  Copyright (C) 2026 https://github.com/cw-l
  SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Capacity Planning

For the IT admin. Decide the scope, plan storage and cost, and get approval before rolling out to every endpoint. Revisit if you extend retention or add endpoints.

## 1. Decide the scope

Choose which endpoints to cover:

- **All endpoints.** Every host has off-host logs. Highest storage and cost.
- **Selected endpoints,** by your own internal criteria. Lower storage and cost, but an endpoint not covered leaves no off-host evidence if it is involved in an incident.

This is a business decision, not a technical one. Agree it with whoever approves the spend, and write down what was decided and why.

## 2. Run a pilot

Install on a few representative hosts and let them run for about a week. Usage differs a lot between machines, so measure your own fleet; do not rely on a generic figure.

## 3. Measure

After the pilot, find the bucket's total size and its object count. See [Cloudflare's R2 documentation](https://developers.cloudflare.com/r2/) for how.

## 4. Estimate

- **Storage per host per day** = total size / hosts / days.
- **Storage needed** = hosts in scope x storage per host per day x days you keep logs.
- **Write operations per month** = roughly the number of objects uploaded (each object is one upload). Count the pilot's objects per host per day and scale to your scope and a month.
- **Read operations** = what the IR team downloads during an engagement. Egress itself is free.

Illustrative only: 10 hosts x 20 MB per day x 90 days = 18 GB.

## 5. Check the cost

Compare your estimate with the free tier and the paid rates on [Cloudflare's R2 pricing page](https://developers.cloudflare.com/r2/pricing/). If you will exceed the free tier, or want to keep more than it covers, work out what that costs the firm per month and get it approved before you roll out. Rates and limits change, so use the page, not this document.

## 6. Decide retention

Logs are kept until something deletes them, so storage only grows. Decide how long the firm needs them. To delete older logs automatically, use an R2 lifecycle rule: see [Cloudflare's object lifecycle documentation](https://developers.cloudflare.com/r2/buckets/object-lifecycles/).

## 7. Optional: keep logs longer for less

Cloudflare offers a cheaper storage class for data that is rarely read, and lifecycle rules can move older logs into it automatically. It can lower the cost of long retention. It may not be free and can add retrieval charges and minimum storage periods, which matter when the IR team downloads a lot. Read [Cloudflare's storage class documentation](https://developers.cloudflare.com/r2/buckets/storage-classes/) and [pricing](https://developers.cloudflare.com/r2/pricing/), then decide whether it suits you. If you adopt it, include it in the cost estimate in section 5.