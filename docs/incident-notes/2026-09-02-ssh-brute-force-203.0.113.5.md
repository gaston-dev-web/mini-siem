# SSH brute force from 203.0.113.5

**WHAT FIRED**
SSH Brute Force (HIGH) — rule `ssh-brute-force`

**WHEN**
2026-09-02 09:28:52 – 09:29:12 UTC (20 seconds)

**WHO / WHERE**
Source `203.0.113.5` (external) → host `web01`, SSH/22

**WHAT HAPPENED**
8 failed password attempts against 4 accounts: `root` (x3), `test` (x3),
`admin`, `ubuntu`. Every line is logged as `invalid user` — none of these
accounts exist on web01.

The alert reported only 5 attempts because a threshold rule fires the moment
it crosses its threshold and does not keep counting; `cooldown_seconds: 120`
then suppressed re-alerting. The raw log confirms 8. **The alert understated
the activity by 60%.**

**ASSESSMENT**
True positive, low impact.

Automated credential spray using a generic default-account dictionary. The
account list is evidence in itself: `root`/`admin`/`test`/`ubuntu` are what
every internet bot tries, and none of them exist here — the actor knew nothing
about this host and was not targeting it specifically. Eight attempts in
20 seconds is machine-speed, not a human mistyping.

No successful authentication from this IP. Verified by searching the log for
`Accepted` entries from `203.0.113.5` — none present.

**NEXT ACTION**
1. Block `203.0.113.5` at the perimeter firewall.
2. Check whether other hosts logged activity from the same source IP.
3. No user impact and no compromise — no notification required. Close after
   the block is confirmed.

**NOTE FOR TUNING**
This IP also triggered `port-scan-detected` minutes earlier. Two alerts, one
actor: reconnaissance followed by attack. Worth handling as a single incident
rather than two tickets — and worth considering whether the two rules should
correlate into one higher-confidence detection.
