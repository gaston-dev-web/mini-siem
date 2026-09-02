# Login attempt from blocklisted IP 198.51.100.66

**WHAT FIRED**
SSH Login Attempt From Known-Malicious IP (CRITICAL) — rule
`ssh-login-from-blacklisted-ip`

**WHEN**
2026-09-02 09:29:14 UTC — a single event

**WHO / WHERE**
Source `198.51.100.66` (external, listed in
`rules_examples/lists/known_malicious_ips.txt`) → host `web01`, SSH/22

**WHAT HAPPENED**
One failed password attempt for user `root`, logged as `invalid user` — the
account does not exist on web01.

Pivoted on the indicator across every available log source: this IP appears
exactly once, in one file, against one host and one service. No repeat
attempts, no other protocols, no other hosts. No successful authentication.

**ASSESSMENT**
True positive — the listed IP did contact us, so the detection worked as
designed. **The severity, however, is not justified.**

The CRITICAL rating comes entirely from the blocklist, and the blocklist is an
example file with no source, no date, and no reason-for-listing recorded
against the entry. Behaviourally this event is *less* notable than the HIGH
brute force from `203.0.113.5`: one failed attempt at a nonexistent account is
indistinguishable from routine internet background noise.

Reputation-based detections are only as good as the intel behind them.
Blocklists go stale — an address listed years ago for hosting malware gets
recycled to an unrelated customer, and the entry keeps firing CRITICALs
forever.

**NEXT ACTION**
1. Validate the intel: where did this list come from, who maintains it, when
   was `198.51.100.66` added, and why? Unsourced intel cannot support a
   CRITICAL.
2. Block `198.51.100.66`. Cheap, no operational downside.
3. Pivot wider: check other hosts, and the surrounding `198.51.100.0/24` range,
   for related activity.
4. If the intel cannot be sourced, downgrade this rule's severity. A CRITICAL
   that routinely means nothing trains the whole team to ignore CRITICALs —
   and then one day one of them matters.
