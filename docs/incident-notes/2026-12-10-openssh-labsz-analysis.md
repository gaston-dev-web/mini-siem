# SSH capture analysis — host `LabSZ`, 10 Dec 06:55 → 11:04 UTC

> Analysis performed with mini-siem on `sample_logs/openssh_real.log`, a real
> `/var/log/auth.log` capture published in the open
> [Loghub](https://github.com/logpai/loghub) dataset (OpenSSH). The attackers,
> the IPs and the attempts are real; the host is not a system operated by the
> author, and no action was taken on any of it.
>
> *Spanish original: [`2026-12-10-openssh-labsz-analisis.md`](2026-12-10-openssh-labsz-analisis.md)*

---

## 1. Executive summary

2000 lines of SSH remote-access logs from the server LabSZ were analysed,
covering roughly four hours. The capture contains 524 failed authentication
attempts, mostly against the root account, none of them successful, and one
successful login to the account fztu from an IP with no prior failed attempts.
Whether that access was legitimate is pending verification with the account
owner. Recommended next steps: verify that access, harden the SSH configuration,
and improve detection of low-rate attempts and automated session analysis.

---

## 2. Scope and data

| | |
|---|---|
| Source | `/var/log/auth.log` from a single Linux host |
| Host | `LabSZ` (2000 of 2000 lines) |
| Window | 2026-12-10 06:55:46 → 11:04:45 UTC (4.1 hours) |
| Lines | 2000 |
| Normalised events | 2000 (100 % of lines produced an event) |
| Tooling | mini-siem, 8 detection rules loaded |

Source limitation: this is **a single host** and **a single log source**. There
is no firewall data, no netflow, no application logs. Everything stated below is
limited to what sshd chose to write.

---

## 3. Parser coverage

| event_type / outcome | events | % |
|---|---:|---:|
| `context` / unknown | 874 | 43.7 % |
| `authentication` / failure | 524 | 26.2 % |
| `scan` / unknown | 511 | 25.6 % |
| `warning` / unknown | 85 | 4.2 % |
| `daemon` / unknown *(unrecognised)* | 4 | 0.2 % |
| `authentication` / success | 1 | 0.1 % |
| `session` / success | 1 | 0.1 % |

**Coverage: 99.8 %.** The 4 unrecognised lines are:

```
Invalid user  0101 from 5.188.10.180          <- double space in the username
pam_unix(sshd:session): session opened for user fztu by (uid=0)
pam_unix(sshd:session): session closed for user fztu
fatal: Write failed: Connection reset by peer [preauth]
```

The parser cannot automatically correlate the opening and closing of a session
to determine how long it lasted and whether it closed within the period
analysed. For the fztu account, manual review of the logs does yield a duration
of 12 minutes 46 seconds. These logs do not show what the user did during the
session; investigating that requires additional log sources.

---

## 4. Activity overview

- **30 distinct IPs** appear in the capture.
- **24 IPs** attempted to authenticate and failed.
- **5 IPs** only touched the port and left without attempting credentials.
- **4 IPs** triggered sshd's own warning for a mismatched *reverse DNS* record.
- **524 failed attempts**, **1 successful**.

Most-targeted accounts (of the 524 failures):

| account | attempts |
|---|---:|
| `root` | 370 |
| `admin` | 45 |
| `support` | 6 |
| `oracle` | 6 |
| `uucp` | 5 |
| `test` | 5 |

**27 %** of the failures targeted accounts that **do not exist** on the system.

Distribution by IP (highest failure counts):

| IP | failures | duration | failures/min | distinct accounts |
|---|---:|---:|---:|---:|
| 183.62.140.253 | 286 | 10 min | 27.95 | 10 |
| 187.141.143.180 | 80 | 7 min | 11.06 | 28 |
| 103.99.0.122 | 46 | 113 min | 0.41 | 19 |
| 112.95.230.3 | 26 | 1 min | 26.44 | 3 |
| 5.188.10.180 | 20 | 2 min | 11.01 | 7 |
| 185.190.58.151 | 18 | 6 min | 3.21 | 4 |
| 52.80.34.196 | 5 | 193 min | **0.03** | 3 |

187.141.143.180 spread 80 attempts across 28 accounts, which is consistent with
enumeration of account names. 183.62.140.253 concentrated 286 attempts on 10
accounts, which is consistent with sustained guessing against a small set. The
former may be looking for valid accounts; the latter may be guessing passwords
for names already selected. These data do not, however, demonstrate that either
one knew the system's actual accounts.

---

## 5. Findings

### F1 — Failed attempts against root from multiple IPs

Of the 524 failed attempts, 370 targeted the root account from multiple IPs.
This pattern is consistent with automated attempts against a well-known account
name and does not demonstrate that the activity was specifically directed at
LabSZ. Nor is there sufficient evidence to assert that the various IPs formed a
coordinated campaign. No successful authentication as root appears in the
capture.

### F2 — Low-rate attacker: `52.80.34.196`

52.80.34.196 made five failed attempts separated by approximately 48 minutes,
with only 12 seconds between the shortest and the longest interval. That
regularity indicates an automated process. Its low rate can avoid alerts based
on many failures in a short window, although this does not demonstrate that
evasion was the intent. The DNS name indicates an AWS instance in the Chinese
cn-north-1 region; it does not identify the responsible party or their physical
location. Reporting the abuse to the provider would require supplying the IP and
the exact timestamps. The three attempts against `matlab` may come from a
standard username list. A possible connection to the host name LabSZ is a
hypothesis without sufficient supporting evidence.

Evidence — the five attempts, with exact times:

```
07:07:45  Failed password for invalid user test9   from port 36060
07:56:02  Failed password for invalid user test    from port 36060
08:44:27  Failed password for invalid user matlab  from port 46199
09:32:42  Failed password for invalid user matlab  from port 36060
10:21:09  Failed password for invalid user matlab  from port 36060
```

Intervals between attempts: **48m17s, 48m25s, 48m15s, 48m27s.**

Reverse DNS for the IP:

```
ec2-52-80-34-196.cn-north-1.compute.amazonaws.com.cn
```

### F3 — The single successful login

At 09:32:20 a successful authentication was recorded for the account fztu from
119.137.62.142. The session lasted 12 minutes 46 seconds and ended cleanly. That
IP produced no prior failed attempts in the capture, but none of these facts
demonstrates that the access was authorised. No evidence links it to the IPs
that generated the failed attempts. The next attempt from 52.80.34.196 occurred
22 seconds later and fits that host's established cadence of approximately 48
minutes, so temporal proximity alone is not sufficient to relate them.
Determining whether the access was legitimate requires confirming the connection
with the account owner, comparing the IP against their usual connection origins,
and reviewing activity logs from the session.

Evidence:

```
09:32:20  Accepted password for fztu from 119.137.62.142 port 49116 ssh2
09:32:20  session opened for user fztu
09:45:06  Received disconnect from 119.137.62.142: disconnected by user
09:45:06  session closed for user fztu
```

- `119.137.62.142` **produced no failed attempt** anywhere in the capture.
- The session lasted 12 minutes 46 seconds and ended cleanly.
- 22 seconds after that login, `52.80.34.196` made its fourth attempt.

---

## 6. Verdict: was there a compromise?

**Brute-force attempts:** within the window analysed, 524 failed attempts were
recorded from 24 IPs, with no successful authentication observed from any of
those IPs. There is no indication that those attempts obtained access to the
server during the period covered.

**fztu access:** one successful authentication was recorded from a different IP,
with no evidence linking it to the preceding attempts. Its legitimacy is pending
verification. To close this finding, the account owner must confirm whether they
made that connection at the recorded time, and their answer must be checked
against the connection origin and the session's activity logs. Should the
evidence confirm the access was not authorised, it would be classified as a
compromise.

---

## 7. What this analysis could not see

- **Attempts below the thresholds:** 14 of the 24 IPs with failed attempts
  generated no alert. This is a coverage limitation: activity that fails to
  trigger a rule is not thereby legitimate.
- **No sequence detection:** the engine cannot automatically detect a sequence
  of several failures followed by a successful access from the same IP.
- **Sessions not interpreted automatically:** the parser does not recognise the
  session-open and session-close lines listed above. They must be reviewed
  manually to establish session duration.
- **Post-access activity unknown:** the available logs do not show which commands
  were executed, which files were modified, or whether privileges were escalated.
- **Limited visibility:** only SSH logs from one host over roughly four hours are
  available. There are no logs from other machines, from the firewall, or from
  network traffic with which to investigate related activity.
- **Identity and authorisation unconfirmed:** an IP address and a successful
  authentication are not by themselves sufficient to identify the person who
  connected or to confirm that they were authorised.

---

## 8. Recommendations

**For the host `LabSZ`**

1. **Verify the fztu access:** confirm the connection with the account owner and
   review that session's activity to determine whether it was authorised.
2. **Disable direct SSH access for root** (`PermitRootLogin no`): this would
   prevent direct access to the account that received 370 failed attempts. Verify
   first that another administrative account exists with adequate access and
   permissions.
3. **Move to key-based authentication and disable password authentication:**
   reduces exposure to password-guessing attempts. Confirm first that authorised
   users can log in with their keys.

**For the SIEM**

4. **Extend detection of low-rate attempts:** complement the existing rule with
   longer windows and grouping by IP *and* account, to improve coverage of
   activity that stays below current thresholds. (Note: grouping by two fields at
   once is not supported by the current engine — it is a backlog item, not a
   configuration change.)
5. **Fix the parser and add sequence rules:** recognise session open and close
   lines, and detect failures followed by a successful access, to support
   investigation.

No recommendation is made to block the observed IPs. The infrastructure
identified in F2 is a rented cloud instance, and blocking individual disposable
addresses offers little durable benefit compared with the configuration changes
above. Rate-limiting at the host (for example with fail2ban) addresses the same
problem without depending on a list of addresses.

---

## Appendix A — Alerts generated

12 alerts, across 10 distinct IPs:

| rule | alerts | IPs |
|---|---:|---|
| `ssh-brute-force` (threshold) | 11 | 183.62.140.253 ×2, 103.99.0.122 ×2, 187.141.143.180, 112.95.230.3, 5.188.10.180, 185.190.58.151, 123.235.32.19, 119.4.203.64, 60.2.12.12 |
| `ssh-brute-force-slow` (low_and_slow) | 1 | 52.80.34.196 |

The other 6 loaded rules did not fire: `port-scan-detected`,
`ssh-lateral-movement`, `ssh-login-from-blacklisted-ip`, `web-dir-scan`,
`web-dir-scan-slow`, `web-sqli-attempt`. That is the expected result — this
capture contains no web logs and no traffic towards multiple hosts.

## Appendix B — Reproducing this analysis

```bash
python -m siem.cli ingest-file sample_logs/openssh_real.log sshd
```
