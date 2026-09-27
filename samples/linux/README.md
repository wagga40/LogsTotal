# Linux log samples

Real-world Linux log files for exercising the Linux detection workflows. Every
file's detected `LogType` is pinned by `tests/test_sample_logs.py`.

| File | Detected type | Engine (workflow) |
|------|---------------|-------------------|
| `syslog_intrusion.log` | `syslog` | ChopChopGo (`linux_syslog`) |
| `syslog_benign.log` | `syslog` | ChopChopGo (`linux_syslog`) |
| `auditd_sample.log` | `auditd` | Zircolite `--auditd` (`linux_auditd`) |
| `sysmon_linux_sample.log` | `sysmon_linux` | Zircolite `-S` (`linux_sysmon`) |
| `journald_sample.json` | `journald` | Zircolite `-j` + field aliases (`linux_journald`) |

`auditd_sample.log` is a raw `/var/log/audit/audit.log` capture (SYSCALL / EXECVE
/ PATH / PROCTITLE records); `sysmon_linux_sample.log` is Sysmon-for-Linux
syslog-wrapped XML events; `journald_sample.json` is a `journalctl -o json` export.

## `journald_sample.json`

A `journalctl -o json` NDJSON export captured from a throwaway Ubuntu 26.04 VM
(`web01`). Benign cron/systemd noise interleaved with an attack-shaped command
sequence: recon, reverse-shell command lines, download-and-execute, GTFOBins
shell escapes, setuid persistence, audit/history clearing, and exfiltration.

Every command in the capture is **inert** — the payloads are `echo`, the
addresses are RFC 5737 documentation ranges (`198.51.100.0/24`), and nothing was
downloaded or executed. Only the *shape* of `_CMDLINE` matters, because that is
what the Sigma process-creation rules key on.

Produces **45 detections across 7 rules** with `linux_journald.yml`
(Zircolite 4.0.0, September 2026 `rules_linux.json`, `zircolite_journald.yaml` aliases).
All 181 events parse; the six previous rules and their 37 hits remain present:

| Rule | Level | Hits |
|---|---|---|
| Linux Reverse Shell Indicator | critical | 8 |
| Execution Of Script Located In Potentially Suspicious Directory | medium | 1 |
| Bash Interactive Shell | low | 2 |
| Crontab Enumeration | low | 2 |
| Local System Accounts Discovery - Linux | low | 27 |
| System Information Discovery | informational | 1 |
| System Network Discovery - Linux | informational | 4 |

Coverage is deliberately modest, and that is a property of the ruleset rather
than of this file: the compiled Linux Sigma set has no journald-specific rules,
only process- and command-shaped ones that the field aliases can reach. Rules
keying on parent process, hashes or network tuples cannot match a journald
export at all. `workflows/linux_journald.yml` documents the trade-off.

At ~180 KB it is much larger than the other samples. That is inherent: a
journald JSON record carries around 25 metadata fields, so a couple of hundred
entries is a couple of hundred kilobytes. It is a real export, not padded.

## Syslog samples

Detected as `syslog` by `app/detection/detector.py`; verified end-to-end against
`tools/chopchopgo/rules/builtin/` (ChopChopGo v1.1.0, 2026-07-19).

## `syslog_intrusion.log`

A single-host intrusion timeline (web server `web01`) reading like a real
`/var/log/syslog`: benign cron/systemd/sshd noise interleaved with an attack
chain — Shellshock CGI initial access, a reverse shell, payload download,
privilege escalation, persistence, exfiltration, and log cleanup.

Produces **13 detections across 10 rules**:

| Line context | Rule | Level |
|---|---|---|
| `apache2 … "() { :;}; …"` | Shellshock Expression | high |
| `sshd … buffer_get_string: bad string` / `Corrupted MAC on input` | Suspicious OpenSSH Daemon Error (×2) | medium |
| `sudo … bash -i >& /dev/tcp/…` | Suspicious Reverse Shell Command Line | high |
| `wget …; chmod +x`, `… | base64 -d | sh`, `chmod u+s /tmp/…` | Suspicious Activity in Shell Commands (×3) | high |
| `ln -s /etc/passwd …` | Symlink Etc Passwd | high |
| `echo … > /etc/ld.so.preload` | Code Injection by ld.so Preload | high |
| `crontab … REPLACE` | Modifying Crontab | medium |
| `scp /tmp/loot.tar.gz attacker@…:` | Remote File Copy | low |
| `history -c; rm -f …bash_history` | Linux Command History Tampering | high |
| `rm -rf /var/log/syslog` | Commands to Clear or Remove the Syslog | high |

The file also contains realistic malicious lines that ChopChopGo does **not**
flag because its keyword-based syslog engine doesn't evaluate every SIGMA
condition — a privileged-user-creation `useradd … UID=0, GID=0` line (needs
`all of selection_*`) and a secondary `exec 5<>/dev/tcp/…` C2 line. They are
kept deliberately: real logs contain activity a given engine misses, so the
detection ratio is honestly below 100%.

## `syslog_benign.log`

Normal operations (cron, logrotate, nginx restart via sudo, postfix, chrony) —
a clean baseline that produces **0 detections**, useful for confirming the
false-positive rate.

## Reproduce

```bash
tools/chopchopgo/chopchopgo-<arch>-lin \
  -target syslog -rules tools/chopchopgo/rules/builtin \
  -file samples/linux/syslog_intrusion.log -out json
```
