# Sample logs

Real-world log samples for trying LogsTotal and for detector regression tests.
Organised by platform; each subdirectory's README maps every file to its
detected `LogType` and the workflow that processes it.

- [`linux/`](linux/README.md) — syslog, auditd, journald, Sysmon for Linux
- [`windows/`](windows/README.md) — EVTX, JSON EVTX, Winlogbeat, Security XML

`tests/test_sample_logs.py` pins each sample's detected type and fails if a new
sample is added without registering it, so this stays honest.
