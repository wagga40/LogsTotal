# Windows log samples

Real-world Windows event samples spanning the formats LogsTotal detects. Every
file's detected `LogType` is pinned by `tests/test_sample_logs.py`.

| File | Detected type | Notes |
|------|---------------|-------|
| `bitsadmin.evtx` | `evtx` | Native EVTX (magic bytes `ElfFile\x00`); BITS admin activity. |
| `sysmon_process_creation.json` | `json_evtx` | Sysmon `Microsoft-Windows-Sysmon/Operational` EventID 1 (process creation), JSON-exported EVTX shape. |
| `sysmon_winlogbeat.json` | `json_winlogbeat` | Winlogbeat-shipped Sysmon event (`winlog`/`agent` keys). |
| `security_events.xml` | `xml_evtx` | Raw Windows Security event XML (EventID 4672/4624), the rootless `wevtutil qe /f:xml` layout. Auto-detected and run by `workflows/windows_xml.yml`. Both events parse (2/2) and both are benign, so 0 findings here is the correct result. **Correction (2026-08-05):** the previous note claimed "2 of 8 events parsed" and concluded XML barely worked. The file contains 2 events, not 8 — the count came from grepping `<Event`, which also matches `<EventID>`, `<EventData>` and `<EventRecordID>`. The earlier test also used `--xml-input`, which is the wrong flag for a rootless file; `--evtxtract-input` reads it completely. |

Upload the `evtx` / `json_evtx` / `json_winlogbeat` files to run the default
`windows_full` workflow (Hayabusa + Chainsaw + Zircolite).
