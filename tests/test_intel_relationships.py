"""Tier-1 pure-function tests for typed entity relationship extraction.

`app/intel/relationships.py` must not import FastAPI or Huey — these tests
exercise the extractors directly with plain event dicts.

The extractors must produce entity *values* normalized exactly like
``_compute_analytics_data`` in ``app/routers/jobs.py`` so the tuples line up
with the ``entity_map`` keys ``(value, entity_type)``:

- executable: ``os.path.basename`` of the path, backslashes folded, lowercased
- hash: uppercased hex (from ``MD5=..,SHA256=..`` composite or bare hex)
- user: stripped, machine accounts (trailing ``$``) and noise users dropped
- domain: stripped + lowercased, must look like a domain (not an IP)
- ip: raw matched form
"""

from __future__ import annotations

from app.intel.relationships import (
    ASSOCIATIONS,
    EVIDENCE_FIELDS,
    RELATIONSHIP_ENDPOINTS,
    RELATIONSHIP_TYPES,
    build_association_groups,
    extract_relationships,
    parse_sysmon_query_results,
    trim_evidence_event,
)

# ── parse_sysmon_query_results ─────────────────────────────────────────────


def test_query_results_extracts_ipv4_mapped_addresses():
    raw = "::ffff:104.16.0.1;::ffff:104.16.0.2;"
    assert parse_sysmon_query_results(raw) == ["104.16.0.1", "104.16.0.2"]


def test_query_results_strips_type_prefix_and_keeps_ips_only():
    raw = "type:  5 cdn.example.com;::ffff:1.2.3.4;"
    assert parse_sysmon_query_results(raw) == ["1.2.3.4"]


def test_query_results_plain_ipv4():
    assert parse_sysmon_query_results("192.168.1.10;8.8.8.8;") == ["192.168.1.10", "8.8.8.8"]


def test_query_results_no_answer_placeholders_return_empty():
    assert parse_sysmon_query_results("-") == []
    assert parse_sysmon_query_results("") == []
    assert parse_sysmon_query_results("::;") == []


def test_query_results_deduplicates_preserving_order():
    raw = "::ffff:1.1.1.1;::ffff:1.1.1.1;2.2.2.2;"
    assert parse_sysmon_query_results(raw) == ["1.1.1.1", "2.2.2.2"]


# ── extract_relationships: hashes_to (the user's explicit ask) ─────────────


def test_sysmon1_image_to_hash_edge():
    event = {
        "EventID": 1,
        "Image": r"C:\Windows\System32\powershell.exe",
        "Hashes": "MD5=00112233445566778899AABBCCDDEEFF,SHA256=" + "a" * 64,
        "Computer": "WS01",
    }
    rels = extract_relationships(event)
    assert ("powershell.exe", "executable", "00112233445566778899AABBCCDDEEFF", "hash", "hashes_to") in rels
    assert ("powershell.exe", "executable", "A" * 64, "hash", "hashes_to") in rels


def test_sysmon1_parent_of_edge():
    event = {
        "EventID": 1,
        "ParentImage": r"C:\Windows\explorer.exe",
        "Image": r"C:\Windows\System32\cmd.exe",
    }
    rels = extract_relationships(event)
    assert ("explorer.exe", "executable", "cmd.exe", "executable", "parent_of") in rels


def test_sysmon1_runs_on_host_edge():
    event = {"EventID": 1, "Image": r"C:\evil.exe", "Computer": "HOST-7"}
    rels = extract_relationships(event)
    assert ("evil.exe", "executable", "HOST-7", "computer", "runs_on") in rels


def test_sysmon7_loads_and_hashes_loaded_image():
    event = {
        "EventID": 7,
        "Image": r"C:\Windows\System32\lsass.exe",
        "ImageLoaded": r"C:\temp\evil.dll",
        "Hashes": "SHA256=" + "b" * 64,
    }
    rels = extract_relationships(event)
    assert ("lsass.exe", "executable", "evil.dll", "executable", "loads") in rels
    # In Sysmon 7 the Hashes field describes the *loaded* image
    assert ("evil.dll", "executable", "B" * 64, "hash", "hashes_to") in rels


# ── extract_relationships: resolves_to ─────────────────────────────────────


def test_sysmon22_domain_resolves_to_ips():
    event = {
        "EventID": 22,
        "QueryName": "malware.example.com",
        "QueryResults": "::ffff:93.184.216.34;",
    }
    rels = extract_relationships(event)
    assert ("malware.example.com", "domain", "93.184.216.34", "ip_address", "resolves_to") in rels


# ── extract_relationships: auth surfaces (gated by EventID) ────────────────


def test_security_4624_logon_edges():
    event = {
        "EventID": 4624,
        "TargetUserName": "jdoe",
        "IpAddress": "10.0.0.5",
        "Computer": "DC01",
    }
    rels = extract_relationships(event)
    assert ("jdoe", "user", "10.0.0.5", "ip_address", "logs_on_from") in rels
    assert ("jdoe", "user", "DC01", "computer", "logs_on_to") in rels


def test_logon_skips_machine_accounts_and_dash_ip():
    event = {
        "EventID": 4624,
        "TargetUserName": "WS01$",  # machine account -> not a user entity
        "IpAddress": "-",  # no source IP
        "Computer": "DC01",
    }
    rels = extract_relationships(event)
    assert all(r[4] != "logs_on_from" for r in rels)
    assert all(r[1] != "user" for r in rels)


def test_sysmon3_connects_to_only_between_external_ips():
    external = {"EventID": 3, "SourceIp": "8.8.8.8", "DestinationIp": "1.1.1.1"}
    rels = extract_relationships(external)
    assert ("8.8.8.8", "ip_address", "1.1.1.1", "ip_address", "connects_to") in rels

    internal = {"EventID": 3, "SourceIp": "10.0.0.1", "DestinationIp": "10.0.0.2"}
    rels2 = extract_relationships(internal)
    assert all(r[4] != "connects_to" for r in rels2)


# ── extract_relationships: structural guarantees ──────────────────────────


def test_nested_evtx_shape_is_flattened():
    event = {
        "Event": {
            "System": {"EventID": 1, "Computer": "NEST01"},
            "EventData": {"Image": r"C:\a\rundll32.exe", "Hashes": "SHA1=" + "c" * 40},
        }
    }
    rels = extract_relationships(event)
    assert ("rundll32.exe", "executable", "C" * 40, "hash", "hashes_to") in rels
    assert ("rundll32.exe", "executable", "NEST01", "computer", "runs_on") in rels


def test_unknown_event_yields_no_relationships():
    assert extract_relationships({"EventID": 9999, "Foo": "bar"}) == []
    assert extract_relationships({}) == []
    assert extract_relationships("not a dict") == []


def test_all_emitted_types_are_registered():
    sample_events = [
        {"EventID": 1, "Image": r"C:\a.exe", "ParentImage": r"C:\b.exe", "Hashes": "SHA256=" + "d" * 64, "Computer": "C1", "User": "alice"},
        {"EventID": 7, "Image": r"C:\a.exe", "ImageLoaded": r"C:\c.dll", "Hashes": "MD5=" + "e" * 32},
        {"EventID": 22, "QueryName": "x.example.org", "QueryResults": "9.9.9.9;"},
        {"EventID": 4624, "TargetUserName": "bob", "IpAddress": "8.8.4.4", "Computer": "C2"},
        {"EventID": 3, "SourceIp": "8.8.8.8", "DestinationIp": "1.1.1.1"},
        {"EventID": 11, "Image": r"C:\a.exe", "TargetFilename": r"C:\drop\payload.bat"},
    ]
    emitted = {r[4] for ev in sample_events for r in extract_relationships(ev)}
    assert emitted, "expected at least some relationships"
    assert emitted <= set(RELATIONSHIP_TYPES), f"unregistered types: {emitted - set(RELATIONSHIP_TYPES)}"


def test_runs_as_owning_user_for_process_event():
    event = {"EventID": 1, "Image": r"C:\svc.exe", "User": "CORP\\svc-backup"}
    rels = extract_relationships(event)
    assert ("svc.exe", "executable", "CORP\\svc-backup", "user", "runs_as") in rels


def test_sysmon11_creates_cmdline_file():
    event = {"EventID": 11, "Image": r"C:\dropper.exe", "TargetFilename": r"C:\drop\payload.bat"}
    rels = extract_relationships(event)
    assert ("dropper.exe", "executable", "payload.bat", "cmdline_file", "creates") in rels


# ── trim_evidence_event ────────────────────────────────────────────────────


def test_trim_keeps_only_whitelisted_fields():
    event = {
        "EventID": 1,
        "Image": r"C:\evil.exe",
        "Computer": "WS01",
        "CommandLine": "secret --flag",  # not whitelisted → dropped
        "User": "DOMAIN\\alice",
    }
    out = trim_evidence_event(event)
    assert out == {"EventID": 1, "Image": r"C:\evil.exe", "Computer": "WS01", "User": "DOMAIN\\alice"}
    assert "CommandLine" not in out


def test_trim_flattens_nested_evtx_shape():
    event = {"Event": {"System": {"EventID": 3, "Computer": "HOST"}, "EventData": {"SourceIp": "8.8.8.8", "DestinationIp": "1.1.1.1"}}}
    out = trim_evidence_event(event)
    assert out["EventID"] == 3
    assert out["Computer"] == "HOST"
    assert out["SourceIp"] == "8.8.8.8"
    assert out["DestinationIp"] == "1.1.1.1"


def test_trim_drops_empty_and_nonscalar_values():
    event = {"Image": "   ", "Hashes": "MD5=ABC", "QueryResults": [], "EventID": ""}
    out = trim_evidence_event(event)
    assert out == {"Hashes": "MD5=ABC"}


def test_trim_handles_non_dict():
    assert trim_evidence_event("nope") == {}
    assert trim_evidence_event(None) == {}


def test_evidence_fields_are_unique():
    assert len(EVIDENCE_FIELDS) == len(set(EVIDENCE_FIELDS))


# ── ASSOCIATIONS map + build_association_groups (Overview card) ────────────


def test_relationship_endpoints_cover_all_types():
    assert set(RELATIONSHIP_ENDPOINTS) == set(RELATIONSHIP_TYPES)


def test_associations_reference_valid_types_and_directions():
    for entity_type, specs in ASSOCIATIONS.items():
        seen = set()
        for spec in specs:
            assert spec.rel_type in RELATIONSHIP_TYPES, (entity_type, spec)
            assert spec.direction in ("in", "out"), (entity_type, spec)
            assert spec.label.strip(), (entity_type, spec)
            assert (spec.rel_type, spec.direction) not in seen, (entity_type, spec)
            seen.add((spec.rel_type, spec.direction))


def test_associations_directions_match_endpoint_typing():
    # "out" means the focal entity is the edge source, so its type must be the
    # canonical source type of that relationship (and vice versa for "in").
    for entity_type, specs in ASSOCIATIONS.items():
        for spec in specs:
            src_type, tgt_type = RELATIONSHIP_ENDPOINTS[spec.rel_type]
            expected = src_type if spec.direction == "out" else tgt_type
            assert entity_type == expected, (entity_type, spec)


def test_build_association_groups_orders_and_omits_empty():
    exe_a, exe_b, host = object(), object(), object()
    rows_by_direction = {
        # runs_on comes after parent_of in the executable spec order, but is
        # listed first here — output must follow spec order regardless.
        "out": [
            ("runs_on", 5, 1, host),
            ("parent_of", 2, 1, exe_b),
        ],
        "in": [("parent_of", 7, 1, exe_a)],
    }
    groups = build_association_groups("executable", rows_by_direction)
    assert [(g["rel_type"], g["direction"]) for g in groups] == [
        ("parent_of", "in"),
        ("parent_of", "out"),
        ("runs_on", "out"),
    ]
    assert groups[0]["label"] == "Parent processes"
    assert groups[0]["rows"] == [{"entity": exe_a, "occurrence_count": 7}]
    assert all(g["overflow"] == 0 for g in groups)


def test_build_association_groups_unknown_entity_type():
    assert build_association_groups("service", {"out": [], "in": []}) == []
    assert build_association_groups("nonsense", {"out": [("hashes_to", 1, 1, object())], "in": []}) == []


def test_build_association_groups_overflow():
    rows = [("hashes_to", 10 - i, 13, object()) for i in range(10)]
    groups = build_association_groups("executable", {"out": rows, "in": []})
    assert len(groups) == 1
    assert groups[0]["overflow"] == 3
    assert len(groups[0]["rows"]) == 10

    exact = [("hashes_to", 1, 2, object()), ("hashes_to", 1, 2, object())]
    groups = build_association_groups("executable", {"out": exact, "in": []})
    assert groups[0]["overflow"] == 0


# ── extract_relationships: auditd (flat Zircolite output) ──────────────────


def test_auditd_execve_runs_as_and_communicates():
    ev = {
        "type": "SYSCALL",
        "exe": "/usr/bin/curl",
        "comm": "curl",
        "pid": "1234",
        "ppid": "1000",
        "acct": "root",
        "addr": "203.0.113.5",
        "proctitle": "curl http://evil.example",
    }
    rels = extract_relationships(ev)
    assert ("curl", "executable", "root", "user", "runs_as") in rels
    assert ("curl", "executable", "203.0.113.5", "ip_address", "communicates_with") in rels


def test_auditd_runs_on_hostname():
    ev = {"exe": "/usr/bin/ssh", "pid": "77", "hostname": "web01"}
    rels = extract_relationships(ev)
    assert ("ssh", "executable", "web01", "computer", "runs_on") in rels


def test_auditd_node_field_as_hostname():
    ev = {"exe": "/usr/bin/ssh", "pid": "77", "node": "db02"}
    rels = extract_relationships(ev)
    assert ("ssh", "executable", "db02", "computer", "runs_on") in rels


def test_auditd_uid_fallback_when_no_acct():
    ev = {"exe": "/usr/bin/sudo", "pid": "5", "uid": "1000"}
    rels = extract_relationships(ev)
    assert ("sudo", "executable", "1000", "user", "runs_as") in rels


def test_auditd_creates_on_create_nametype():
    ev = {"exe": "/usr/bin/wget", "pid": "9", "name": "/tmp/payload.sh", "nametype": "CREATE"}
    rels = extract_relationships(ev)
    assert ("wget", "executable", "payload.sh", "cmdline_file", "creates") in rels


def test_auditd_creates_skipped_for_other_nametype():
    ev = {"exe": "/usr/bin/cat", "pid": "9", "name": "/etc/passwd", "nametype": "NORMAL"}
    rels = extract_relationships(ev)
    assert not any(r[4] == "creates" for r in rels)


def test_auditd_a0_fallback_image():
    ev = {"a0": "nmap", "pid": "3", "acct": "root"}
    rels = extract_relationships(ev)
    assert ("nmap", "executable", "root", "user", "runs_as") in rels


def test_auditd_no_exe_no_edges():
    ev = {"type": "SYSCALL", "pid": "1", "acct": "root", "addr": "1.2.3.4"}
    assert extract_relationships(ev) == []


def test_windows_event_gets_no_linux_edges():
    ev = {
        "EventID": 1,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "ParentImage": "C:\\Windows\\explorer.EXE",
        "Computer": "WS01",
    }
    rels = extract_relationships(ev)
    assert not any(r[4] == "communicates_with" for r in rels)


def test_trim_keeps_auditd_fields():
    ev = {"exe": "/usr/bin/curl", "pid": "1", "addr": "1.2.3.4", "totally_unknown_field": "x"}
    trimmed = trim_evidence_event(ev)
    assert trimmed == {"exe": "/usr/bin/curl", "pid": "1", "addr": "1.2.3.4"}


# ── Zircolite offline-mode host sentinel (E2E finding) ─────────────────────


def test_auditd_offline_host_sentinel_dropped():
    """Zircolite offline mode emits host="offline"; it must not become an edge."""
    ev = {"a0": "chmod", "a1": "777", "type": "EXECVE", "host": "offline"}
    rels = extract_relationships(ev)
    assert ("chmod", "executable", "offline", "computer", "runs_on") not in rels
    assert not any(r[2] == "offline" for r in rels)


def test_auditd_real_host_still_extracted():
    ev = {"a0": "chmod", "type": "EXECVE", "host": "web01"}
    rels = extract_relationships(ev)
    assert ("chmod", "executable", "web01", "computer", "runs_on") in rels
