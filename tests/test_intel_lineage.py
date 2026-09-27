"""Tier 1 pure tests for app/intel/lineage.py::build_process_forest."""

from app.intel.lineage import DEFAULT_MAX_NODES, MAX_DEPTH, build_process_forest


def _sysmon(guid, pid, image, *, pguid=None, ppid=None, pimage=None, cmd=None, time=None, computer="HOST1", user=None):
    """A flat Sysmon EID 1 event (Zircolite-style: fields at top level)."""
    ev = {"EventID": 1, "ProcessGuid": guid, "ProcessId": pid, "Image": image, "Computer": computer}
    if pguid is not None:
        ev["ParentProcessGuid"] = pguid
    if ppid is not None:
        ev["ParentProcessId"] = ppid
    if pimage is not None:
        ev["ParentImage"] = pimage
    if cmd is not None:
        ev["CommandLine"] = cmd
    if time is not None:
        ev["UtcTime"] = time
    if user is not None:
        ev["User"] = user
    return ev


def _by_image(nodes, name):
    for n in nodes:
        if n["image"] == name:
            return n
    raise AssertionError(f"{name} not found in {[n['image'] for n in nodes]}")


def test_guid_linking_builds_chain():
    events = [
        _sysmon("{G-CMD}", "2828", r"C:\Windows\System32\cmd.exe", pguid="{G-WMI}", ppid="836", pimage=r"C:\Windows\System32\wbem\WmiPrvSE.exe", time="2024-01-01 10:00:01"),
        _sysmon("{G-WHO}", "3328", r"C:\Windows\System32\whoami.exe", pguid="{G-CMD}", ppid="2828", time="2024-01-01 10:00:02"),
    ]
    forest = build_process_forest(events)
    assert forest["stats"] == {"processes": 3, "hits": 2, "inferred": 1, "roots": 1, "truncated": False, "depth_capped": False, "max_nodes": DEFAULT_MAX_NODES}

    root = forest["roots"][0]
    assert root["image"] == "wmiprvse.exe"
    assert root["hit"] is False  # synthesized ancestor
    cmd = root["children"][0]
    assert cmd["image"] == "cmd.exe" and cmd["hit"] is True
    who = cmd["children"][0]
    assert who["image"] == "whoami.exe" and who["hit"] is True


def test_pid_fallback_links_4688_without_guid():
    events = [
        {"EventID": 4688, "NewProcessId": "0x64", "NewProcessName": r"C:\Windows\explorer.exe", "ProcessId": "0x4", "Computer": "H", "UtcTime": "2024-01-01 09:00:00"},
        {"EventID": 4688, "NewProcessId": "0xc8", "NewProcessName": r"C:\Windows\System32\cmd.exe", "ProcessId": "0x64", "Computer": "H", "UtcTime": "2024-01-01 09:00:05"},
    ]
    forest = build_process_forest(events)
    # explorer's parent (PID 0x4) has no ParentImage, so no nameless ancestor is made:
    # explorer is a clean root and cmd links to it by PID.
    explorer = _by_image(forest["roots"], "explorer.exe")
    assert explorer["children"][0]["image"] == "cmd.exe"


def test_pid_recycle_picks_closest_earlier_parent():
    # Two processes reuse PID 100; the child must attach to the one created just before it.
    events = [
        _sysmon(None, "100", r"C:\a\old.exe", time="2024-01-01 08:00:00"),
        _sysmon(None, "100", r"C:\a\new.exe", time="2024-01-01 10:00:00"),
        _sysmon(None, "200", r"C:\a\child.exe", ppid="100", time="2024-01-01 10:00:30"),
    ]
    forest = build_process_forest(events)
    new = _by_image([n for r in forest["roots"] for n in [r]], "new.exe")
    assert any(c["image"] == "child.exe" for c in new["children"])
    old = _by_image(forest["roots"], "old.exe")
    assert all(c["image"] != "child.exe" for c in old["children"])


def test_virtual_ancestor_synthesized_from_parent_image():
    events = [_sysmon("{G1}", "10", r"C:\evil.exe", ppid="4", pimage=r"C:\Windows\System32\services.exe", time="t1")]
    forest = build_process_forest(events)
    assert forest["stats"]["inferred"] == 1
    root = forest["roots"][0]
    assert root["image"] == "services.exe" and root["hit"] is False
    assert root["children"][0]["image"] == "evil.exe"


def test_dedup_same_guid_from_two_tools():
    e = _sysmon("{G-DUP}", "500", r"C:\d.exe", time="t1")
    forest = build_process_forest([e, dict(e)])
    assert forest["stats"]["hits"] == 1


def test_siblings_sorted_chronologically():
    events = [
        _sysmon("{P}", "1", r"C:\p.exe", time="2024-01-01 10:00:00"),
        _sysmon("{B}", "3", r"C:\b.exe", pguid="{P}", time="2024-01-01 10:00:30"),
        _sysmon("{A}", "2", r"C:\a.exe", pguid="{P}", time="2024-01-01 10:00:10"),
    ]
    forest = build_process_forest(events)
    parent = forest["roots"][0]
    assert [c["image"] for c in parent["children"]] == ["a.exe", "b.exe"]


def test_max_nodes_truncates():
    events = [_sysmon(f"{{G{i}}}", str(i), rf"C:\p{i}.exe", time=f"t{i:03d}") for i in range(10)]
    forest = build_process_forest(events, max_nodes=4)
    assert forest["stats"]["hits"] == 4
    assert forest["stats"]["truncated"] is True


def test_non_process_events_ignored():
    events = [
        {"EventID": 3, "Image": r"C:\x.exe", "SourceIp": "1.2.3.4", "DestinationIp": "5.6.7.8", "Computer": "H"},
        _sysmon("{G}", "9", r"C:\real.exe", time="t1"),
    ]
    forest = build_process_forest(events)
    assert forest["stats"]["hits"] == 1
    assert forest["roots"][0]["image"] == "real.exe"


def test_nested_evtx_shape_flattened():
    # Zircolite/Chainsaw nested shape: fields under Event.EventData / Event.System.
    event = {
        "Event": {
            "System": {"EventID": 1, "Computer": "HOST"},
            "EventData": {
                "ProcessGuid": "{N}",
                "ProcessId": "42",
                "Image": r"C:\Windows\System32\powershell.exe",
                "ParentImage": r"C:\Windows\explorer.exe",
                "ParentProcessId": "9",
                "UtcTime": "2024-01-01 11:00:00",
            },
        }
    }
    forest = build_process_forest([event])
    root = forest["roots"][0]
    assert root["image"] == "explorer.exe"
    assert root["children"][0]["image"] == "powershell.exe"


def test_process_event_without_image_dropped():
    # A process-creation event with no Image (e.g. sparse Hayabusa) is noise — dropped.
    events = [
        {"EventID": 1, "ProcessGuid": "{G-NOIMG}", "ProcessId": "1", "Computer": "H", "UtcTime": "t1"},
        _sysmon("{G-REAL}", "2", r"C:\real.exe", time="t2"),
    ]
    forest = build_process_forest(events)
    assert forest["stats"]["hits"] == 1
    assert forest["roots"][0]["image"] == "real.exe"


def test_no_inferred_ancestor_without_parent_image():
    # Parent known only by PID (no ParentImage) must NOT create a nameless ancestor.
    events = [_sysmon("{G}", "10", r"C:\evil.exe", ppid="4", time="t1")]
    forest = build_process_forest(events)
    assert forest["stats"]["inferred"] == 0
    assert forest["roots"][0]["image"] == "evil.exe"


def test_empty_input():
    forest = build_process_forest([])
    assert forest["roots"] == []
    assert forest["stats"]["processes"] == 0


# ── auditd lineage (no GUIDs — pid/ppid + time fallback) ───────────────────


def test_auditd_pid_chain_links_child():
    parent = {"exe": "/bin/bash", "pid": "100", "ppid": "1", "Timestamp": "2024-01-05T12:00:00Z"}
    child = {"exe": "/usr/bin/curl", "pid": "200", "ppid": "100", "Timestamp": "2024-01-05T12:00:05Z"}
    forest = build_process_forest([parent, child])
    assert forest["stats"]["hits"] == 2
    assert len(forest["roots"]) == 1
    root = forest["roots"][0]
    assert root["image"] == "bash"
    assert [c["image"] for c in root["children"]] == ["curl"]


def test_auditd_epoch_fallback_time_ordering():
    parent = {"exe": "/bin/sh", "pid": "10", "msg": "audit(1700000000.100:1):"}
    child = {"exe": "/usr/bin/wget", "pid": "20", "ppid": "10", "msg": "audit(1700000050.200:2):"}
    forest = build_process_forest([parent, child])
    assert len(forest["roots"]) == 1
    assert forest["roots"][0]["image"] == "sh"
    assert forest["roots"][0]["children"][0]["image"] == "wget"


def test_auditd_unmatched_parent_child_stays_root():
    """No parent image in auditd events — no synthetic ancestor, child is a root."""
    child = {"exe": "/usr/bin/curl", "pid": "200", "ppid": "999", "Timestamp": "2024-01-05T12:00:05Z"}
    forest = build_process_forest([child])
    assert forest["stats"]["inferred"] == 0
    assert len(forest["roots"]) == 1
    assert forest["roots"][0]["image"] == "curl"


def test_auditd_fields_populate_node():
    ev = {
        "exe": "/usr/bin/curl",
        "comm": "curl",
        "pid": "1234",
        "ppid": "1",
        "acct": "root",
        "proctitle": "curl http://evil.example",
        "hostname": "web01",
        "Timestamp": "2024-01-05T12:00:00Z",
    }
    forest = build_process_forest([ev])
    node = forest["roots"][0]
    assert node["image"] == "curl"
    assert node["image_full"] == "/usr/bin/curl"
    assert node["cmdline"] == "curl http://evil.example"
    assert node["user"] == "root"
    assert node["computer"] == "web01"
    assert node["hit"] is True


def test_auditd_requires_pid_and_exe():
    assert build_process_forest([{"exe": "/bin/sh"}])["stats"]["hits"] == 0
    assert build_process_forest([{"pid": "5"}])["stats"]["hits"] == 0


def test_mixed_windows_and_auditd_events():
    win = {
        "Event": {
            "System": {"EventID": 1, "Computer": "WS01"},
            "EventData": {
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "ProcessGuid": "{A}",
                "ProcessId": "4242",
                "UtcTime": "2024-01-05 12:00:00.000",
            },
        }
    }
    lin = {"exe": "/bin/bash", "pid": "100", "Timestamp": "2024-01-05T12:00:00Z"}
    forest = build_process_forest([win, lin])
    assert forest["stats"]["hits"] == 2
    images = {r["image"] for r in forest["roots"]}
    assert images == {"cmd.exe", "bash"}


def _hayabusa_eid1(pguid, pid, proc, *, parent_pguid=None, parent_pid=None, parent_image=None, cmd=None, time=None, computer="HOST1"):
    """A Hayabusa NDJSON EID 1 event: abbreviated Details + ExtraFieldInfo."""
    details = {"Proc": proc, "PGUID": pguid, "PID": pid}
    if parent_pguid is not None:
        details["ParentPGUID"] = parent_pguid
    if parent_pid is not None:
        details["ParentPID"] = parent_pid
    if cmd is not None:
        details["Cmdline"] = cmd
    extra = {}
    if parent_image is not None:
        extra["ParentImage"] = parent_image
    if time is not None:
        extra["UtcTime"] = time
    return {"EventID": 1, "Computer": computer, "Channel": "Sysmon", "Details": details, "ExtraFieldInfo": extra}


def test_hayabusa_abbreviated_fields_build_chain():
    """Hayabusa's standard profiles abbreviate Sysmon fields (PGUID/PID/Proc/…) and
    stash ParentImage/UtcTime in ExtraFieldInfo — the tree must still build.

    A job where only Hayabusa completed must not produce an empty forest."""
    events = [
        _hayabusa_eid1(
            "{G-CMD}",
            "2828",
            r"C:\Windows\System32\cmd.exe",
            parent_pguid="{G-EXP}",
            parent_pid="836",
            parent_image=r"C:\Windows\explorer.exe",
            cmd="cmd /c whoami",
            time="2024-01-01 10:00:01",
        ),
        _hayabusa_eid1(
            "{G-WHO}",
            "3328",
            r"C:\Windows\System32\whoami.exe",
            parent_pguid="{G-CMD}",
            parent_pid="2828",
            time="2024-01-01 10:00:02",
        ),
    ]
    forest = build_process_forest(events)
    assert forest["stats"] == {"processes": 3, "hits": 2, "inferred": 1, "roots": 1, "truncated": False, "depth_capped": False, "max_nodes": DEFAULT_MAX_NODES}
    root = forest["roots"][0]
    assert root["image"] == "explorer.exe" and root["hit"] is False
    cmd = root["children"][0]
    assert cmd["image"] == "cmd.exe" and cmd["cmdline"] == "cmd /c whoami" and cmd["pid"] == "2828"
    who = cmd["children"][0]
    assert who["image"] == "whoami.exe" and who["time"] == "2024-01-01 10:00:02"


# ── depth clamping ──────────────────────────────────────────────────────────────
#
# Node count and depth are independent axes, and a node cap does not bound depth.
# Every consumer of the forest recurses per level — `prune_to_entity`'s `visit`/`count`
# and the `node()` macro in `partials/_process_tree.html` — so a near-linear chain blows
# the Python stack long before it hits `max_nodes`. Measured ceilings on CPython 3.14 at
# the default limit of 1000: render 247, prune 495, build 996 — reachable, not theoretical.


def _chain(depth, *, computer="HOST1"):
    """A pathological single chain: each process is the child of the one before it."""
    return [
        _sysmon(
            f"{{G{i}}}",
            str(1000 + i),
            rf"C:\p{i}.exe",
            pguid=f"{{G{i - 1}}}" if i else None,
            ppid=str(999 + i),
            time=f"2026-08-14 00:00:{i % 60:02d}.{i:04d}",
            computer=computer,
        )
        for i in range(depth)
    ]


def _depth_of(forest):
    """Deepest chain in the forest, walked iteratively so the test can't blow up itself."""
    deepest = 0
    stack = [(r, 1) for r in forest["roots"]]
    while stack:
        node, d = stack.pop()
        deepest = max(deepest, d)
        stack.extend((c, d + 1) for c in node["children"])
    return deepest


def test_deep_chain_is_clamped_to_max_depth():
    forest = build_process_forest(_chain(600), max_nodes=600)
    assert _depth_of(forest) <= MAX_DEPTH
    assert forest["stats"]["depth_capped"] is True
    # Severing re-roots the remainder; no process is lost.
    assert forest["stats"]["hits"] == 600
    assert forest["stats"]["processes"] == 600


def test_shallow_tree_is_not_marked_depth_capped():
    forest = build_process_forest(_chain(10), max_nodes=10)
    assert _depth_of(forest) == 10
    assert forest["stats"]["depth_capped"] is False
    assert len(forest["roots"]) == 1


def test_clamped_forest_survives_prune_and_render():
    """The whole point of clamping: the downstream recursive consumers must not blow up."""
    from app.intel.lineage import prune_to_entity
    from app.templates_config import templates

    forest = build_process_forest(_chain(600), max_nodes=600)
    pruned = prune_to_entity(forest, "executable", "p5.exe")
    assert pruned["stats"]["matched"] == 1
    html = templates.get_template("partials/_process_tree.html").render(forest=forest, max_nodes=600, request=None)
    assert "p599.exe" in html


# ── parent-resolution index equivalence ────────────────────────────────────────
#
# A linear scan of every candidate for every child is O(n^2), and `_find_pid_parent` is
# the path *every* auditd job takes (auditd events carry no ProcessGuid at all). The index
# must be a pure speedup: this pins byte-identical output against a verbatim copy of the
# linear-scan implementation over randomised inputs.


def _reference_find_pid_parent(child, candidates):
    """The pre-index implementation, kept verbatim as a differential oracle."""
    ppid = child["_parent_pid"]
    if not ppid:
        return None
    pool = [c for c in candidates if c is not child and c["pid"] == ppid and c["computer"] == child["computer"]]
    if not pool:
        return None
    ctime = child["time"]
    if ctime:
        earlier = [c for c in pool if c["time"] and c["time"] <= ctime]
        if earlier:
            return max(earlier, key=lambda c: c["time"])
    return pool[0] if len(pool) == 1 else None


def test_pid_index_matches_reference_on_randomised_events():
    import json
    import random

    from app.intel import lineage

    for seed in range(60):
        rnd = random.Random(seed)
        events = []
        for i in range(rnd.randint(1, 80)):
            # Deliberately collide PIDs, drop timestamps, mix hosts and self-parent:
            # every branch the reference implementation distinguishes must be reachable.
            pid = str(rnd.choice([100, 101, 102, 1000 + i]))
            events.append(
                _sysmon(
                    f"{{G{i}}}" if rnd.random() < 0.4 else None,
                    pid,
                    rf"C:\p{i}.exe",
                    pguid=f"{{G{rnd.randint(0, max(0, i - 1))}}}" if rnd.random() < 0.3 else None,
                    ppid=str(rnd.choice([100, 101, 102, pid])),
                    pimage=rf"C:\parent{i % 3}.exe" if rnd.random() < 0.5 else None,
                    time=f"2026-08-14 00:00:{rnd.randint(0, 59):02d}" if rnd.random() < 0.8 else None,
                    computer=rnd.choice(["HOST1", "HOST2", None]),
                )
            )

        # Swap at the *index-builder* seam so the oracle receives the candidate list in
        # its original order. Flattening the index instead would regroup nodes by
        # (computer, pid) and silently destroy the ordering that `max()`'s first-wins
        # tie-break and the single-candidate `pool[0]` fallback both depend on — the
        # oracle would then agree with the new code for the wrong reason.
        real_index, real_find = lineage._index_by_pid, lineage._find_pid_parent
        try:
            lineage._index_by_pid = lambda concrete: concrete
            lineage._find_pid_parent = _reference_find_pid_parent
            expected = build_process_forest(list(events))
        finally:
            lineage._index_by_pid, lineage._find_pid_parent = real_index, real_find
        actual = build_process_forest(list(events))
        assert json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True), f"seed={seed}"


def test_truncation_banner_quotes_the_real_cap():
    """A banner reading `{{ max_nodes or 500 }}` falls through to the literal whenever no
    render site passes `max_nodes`, so raising the cap would leave the page quoting a stale
    number. The cap must come from the forest, not the template."""
    from app.intel.lineage import prune_to_entity
    from app.templates_config import templates

    tpl = templates.get_template("partials/_process_tree.html")
    events = [_sysmon(f"{{G{i}}}", str(i), rf"C:\p{i}.exe", time=f"t{i:03d}") for i in range(30)]
    forest = build_process_forest(events, max_nodes=7)
    assert forest["stats"]["max_nodes"] == 7

    # The "capped at N" sentence only renders on a pruned view, which is also the path that
    # copies stats forward — so it pins both the value and the copy.
    pruned = prune_to_entity(forest, "executable", "p3.exe")
    assert pruned["stats"]["max_nodes"] == 7
    html = tpl.render(forest=pruned, request=None)
    assert "capped at 7 processes" in html
    assert "500 processes" not in html


def test_default_cap_is_reported_when_caller_passes_nothing():
    events = [_sysmon(f"{{G{i}}}", str(i), rf"C:\p{i}.exe", time=f"t{i:03d}") for i in range(3)]
    assert build_process_forest(events)["stats"]["max_nodes"] == DEFAULT_MAX_NODES
