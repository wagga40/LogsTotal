"""Process lineage — reconstruct parent→child process trees from matched events.

Pure Python (no FastAPI / Huey imports, same discipline as ``app/similarity/`` and
``app/intel/relationships.py``). Given the events that matched a SIGMA rule for a job
(read on-demand from the per-job tool output files), this rebuilds the process-creation
lineage so an analyst can follow a kill chain over time — the "lineage-first triage" idea
from sigmalineage.

Only **process-creation** events are used: Sysmon Event ID 1 and Security Event ID 4688.
Each such event already carries both the child and its parent's identity, so ancestry can
be reconstructed from the matched events alone:

- Primary linking is by GUID (``ParentProcessGuid`` -> ``ProcessGuid``), high fidelity.
- Fallback linking is by parent PID + computer, choosing the candidate parent with the
  closest non-negative creation-time delta (PID-recycle safe).
- A parent that never appears as its own matched event becomes a synthetic, ``hit=False``
  "[Unknown Ancestor]" node so the chain surfaces instead of being dropped.

The result is a JSON-serializable forest (``roots`` of nested nodes) plus summary ``stats``.
The tree is HIT-anchored: every concrete node came from a rule-matched event; it is not the
full host process tree.
"""

from __future__ import annotations

import os
import re

from app.constants import RE_IPV4
from app.intel.relationships import _HOST_NOISE, _HOSTNAME_KEYS, _event_id, _extract_hashes, _first, _flatten

# Windows process-creation event IDs we build lineage from.
PROCESS_CREATE_EIDS: frozenset[int] = frozenset({1, 4688})

# Entity types that can anchor a process tree.
#
# The tree's nodes carry an image, a command line, a user, a computer and a set of image
# hashes — nothing else. An `ip_address` or a `domain` would only ever match incidentally,
# inside a command line, so those get no Processes tab at all rather than a tab that
# permanently reads "not applicable". `service` and `task` are the same story.
PROCESS_TREE_ENTITY_TYPES: frozenset[str] = frozenset({"computer", "executable", "cmdline_file", "user", "hash"})

# Auditd msg-id timestamp: "audit(<epoch>.<frac>:<serial>)".
_RE_AUDIT_EPOCH = re.compile(r"audit\((\d+)\.(\d+):\d+\)")

# Hard cap on concrete nodes to keep the tree (and the page) bounded.
DEFAULT_MAX_NODES = 2000

# Hard cap on chain *depth*, which is a different axis from node count. Every consumer of
# the forest recurses once per level — `prune_to_entity`'s `visit`/`count`, and the `node()`
# macro in `partials/_process_tree.html` — so a near-linear chain would blow the Python
# stack well before it reached `max_nodes`. Measured ceilings on CPython 3.14 at the
# default recursion limit of 1000: **render 247, prune 495, build 996**.
#
# Clamping here, once, is what lets all three downstream stages keep their natural
# recursive shape: nothing they receive can exceed this. 100 leaves a 2.4x margin under
# the render ceiling while sitting far above any real lineage — genuine process chains run
# to a few dozen levels, not hundreds.
MAX_DEPTH = 100

_UNKNOWN_LABEL = "[Unknown Ancestor]"


def _clean(val: object) -> str | None:
    """Stripped non-empty string, else None (``-`` treated as empty)."""
    if not isinstance(val, str):
        if isinstance(val, int):
            return str(val)
        return None
    v = val.strip()
    if not v or v == "-":
        return None
    return v


def _basename(path: str | None) -> str | None:
    """Lowercased basename of a Windows/Unix path; passthrough for bare names."""
    if not path:
        return None
    name = os.path.basename(path.replace("\\", "/")).strip().lower()
    return name or None


def _clean_host(val: object) -> str | None:
    """`_clean`, plus the placeholder hostnames that are not hosts.

    Zircolite run offline stamps ``offline`` into the Computer field, and the entity
    extractor already drops that (`relationships._HOST_NOISE`). Without the same drop here, a
    job parsed offline would give every node ``computer="offline"`` — which no real host
    entity can ever match, and which silently poisons the PID-fallback parent lookup by making
    every process on every host look like it shares one machine.
    """
    v = _clean(val)
    if v is None or v.lower() in _HOST_NOISE:
        return None
    return v


def _make_node(*, hit: bool) -> dict:
    return {
        "guid": None,
        "pid": None,
        "image": None,
        "image_full": None,
        # Other basenames this same process is known by. `image` is what it was launched
        # as; `OriginalFileName` is what the vendor compiled it as, and for a renamed
        # binary the two differ — `Image=C:\temp\svchost.exe` with
        # `OriginalFileName=mimikatz.exe`. The analytics extractor reads fifteen image-ish
        # keys and makes an entity out of every one, so the entity is `mimikatz.exe` while
        # the node was only ever `svchost.exe`: a permanent anchoring miss on precisely the
        # case a process tree is opened for. Kept as alternates rather than replacing
        # `image`, because the display name should stay what actually ran.
        "image_alts": [],
        "cmdline": None,
        "user": None,
        "time": None,
        "computer": None,
        # Uppercase hex, from Sysmon EID 1's `Hashes` composite. Present so a `hash`
        # entity has something to match — there is no other node field it could use, and
        # re-scanning the raw events downstream would duplicate this whole parse. Usually
        # empty (4688 and auditd carry no hashes).
        "hashes": [],
        "hit": hit,
        "children": [],
    }


# Fields naming the *same* process under another name. Deliberately short: every key here
# must describe the process the event is about, not one it merely touched. `ParentImage`
# names a different process (which gets its own node, real or synthesised), and
# `ImageLoaded`/`TargetImage`/`SourceImage` name a DLL or a victim — including any of them
# would make a tree claim a process was something it was not.
_IMAGE_ALT_KEYS = ("OriginalFileName", "OriginalFilename")


def _image_alts(fields: dict, image: str) -> list[str]:
    """Lowercased basenames this process also answers to, excluding `image` itself."""
    alts: list[str] = []
    for key in _IMAGE_ALT_KEYS:
        name = _basename(_clean(fields.get(key)))
        if name and name != image and name not in alts:
            alts.append(name)
    return alts


def _audit_epoch_time(fields: dict) -> str | None:
    """Timestamp from an ``audit(<epoch>.<frac>:<id>)`` marker in any string field.

    Zero-padded to a fixed width so lexical comparison (used by parent linking and
    sibling sort) stays chronological. A job mixes at most one time format, so
    padded epochs never compete with ISO strings within the same tree.
    """
    for val in fields.values():
        if isinstance(val, str):
            m = _RE_AUDIT_EPOCH.search(val)
            if m:
                return f"{m.group(1).zfill(13)}.{m.group(2)}"
    return None


def _parse_auditd_event(fields: dict) -> dict | None:
    """Project a flat auditd record (no EventID) to a process node, or None.

    Auditd events carry no GUID and no *parent* image name, so linking relies
    entirely on the pid/ppid + nearest-earlier-time fallback, and a child whose
    parent never matched a rule stays a root (no "[Unknown Ancestor]" synth).
    """
    image_full = _clean(_first(fields, "exe", "comm"))
    pid = _clean(fields.get("pid"))
    if not image_full or not pid:
        return None
    image = _basename(image_full)
    if not image:
        return None
    node = _make_node(hit=True)
    node["image_full"] = image_full
    node["image"] = image
    node["pid"] = pid
    node["cmdline"] = _clean(_first(fields, "proctitle", "cmd"))
    node["user"] = _clean(_first(fields, "acct", "auid", "uid"))
    node["time"] = _clean(_first(fields, "UtcTime", "SystemTime", "Timestamp", "timestamp")) or _audit_epoch_time(fields)
    node["computer"] = _clean_host(_first(fields, *_HOSTNAME_KEYS))
    node["_parent_guid"] = None
    node["_parent_pid"] = _clean(fields.get("ppid"))
    node["_parent_image_full"] = None
    return node


def _parse_event(event: dict) -> dict | None:
    """Project a raw event to a concrete process node, or None if not a process create."""
    if not isinstance(event, dict):
        return None
    fields = _flatten(event)
    # Hayabusa keeps the non-Details EVTX fields (ParentImage, UtcTime, …) in
    # ExtraFieldInfo, which the shared _flatten deliberately ignores (it mirrors
    # the analytics scan). Merge it here without overwriting flattened keys.
    extra = event.get("ExtraFieldInfo")
    if isinstance(extra, dict):
        for k, v in extra.items():
            fields.setdefault(k, v)
    if not fields:
        return None
    eid = _event_id(fields)
    if eid is None:
        return _parse_auditd_event(fields)
    if eid not in PROCESS_CREATE_EIDS:
        return None

    # Field-name fallbacks cover Hayabusa's standard-profile abbreviations
    # (Proc/PGUID/PID/ParentPGUID/ParentPID/Cmdline), whose semantics are
    # normalized: PID is always the *created* process, for 4688 too.
    image_full = _clean(_first(fields, "Image", "NewProcessName", "ProcessName", "Proc"))
    image = _basename(image_full)
    if not image:
        # No identifiable process (e.g. a sparse Hayabusa profile that omits Image) —
        # an un-named node is noise in a lineage tree, so drop it.
        return None
    node = _make_node(hit=True)
    node["guid"] = _clean(_first(fields, "ProcessGuid", "PGUID"))
    node["image_full"] = image_full
    node["image"] = image
    node["image_alts"] = _image_alts(fields, image)
    node["cmdline"] = _clean(_first(fields, "CommandLine", "Cmdline"))
    node["user"] = _clean(_first(fields, "User", "SubjectUserName", "TargetUserName"))
    node["time"] = _clean(_first(fields, "UtcTime", "SystemTime", "Timestamp"))
    node["computer"] = _clean_host(_first(fields, *_HOSTNAME_KEYS))
    # `_extract_hashes` already handles the Sysmon `MD5=…,SHA256=…` composite and the bare
    # single-hash form, and normalises to uppercase hex — reused rather than re-implemented
    # so a `hash` entity compares against exactly what the entity extractor stored.
    node["hashes"] = _extract_hashes(_first(fields, "Hashes", "Hash", "MD5", "SHA256", "SHA1", "IMPHASH"))

    # PID + parent identity differ by source. Sysmon (EID 1): own=ProcessId,
    # parent=ParentProcessId. Security 4688: own=NewProcessId, parent=ProcessId.
    node["_parent_guid"] = _clean(_first(fields, "ParentProcessGuid", "ParentPGUID"))
    if eid == 4688:
        node["pid"] = _clean(_first(fields, "NewProcessId", "PID"))
        node["_parent_pid"] = _clean(_first(fields, "ProcessId", "ParentPID"))
    else:
        node["pid"] = _clean(_first(fields, "ProcessId", "PID"))
        node["_parent_pid"] = _clean(_first(fields, "ParentProcessId", "ParentPID"))
    node["_parent_image_full"] = _clean(_first(fields, "ParentImage", "ParentProcessName"))
    return node


def _dedup_key(node: dict) -> tuple:
    if node["guid"]:
        return ("guid", node["guid"])
    return ("ident", node["computer"], node["pid"], node["image"], node["time"])


def _index_by_pid(concrete: list[dict]) -> dict[tuple, list[dict]]:
    """Group candidates by ``(computer, pid)`` — the only key `_find_pid_parent` selects on.

    Built in `concrete` order, and each bucket keeps that order, because the lookup's
    tie-breaking is order-sensitive in two places: `max()` returns the *first* maximal
    element, and the no-timestamp fallback takes `pool[0]`. A dict preserves insertion
    order, so the bucket is exactly the subsequence a full scan would produce.
    """
    index: dict[tuple, list[dict]] = {}
    for node in concrete:
        index.setdefault((node["computer"], node["pid"]), []).append(node)
    return index


def _find_pid_parent(child: dict, index: dict[tuple, list[dict]]) -> dict | None:
    """Pick the parent with the closest non-negative creation-time delta (PID-recycle safe).

    Takes the prebuilt `(computer, pid)` index rather than the candidate list: scanning every
    candidate for every child is O(n^2), and this is the path *every* auditd job takes,
    since auditd events carry no ProcessGuid for the GUID fast path to use.
    """
    ppid = child["_parent_pid"]
    if not ppid:
        return None
    # `computer` and `pid` may both be None; tuple equality treats that as plain equality
    # would.
    pool = [c for c in index.get((child["computer"], ppid), ()) if c is not child]
    if not pool:
        return None
    ctime = child["time"]
    if ctime:
        earlier = [c for c in pool if c["time"] and c["time"] <= ctime]
        if earlier:
            return max(earlier, key=lambda c: c["time"])
    # No usable timestamps — fall back to a single unambiguous candidate only.
    return pool[0] if len(pool) == 1 else None


def _inferred_key(node: dict) -> tuple | None:
    """Stable key for a synthetic ancestor, or None when the parent can't be named.

    A parent image is required — a PID-only ancestor would render as a nameless
    "[Unknown Ancestor]" node, which is noise, so we leave the child as a root instead.
    """
    pimg = _basename(node["_parent_image_full"])
    if not pimg:
        return None
    if node["_parent_guid"]:
        return ("guid", node["_parent_guid"])
    return ("ident", node["computer"], node["_parent_pid"], pimg)


def _clamp_depth(roots: list[dict], max_depth: int) -> tuple[list[dict], int]:
    """Sever chains deeper than *max_depth*, re-rooting the remainder.

    Returns ``(roots, severed_count)``. Nothing is dropped — a severed child becomes a root
    of its own chain — so every count in `stats` stays truthful; only the parent link is
    cut. The walk is iterative on purpose: it is the one traversal that runs *before* the
    depth bound exists, so it is the one that cannot afford to recurse.
    """
    out_roots = list(roots)
    severed = 0
    stack = [(r, 1) for r in roots]
    while stack:
        node, depth = stack.pop()
        kids = node["children"]
        if not kids:
            continue
        if depth >= max_depth:
            node["children"] = []
            for kid in kids:
                kid["_parent"] = None
                out_roots.append(kid)
                stack.append((kid, 1))
                severed += 1
        else:
            for kid in kids:
                stack.append((kid, depth + 1))
    return out_roots, severed


def _sort_key(node: dict):
    # None times sort last; otherwise lexical order matches chronological for ISO/Sysmon times.
    return (node["time"] is None, node["time"] or "")


def build_process_forest(events: list[dict], *, max_nodes: int = DEFAULT_MAX_NODES) -> dict:
    """Build a process-lineage forest from matched events.

    Returns ``{"roots": [...nested nodes...], "stats": {...}}`` where each node is a JSON dict
    with ``guid/pid/image/image_full/image_alts/cmdline/user/time/computer/hashes/hit/children``
    and ``hit`` is True for concrete matched processes, False for synthesized ancestors.
    """
    # 1. Parse + dedup concrete process-creation events.
    concrete: list[dict] = []
    seen: set[tuple] = set()
    truncated = False
    for ev in events or []:
        node = _parse_event(ev)
        if node is None:
            continue
        key = _dedup_key(node)
        if key in seen:
            continue
        seen.add(key)
        concrete.append(node)
        if len(concrete) >= max_nodes:
            truncated = True
            break

    guid_index = {n["guid"]: n for n in concrete if n["guid"]}
    pid_index = _index_by_pid(concrete)

    # 2. Resolve each concrete node's parent (concrete preferred, else synthesize).
    inferred: dict[tuple, dict] = {}
    for child in concrete:
        parent: dict | None = None
        pguid = child["_parent_guid"]
        if pguid and pguid != child["guid"]:
            parent = guid_index.get(pguid)
        if parent is None:
            parent = _find_pid_parent(child, pid_index)
        if parent is None:
            ikey = _inferred_key(child)
            if ikey is not None:
                parent = inferred.get(ikey)
                if parent is None:
                    parent = _make_node(hit=False)
                    parent["pid"] = child["_parent_pid"]
                    parent["image_full"] = child["_parent_image_full"]
                    parent["image"] = _basename(child["_parent_image_full"]) or _UNKNOWN_LABEL
                    parent["guid"] = child["_parent_guid"]
                    parent["computer"] = child["computer"]
                    inferred[ikey] = parent
        child["_parent"] = parent

    # 3. Break any accidental cycles (PID reuse can otherwise loop), then wire children.
    nodes = concrete + list(inferred.values())
    for child in concrete:
        parent = child.get("_parent")
        # Walk the ancestor chain; if we reach the child itself, sever the link.
        seen_chain: set[int] = {id(child)}
        cur = parent
        while cur is not None:
            if id(cur) in seen_chain:
                child["_parent"] = None
                parent = None
                break
            seen_chain.add(id(cur))
            cur = cur.get("_parent")
        if parent is not None:
            parent["children"].append(child)

    roots = [n for n in nodes if not n.get("_parent")]

    # 3b. Bound the depth before anything recursive touches the tree. Everything below
    # this line — `_finalize` here, `prune_to_entity`, and the template's `node()` macro —
    # recurses per level and is safe only because of this clamp.
    roots, severed = _clamp_depth(roots, max_depth=MAX_DEPTH)

    # 4. Sort siblings + roots chronologically and strip internal keys.
    def _finalize(node: dict) -> dict:
        node["children"].sort(key=_sort_key)
        for c in node["children"]:
            _finalize(c)
        for k in ("_parent", "_parent_guid", "_parent_pid", "_parent_image_full"):
            node.pop(k, None)
        return node

    roots.sort(key=_sort_key)
    for r in roots:
        _finalize(r)

    return {
        "roots": roots,
        "stats": {
            "processes": len(nodes),
            "hits": len(concrete),
            "inferred": len(inferred),
            "roots": len(roots),
            "truncated": truncated,
            "depth_capped": severed > 0,
            # Carried in `stats` rather than passed to the template: a self-describing
            # forest cannot drift from the value that was actually applied, the way a
            # template default would. `prune_to_entity` copies stats forward, so a pruned view
            # still reports the cap its *source* build used.
            "max_nodes": max_nodes,
        },
    }


# ── Entity anchoring ────────────────────────────────────────────────────────────
#
# A process tree filtered to an entity answers "how did this actually run", which is the
# question the tree is for. Doing it here, on the built forest, rather than as the client
# filter that already exists, is not redundancy: `build_process_forest` truncates at
# `DEFAULT_MAX_NODES` **during the parse, before relevance is known**, so on a busy job the
# entity's processes may simply not be among the first `DEFAULT_MAX_NODES` the client ever
# sees. Raising that cap to compensate would trade a bounded page for an unbounded one.
#
# The per-type predicate mirrors `app/intel/entities.py::_entity_appears_in_blob`, but
# matches structured node fields instead of a flat blob, which is strictly more precise.


def _strip_domain(user: str) -> str:
    """`CORP\\alice` -> `alice`. Node users are raw; the entity extractor normalised."""
    return user.rsplit("\\", 1)[-1]


def _strip_dns_suffix(host: str) -> str:
    """`WS01.corp.local` -> `WS01`. An IP address is returned unchanged.

    The `user` branch strips `DOMAIN\\` from both sides; `computer` needs the same, or an
    EVTX `Computer` of `WS01.corp.local` and an auditd `node=ws01` describing the same host
    never match — and they routinely appear in the same case.

    Guarded against IPv4, where every dot is significant: `10.0.0.5` must not become `10`.
    """
    if not host or RE_IPV4.fullmatch(host):
        return host
    return host.split(".", 1)[0] or host


def node_matches_entity(node: dict, entity_type: str, value: str) -> bool:
    """Does this lineage node *concern* the given entity?

    Exact where the two sides normalise identically, substring only where the field is
    genuinely free text:

    ``executable``     ``node["image"]`` **or ``node["image_alts"]``**, exact — every side
                       is `_basename`-lowercased by the same expression, so equality is
                       safe and a substring test would make ``ps.exe`` match
                       ``wsmprovhost.exe``. The alternates are what let a renamed binary
                       anchor: the entity may be its ``OriginalFileName``.
    ``computer``       ``node["computer"]``, case-insensitive and short-name-only, so an
                       EVTX ``WS01.corp.local`` and an auditd ``node=ws01`` agree. Both
                       sides read the same ``_HOSTNAME_KEYS`` tuple.
    ``user``           ``node["user"]``, case-insensitive, after stripping a ``DOMAIN\\``
                       prefix from the node side. (Machine accounts never reach here — the
                       analytics extractor drops ``$``-suffixed names, so no such entity
                       exists to anchor on.)
    ``cmdline_file``   substring of ``node["cmdline"]``, lowercased. These entities are
                       *derived* from the command line, so substring is the relationship.
    ``hash``           membership in ``node["hashes"]``, uppercase hex on both sides.
    """
    if not value:
        return False
    v = value.strip()
    if not v:
        return False

    if entity_type == "executable":
        base = _basename(v)
        if not base:
            return False
        # `.get(...) or []` rather than `["image_alts"]`: a forest cached before this field
        # existed is still served for the rest of its TTL after a deploy, and a KeyError
        # there is a 500 for every viewer.
        return node.get("image") == base or base in (node.get("image_alts") or [])
    if entity_type == "computer":
        return bool(node.get("computer")) and _strip_dns_suffix(node["computer"]).lower() == _strip_dns_suffix(v).lower()
    if entity_type == "user":
        return bool(node.get("user")) and _strip_domain(node["user"]).lower() == _strip_domain(v).lower()
    if entity_type == "cmdline_file":
        return bool(node.get("cmdline")) and v.lower() in node["cmdline"].lower()
    if entity_type == "hash":
        # `.get(...) or []` rather than `["hashes"]` — the same stale-cache defence as
        # `image_alts` above.
        return v.upper() in (node.get("hashes") or [])
    return False


def prune_to_entity(forest: dict, entity_type: str, value: str) -> dict:
    """Keep only the parts of *forest* that concern one entity.

    A node survives if it matches, if one of its descendants matches, or if it is a
    descendant of a match. Ancestors are the point of a process tree — dropping them would
    leave the matched process floating with no story — and the subtree below a match is the
    kill chain, which is the other half of the same story.

    Matching nodes are marked ``node["match"] = True`` so the template can highlight them,
    and ``stats`` gains ``matched`` plus an ``entity_pruned`` flag the template reads to
    open the tree expanded instead of collapsed.

    Returns a new forest; the input is not modified, so a cached unfiltered build can be
    pruned repeatedly for different entities.
    """

    def visit(node: dict, under_match: bool) -> dict | None:
        hit = node_matches_entity(node, entity_type, value)
        keep_all = under_match or hit
        kids = [k for k in (visit(c, keep_all) for c in node.get("children", ())) if k is not None]
        if not (hit or kids or under_match):
            return None
        out = {k: (list(v) if isinstance(v, list) and k != "children" else v) for k, v in node.items() if k != "children"}
        out["children"] = kids
        out["match"] = hit
        return out

    roots = [r for r in (visit(root, False) for root in forest.get("roots", ())) if r is not None]

    def count(nodes) -> tuple[int, int, int, int]:
        total = matched = hits = inferred = 0
        for n in nodes:
            total += 1
            matched += 1 if n.get("match") else 0
            hits += 1 if n.get("hit") else 0
            inferred += 0 if n.get("hit") else 1
            sub = count(n["children"])
            total, matched, hits, inferred = total + sub[0], matched + sub[1], hits + sub[2], inferred + sub[3]
        return total, matched, hits, inferred

    total, matched, hits, inferred = count(roots)
    # **Every** count is re-derived, not just the obvious ones. Carrying `hits` over from
    # the source forest would put "500 hits" in the header of a pruned tree showing eighty — and
    # mixing a recounted `processes` with a stale `hits` is worse than either alone.
    # `truncated` is *not* recounted: the source forest really was capped during the parse,
    # and the template explains what that means for a pruned view.
    stats = dict(forest.get("stats") or {})
    # ...with one exception, which is what lets the empty state tell the truth:
    # `source_processes` is what the job *had* before pruning. Without it "no processes"
    # covers both "this job produced no process-creation events at all" and "it produced
    # 812, none of which mention this entity" — two problems with two different answers.
    source_processes = int(stats.get("processes") or 0)
    stats.update(
        {
            "processes": total,
            "roots": len(roots),
            "hits": hits,
            "inferred": inferred,
            "matched": matched,
            "entity_pruned": True,
            "source_processes": source_processes,
        }
    )
    return {"roots": roots, "stats": stats}
