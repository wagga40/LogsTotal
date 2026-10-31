"""One parser per log type, all yielding `(flat, fixed)`.

`flat` is `{lower-cased path: scalar}` from `app.events.flatten`; `fixed` holds the store's
`_lt_*` columns: `time` (naive UTC datetime or None), `host`, `channel`, `eid`, `rid`, `seq`,
`line`. Windows formats are all brought to the shape pyevtx-rs renders an EVTX record in, so
the same event gets the same columns whether it arrived as EVTX, EVTX-XML, JSON or winlogbeat.

A malformed record is counted in `stats["errors"]` and skipped; it never stops the parse.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import orjson

from app.events.flatten import flatten
from app.events.timeparse import parse_time
from app.tools.event_keys import message_sha, norm_channel, norm_host, norm_int

Parsed = tuple[dict, dict]

#: Formats whose events are EVTX records, so their System block gives the fixed columns.
WINDOWS_TYPES = frozenset({"evtx", "json_evtx", "json_winlogbeat", "xml"})


def iter_events(path: Path, log_type: str, *, stats: dict, spellings: dict, reference: datetime | None = None, evtx_threads: int = 1) -> Iterator[Parsed]:
    stats.setdefault("errors", 0)
    parser = {
        "evtx": _evtx,
        "json_evtx": _json_evtx,
        "json_winlogbeat": _winlogbeat,
        "xml": _xml_file,
        "sysmon_linux": _sysmon_linux,
        "auditd": _auditd,
        "journald": _journald,
        "syslog": _syslog,
    }.get(log_type, _lines)
    if parser is _evtx:
        yield from _evtx(path, stats, spellings, evtx_threads)
    elif parser in (_syslog,):
        yield from _syslog(path, stats, spellings, reference)
    else:
        yield from parser(path, stats, spellings)


# ── Windows ─────────────────────────────────────────────────────────────────────


def _windows_fixed(flat: dict) -> dict:
    get = flat.get
    return {
        "time": parse_time(get(("system", "timecreated", "systemtime")) or get(("systemtime",)) or get(("timestamp",)) or get(("@timestamp",))),
        "host": norm_host(get(("system", "computer")) or get(("computer",))),
        "channel": norm_channel(get(("system", "channel")) or get(("channel",))),
        "eid": norm_int(get(("system", "eventid")) or get(("eventid",))),
        "rid": norm_int(get(("system", "eventrecordid")) or get(("eventrecordid",))),
        "seq": None,
        "line": None,
    }


def _windows(record: dict, spellings: dict) -> Parsed:
    if "Event" in record and isinstance(record["Event"], dict):
        flat = flatten(record["Event"], root=None, spellings=spellings)
    else:
        flat = flatten(record, root=None, spellings=spellings)
    return flat, _windows_fixed(flat)


def _evtx(path: Path, stats: dict, spellings: dict, threads: int) -> Iterator[Parsed]:
    from evtx import PyEvtxParser

    records = iter(PyEvtxParser(str(path), number_of_threads=max(1, threads)).records_json())
    while True:
        try:
            record = next(records)
        except StopIteration:
            return
        except Exception:
            # A corrupt record or chunk: pyevtx-rs reports it on the iterator. Count and go on.
            stats["errors"] += 1
            continue
        try:
            yield _windows(orjson.loads(record["data"]), spellings)
        except Exception:
            stats["errors"] += 1


def _json_records(path: Path, stats: dict) -> Iterator[dict]:
    """NDJSON lines, or a top-level JSON array (loaded whole; uploads are capped at 500 MB)."""
    with path.open("rb") as stream:
        head = stream.read(1024).lstrip(b"\xef\xbb\xbf \t\r\n")
    if head.startswith(b"["):
        try:
            data = orjson.loads(path.read_bytes().lstrip(b"\xef\xbb\xbf"))
        except orjson.JSONDecodeError:
            stats["errors"] += 1
            return
        for item in data if isinstance(data, list) else []:
            if isinstance(item, dict):
                yield item
            else:
                stats["errors"] += 1
        return
    with path.open("rb") as stream:
        for raw in stream:
            line = raw.strip().lstrip(b"\xef\xbb\xbf")
            if not line:
                continue
            try:
                item = orjson.loads(line)
            except orjson.JSONDecodeError:
                stats["errors"] += 1
                continue
            if isinstance(item, dict):
                yield item
            else:
                stats["errors"] += 1


def _json_evtx(path: Path, stats: dict, spellings: dict) -> Iterator[Parsed]:
    for record in _json_records(path, stats):
        yield _windows(record, spellings)


def _winlogbeat(path: Path, stats: dict, spellings: dict) -> Iterator[Parsed]:
    """`winlog.*` mapped onto the EVTX System/EventData names; everything else kept as is."""
    for record in _json_records(path, stats):
        w = record.get("winlog") if isinstance(record.get("winlog"), dict) else {}
        host = record.get("host") if isinstance(record.get("host"), dict) else {}
        process = w.get("process") if isinstance(w.get("process"), dict) else {}
        thread = process.get("thread") if isinstance(process.get("thread"), dict) else {}
        system = {
            "Provider": {"Name": w.get("provider_name"), "Guid": w.get("provider_guid")},
            "EventID": w.get("event_id"),
            "Version": w.get("version"),
            "Task": w.get("task"),
            "Opcode": w.get("opcode"),
            "Keywords": w.get("keywords"),
            "TimeCreated": {"SystemTime": record.get("@timestamp")},
            "EventRecordID": w.get("record_id"),
            "Execution": {"ProcessID": process.get("pid"), "ThreadID": thread.get("id")},
            "Channel": w.get("channel"),
            "Computer": w.get("computer_name") or host.get("name") or host.get("hostname"),
        }
        consumed = {
            "provider_name",
            "provider_guid",
            "event_id",
            "version",
            "task",
            "opcode",
            "keywords",
            "record_id",
            "process",
            "channel",
            "computer_name",
            "event_data",
            "user_data",
        }
        canonical = {"System": system, "EventData": w.get("event_data") or {}, "UserData": w.get("user_data") or {}}
        rest = {k: v for k, v in record.items() if k not in ("winlog", "@timestamp")}
        rest["winlog"] = {k: v for k, v in w.items() if k not in consumed}
        flat = flatten(canonical, root=None, spellings=spellings)
        flat.update({p: v for p, v in flatten(rest, root=None, spellings=spellings).items() if p not in flat})
        yield flat, _windows_fixed(flat)


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_node(element: ET.Element) -> object:
    """An element as pyevtx-rs would render it: attributes, `#text`, children."""
    out: dict = {}
    if element.attrib:
        out["#attributes"] = {_strip_ns(k): v for k, v in element.attrib.items()}
    for child in element:
        name = _strip_ns(child.tag)
        value = _xml_node(child)
        if name in out:
            out[name] = (out[name] if isinstance(out[name], list) else [out[name]]) + [value]
        else:
            out[name] = value
    text = (element.text or "").strip()
    if text:
        if not out:
            return text
        out["#text"] = text
    return out or None


def _xml_event(element: ET.Element) -> dict:
    """`<Event>`: System as-is; EventData's `<Data Name=…>` children become named fields."""
    event: dict = {}
    for child in element:
        name = _strip_ns(child.tag)
        if name == "EventData":
            data: dict = {}
            unnamed: list = []
            for item in child:
                key = item.attrib.get("Name")
                value = (item.text or "").strip()
                if key:
                    data[key] = value
                elif value:
                    unnamed.append(value)
            if unnamed:
                data["Data"] = "\n".join(unnamed)
            event["EventData"] = data
        else:
            event[name] = _xml_node(child)
    return event


_DECLARATION = re.compile(rb"<\?xml[^>]*\?>")
#: Uploads are untrusted. Every entity attack (billion laughs, external entities) needs a DTD,
#: and an EVTX export never has one, so a document declaring one is refused outright — what
#: defusedxml's forbid_dtd does, without the dependency.
_DTD = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


def _xml_file(path: Path, stats: dict, spellings: dict) -> Iterator[Parsed]:
    """EVTX exported as XML, rooted or not: a synthetic root makes a rootless file parseable."""
    parser = ET.XMLPullParser(events=("end",))
    parser.feed(b"<lt_root>")
    tail = b""
    with path.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            if _DTD.search(tail + chunk):  # the overlap catches a token split across chunks
                stats["errors"] += 1
                stats["dtd_refused"] = True
                return
            tail = chunk[-16:]
            parser.feed(_DECLARATION.sub(b"", chunk))
            yield from _drain_xml(parser, stats, spellings)
    parser.feed(b"</lt_root>")
    try:
        parser.close()
    except ET.ParseError:
        stats["errors"] += 1
    yield from _drain_xml(parser, stats, spellings)


def _drain_xml(parser: ET.XMLPullParser, stats: dict, spellings: dict) -> Iterator[Parsed]:
    try:
        for _kind, element in parser.read_events():
            if _strip_ns(element.tag) == "Event":
                try:
                    yield _windows(_xml_event(element), spellings)
                except Exception:
                    stats["errors"] += 1
                element.clear()
    except ET.ParseError:
        stats["errors"] += 1


# ── Linux ───────────────────────────────────────────────────────────────────────


def _text_lines(path: Path) -> Iterator[tuple[int, str]]:
    with path.open("rb") as stream:
        for number, raw in enumerate(stream, start=1):
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if line.strip():
                yield number, line


def _sysmon_linux(path: Path, stats: dict, spellings: dict) -> Iterator[Parsed]:
    """A syslog line carrying one `<Event>…</Event>` XML record."""
    for number, line in _text_lines(path):
        start = line.find("<Event")
        if start < 0:
            continue
        if _DTD.search(line.encode("utf-8", "replace")):
            stats["errors"] += 1
            continue
        try:
            flat, fixed = _windows(_xml_event(ET.fromstring(line[start:])), spellings)  # noqa: S314 — a line declaring a DTD was refused above
        except ET.ParseError:
            stats["errors"] += 1
            continue
        fixed["line"] = number
        yield flat, fixed


_AUDIT = re.compile(r"^(?:node=(\S+) )?type=(\S+) msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s?(.*)$")
_KV = re.compile(r"""([A-Za-z0-9_-]+)=("[^"]*"|'[^']*'|\S*)""")
_HEX = re.compile(r"^[0-9A-Fa-f]{4,}$")


def _audit_value(key: str, raw: str) -> str:
    if raw[:1] in ('"', "'"):
        return raw[1:-1]
    if (key == "proctitle" or re.fullmatch(r"a\d+", key)) and _HEX.match(raw) and len(raw) % 2 == 0:
        try:
            return bytes.fromhex(raw).decode("utf-8", errors="replace").replace("\x00", " ").strip()
        except ValueError:
            return raw
    return raw


def _auditd(path: Path, stats: dict, spellings: dict) -> Iterator[Parsed]:
    for number, line in _text_lines(path):
        m = _AUDIT.match(line)
        if not m:
            stats["errors"] += 1
            continue
        node, kind, epoch, serial, rest = m.groups()
        body, _, enriched = rest.partition("\x1d")
        fields: dict = {"type": kind}
        for key, raw in _KV.findall(body):
            if key == "msg" and raw[:1] == "'":
                for inner_key, inner_raw in _KV.findall(raw[1:-1]):
                    fields.setdefault(inner_key, _audit_value(inner_key, inner_raw))
                continue
            fields.setdefault(key, _audit_value(key, raw))
        for key, raw in _KV.findall(enriched):
            fields.setdefault(key, _audit_value(key, raw))
        flat = flatten(fields, root=None, spellings=spellings)
        fixed = {
            "time": parse_time(float(epoch)),
            "host": norm_host(node or fields.get("hostname")),
            "channel": "auditd",
            "eid": None,
            "rid": None,
            "seq": int(serial),
            "line": number,
        }
        yield flat, fixed


def _journald_fixed(fields: dict, number: int | None) -> dict:
    return {
        "time": parse_time(fields.get("__REALTIME_TIMESTAMP") or fields.get("_SOURCE_REALTIME_TIMESTAMP")),
        "host": norm_host(fields.get("_HOSTNAME")),
        "channel": norm_channel(fields.get("SYSLOG_IDENTIFIER") or fields.get("_COMM") or "journald"),
        "eid": None,
        "rid": None,
        "seq": None,
        "line": number,
    }


def _journald(path: Path, stats: dict, spellings: dict) -> Iterator[Parsed]:
    with path.open("rb") as stream:
        head = stream.read(64).lstrip(b"\xef\xbb\xbf")
    if head.startswith(b"__CURSOR="):
        yield from _journald_export(path, stats, spellings)
        return
    for record in _json_records(path, stats):
        fields = {k: (orjson.dumps(v).decode() if isinstance(v, list) else v) for k, v in record.items()}
        yield flatten(fields, root=None, spellings=spellings), _journald_fixed(fields, None)


def _journald_export(path: Path, stats: dict, spellings: dict) -> Iterator[Parsed]:
    """`journalctl -o export`: KEY=value lines, a blank line between entries; a binary field
    is its name alone on a line, then a little-endian 64-bit length, the bytes and a newline."""
    fields: dict = {}
    with path.open("rb") as stream:
        while True:
            raw = stream.readline()
            if not raw or raw == b"\n":
                if fields:
                    yield flatten(fields, root=None, spellings=spellings), _journald_fixed(fields, None)
                    fields = {}
                if not raw:
                    return
                continue
            line = raw.rstrip(b"\n")
            key, sep, value = line.partition(b"=")
            if sep:
                fields[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
                continue
            size_bytes = stream.read(8)
            if len(size_bytes) < 8:
                stats["errors"] += 1
                return
            data = stream.read(int.from_bytes(size_bytes, "little"))
            stream.read(1)
            fields[line.decode("utf-8", "replace")] = data.decode("utf-8", "replace")


_RFC5424 = re.compile(r"^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[.*?\](?:\[.*?\])*) ?(.*)$")
_RFC3164 = re.compile(r"^(?:<(\d{1,3})>)?([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) (\S+) ([^:\[\s]+)(?:\[(\d+)\])?: ?(.*)$")
_ISO_SYSLOG = re.compile(r"^(?:<(\d{1,3})>)?(\d{4}-\d{2}-\d{2}[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?) (\S+) ([^:\[\s]+)(?:\[(\d+)\])?: ?(.*)$")
_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}


def _rfc3164_time(month: str, day: str, clock: str, reference: datetime | None) -> datetime | None:
    """RFC 3164 has no year. The upload's date supplies it; a month after the upload's is last year's."""
    if month not in _MONTHS:
        return None
    ref = reference or datetime.now()
    year = ref.year - (1 if _MONTHS[month] > ref.month else 0)
    try:
        return datetime.strptime(f"{year}-{_MONTHS[month]:02d}-{int(day):02d} {clock}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _syslog(path: Path, stats: dict, spellings: dict, reference: datetime | None) -> Iterator[Parsed]:
    for number, line in _text_lines(path):
        fields: dict = {}
        when = None
        if m := _RFC5424.match(line):
            pri, stamp, host, app, procid, msgid, sd, message = m.groups()
            fields = {
                "priority": int(pri),
                "timestamp": stamp,
                "host": host,
                "program": app,
                "pid": procid if procid != "-" else None,
                "msgid": msgid if msgid != "-" else None,
                "structured_data": sd if sd != "-" else None,
                "message": message,
            }
            when = parse_time(stamp)
        elif m := _ISO_SYSLOG.match(line):
            pri, stamp, host, program, pid, message = m.groups()
            fields = {"priority": int(pri) if pri else None, "timestamp": stamp, "host": host, "program": program, "pid": pid, "message": message}
            when = parse_time(stamp)
        elif m := _RFC3164.match(line):
            pri, month, day, clock, host, program, pid, message = m.groups()
            fields = {"priority": int(pri) if pri else None, "timestamp": f"{month} {day} {clock}", "host": host, "program": program, "pid": pid, "message": message}
            when = _rfc3164_time(month, day, clock, reference)
        else:
            fields = {"message": line}
            stats["unparsed_lines"] = stats.get("unparsed_lines", 0) + 1
        if fields.get("priority") is not None:
            fields["facility"], fields["severity"] = divmod(fields["priority"], 8)
        fields["message_sha"] = message_sha(fields.get("message"))
        yield (
            flatten(fields, root=None, spellings=spellings),
            {"time": when, "host": norm_host(fields.get("host")), "channel": norm_channel(fields.get("program")), "eid": None, "rid": None, "seq": None, "line": number},
        )


def _lines(path: Path, stats: dict, spellings: dict) -> Iterator[Parsed]:
    """Unknown formats: one event per non-empty line, kept whole."""
    for number, line in _text_lines(path):
        yield flatten({"message": line}, root=None, spellings=spellings), {"time": None, "host": None, "channel": None, "eid": None, "rid": None, "seq": None, "line": number}
