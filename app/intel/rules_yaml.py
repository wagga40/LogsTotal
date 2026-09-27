"""Rules as data — the one YAML document the seed files, the export and the import share.

Two files ship under `rules/`: `lists.yml`, the named sets a condition tests with
`list:<name>`, and `builtin.yml`, the shared rules — `lolbin`, `privileged`, `rfc1918`, … —
whose criteria are real expressions in the entity grammar (`list:lolbas`,
`cidr:10.0.0.0/8,…`, `re:/^[0-9a-f]{32}$/`) rather than `attr:` pointers into
`compute_attributes()`. The Rules page exports the same document and imports it back, so
rules and lists can be read, diffed, shared and restored as a file.

**Seeding policy: the file updates what nobody edited.** Every seeded row remembers the
hash of the definition it was seeded with (`seed_hash`, `enabled` excluded). At start, a row
whose current definition still equals that hash takes the file's newer version; a row that
differs was edited in the UI and is left alone. The two obvious policies are both wrong:
overwrite-on-boot (what workflows do) discards an admin's edit on every Docker restart, and
never-overwrite means a shipped fix reaches nobody.

Two halves. The pure half — `RuleSpec`, `RulesDocument`, `parse_rules_yaml`,
`validate_spec`, `apply_spec`, `spec_from_rule`, `spec_hash`, `dump_rules_yaml` — has no
session and is what the rule form, the import and the seed all validate through, so a
document that imports is a form that would have saved. The impure half at the bottom is the
two writers, `sync_rules_from_dir` and `import_rules`. Lists themselves live in
`rule_lists.py`; this module carries them through the document and the two writers.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.constants import DEFAULT_RULE_SCOPE, ENTITY_TYPES, RULE_SCOPES, parse_entity_types
from app.intel.queries import job_terms, parse_query, unknown_list_errors
from app.intel.rule_lists import ListSpec, is_list_scalar, list_hash, load_lists, normalize_values, rules_naming, validate_list_spec, write_list
from app.intel.rule_lists import spec_to_mapping as list_to_mapping
from app.intel.webhooks import WEBHOOK_METHODS, WebhookError, clean_webhook_headers, validate_url_syntax
from app.jobs_query import parse_jobs_query, query_errors
from app.json_utils import dumps as json_dumps
from app.json_utils import loads as json_loads
from app.models import IntelRule, IntelRuleMatch, JobRuleMatch, WebhookDelivery
from app.tags import ensure_tag_definition, parse_tag_write
from app.yaml_utils import bounded_load as yaml_safe_load

#: Bounds on one document. Two hundred is ten times the shipped set and four times a
#: member's rule budget; half a megabyte is the largest reasonable paste.
MAX_RULES_PER_DOCUMENT = 200
MAX_LISTS_PER_DOCUMENT = 50
MAX_DOCUMENT_BYTES = 512 * 1024

NAME_MAX = 120
DESCRIPTION_MAX = 500
CRITERIA_MAX = 500
#: `IntelRule.builtin_key` is `String(50)`; the same shape as a tag name and a list name.
KEY_RE = re.compile(r"^[a-z0-9_]{1,50}$")


@dataclass(frozen=True)
class RuleSpec:
    """One rule as data: everything a document says about it, and nothing a document may not.

    Not here, deliberately: the owner (decided by who imports), `is_builtin`/`builtin_key`
    beyond `key` (decided by *how* it is imported), the webhook signing secret (never
    exported, never importable — a secret in a file people share is not a secret),
    `notify_job_watch` (a per-person preference, at most one rule per owner carries it), and
    `seed_hash` (the seeder's own bookkeeping).
    """

    name: str
    criteria: str = ""
    key: str | None = None
    description: str = ""
    scope: str = DEFAULT_RULE_SCOPE
    entity_types: tuple[str, ...] = ()
    tags: tuple[tuple[str, str], ...] = ()
    notify: bool = False
    enabled: bool = True
    webhook_url: str | None = None
    webhook_method: str = "POST"
    webhook_headers_json: str | None = None
    webhook_enabled: bool = False


@dataclass
class RulesDocument:
    """What a parsed document holds: the rules and lists that were clean, and every error."""

    rules: list[RuleSpec] = field(default_factory=list)
    lists: list[ListSpec] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ── validation ─────────────────────────────────────────────────────────────────


def _criteria_errors(criteria: str, scope: str, known_lists) -> list[str]:
    """Exactly the checks the rule form makes, per scope, so the three writers agree."""
    if scope == "job":
        # The jobs-list grammar, validated by its own parser. `job:` does not exist in it;
        # every other term is legitimate, and the ones that only make sense mid-run
        # (`is:running`) simply never match a finished job — a rule that matches nothing,
        # which is not an error.
        return query_errors(parse_jobs_query(criteria))
    parsed = parse_query(criteria)
    if job_terms(parsed):
        # An entity rule is already evaluated against exactly the job being finished, so
        # `job:` is at best a no-op. It is also the one term that would gain a rule the power
        # to ask "did *that* job contain anything matching X" — the worker has no viewer to
        # check visibility against, so the answer would arrive regardless of whether the
        # owner may see that submission.
        return ["job: cannot be used in a rule — rules already run against each job as it finishes"]
    if parsed.get("invalid"):
        return [parsed["errors"][0] if parsed["errors"] else "That condition is not valid"]
    # A term that fell back to a literal (`attr:bogus`) is a rule that will search for the
    # misspelling as text and match nothing, forever, without saying so. A `list:` naming
    # no list is the same mistake one layer down, which only a caller with a session can see.
    errors = list(parsed.get("errors") or [])
    if known_lists is not None:
        errors.extend(unknown_list_errors(parsed, known_lists))
    return errors


def validate_spec(spec: RuleSpec, *, known_lists=None) -> list[str]:
    """Every reason this spec may not become a rule, in field order. Empty means it may.

    The one validator: the rule form, the YAML import and the seed all call it, so no
    surface can accept what another would refuse. `known_lists` is the set of list names the
    database carries; pass it wherever there is a session, or a rule can name a list that
    does not exist and quietly match nothing.
    """
    errors: list[str] = []
    if not spec.name.strip():
        errors.append("Rule needs a name")
    elif len(spec.name) > NAME_MAX:
        errors.append(f"Name is longer than {NAME_MAX} characters")
    if len(spec.description) > DESCRIPTION_MAX:
        errors.append(f"Description is longer than {DESCRIPTION_MAX} characters")
    if spec.key is not None and not KEY_RE.match(spec.key):
        errors.append("key must be 1-50 lowercase letters, digits or underscores")
    if spec.scope not in RULE_SCOPES:
        errors.append(f"scope must be one of {', '.join(RULE_SCOPES)}")
    unknown_types = [t for t in spec.entity_types if t not in ENTITY_TYPES]
    if unknown_types:
        errors.append(f"unknown entity type {unknown_types[0]!r} — one of {', '.join(ENTITY_TYPES)}")
    if len(spec.criteria) > CRITERIA_MAX:
        errors.append(f"Condition is longer than {CRITERIA_MAX} characters")
    elif spec.scope in RULE_SCOPES:
        errors.extend(_criteria_errors(spec.criteria, spec.scope, known_lists))
    if spec.webhook_url:
        # Syntax only. Resolution is checked at delivery time — a receiver that is briefly
        # down, or only resolvable from the worker's network, must not block saving a rule.
        try:
            validate_url_syntax(spec.webhook_url)
        except WebhookError as exc:
            errors.append(f"Webhook URL rejected: {exc}")
    if spec.webhook_method not in WEBHOOK_METHODS:
        errors.append(f"Method must be one of {', '.join(WEBHOOK_METHODS)}")
    try:
        clean_webhook_headers(spec.webhook_headers_json)
    except WebhookError as exc:
        errors.append(str(exc))
    return errors


def document_errors(rules: list[RuleSpec], lists: list[ListSpec] = ()) -> list[str]:
    """What is wrong with a *set* that is right with each member: duplicate identities."""
    errors: list[str] = []
    seen_keys: set[str] = set()
    seen_names: set[str] = set()
    for i, spec in enumerate(rules):
        if spec.key:
            if spec.key in seen_keys:
                errors.append(f"rules[{i}] ({spec.key}): duplicate key")
            seen_keys.add(spec.key)
        name = spec.name.strip().lower()
        if name in seen_names:
            errors.append(f"rules[{i}] ({spec.name}): duplicate name — a name is a rule's identity when it is imported as your own")
        seen_names.add(name)
    seen_lists: set[str] = set()
    for i, lspec in enumerate(lists):
        if lspec.name in seen_lists:
            errors.append(f"lists[{i}] ({lspec.name}): duplicate list name")
        seen_lists.add(lspec.name)
    return errors


# ── the column mapping, both directions ────────────────────────────────────────


def apply_spec(rule: IntelRule, spec: RuleSpec) -> None:
    """Write a validated spec onto a row.

    Never touches `owner_user_id`, `is_builtin`, `builtin_key`, `seed_hash`, the signing
    secret or `notify_job_watch` — see `RuleSpec`. Call `validate_spec` first; this trusts
    its input.
    """
    rule.name = spec.name
    rule.description = spec.description or None
    rule.scope = spec.scope
    rule.query = spec.criteria
    # Entity types narrow an entity rule and mean nothing to a job rule. Stored as an empty
    # list for the latter, so switching a rule's scope cannot leave a filter behind that
    # nothing applies and nothing displays.
    rule.entity_types = json_dumps(list(spec.entity_types) if spec.scope == "entity" else [])
    # The same index-aligned CSV pair the tag picker posts.
    rule.action_tag = ",".join(t for t, _ in spec.tags) or None
    rule.action_tag_color = ",".join(c for _, c in spec.tags) or "gray"
    rule.action_notify = bool(spec.notify)
    rule.enabled = bool(spec.enabled)
    rule.webhook_url = spec.webhook_url or None
    rule.webhook_method = spec.webhook_method
    rule.webhook_headers_json = clean_webhook_headers(spec.webhook_headers_json)
    rule.webhook_enabled = bool(spec.webhook_url) and bool(spec.webhook_enabled)


def spec_from_rule(rule: IntelRule) -> RuleSpec:
    """Read a row back as a spec — what Export writes, and what the seeder hashes."""
    return RuleSpec(
        key=rule.builtin_key,
        name=rule.name or "",
        description=rule.description or "",
        scope=rule.scope or DEFAULT_RULE_SCOPE,
        entity_types=tuple(parse_entity_types(json_loads(rule.entity_types or "[]"))),
        criteria=rule.query or "",
        tags=tuple(parse_tag_write(rule.action_tag or "", rule.action_tag_color or "gray")),
        notify=bool(rule.action_notify),
        enabled=bool(rule.enabled),
        webhook_url=rule.webhook_url or None,
        webhook_method=(rule.webhook_method or "POST").upper(),
        webhook_headers_json=rule.webhook_headers_json or None,
        webhook_enabled=bool(rule.webhook_enabled),
    )


def spec_hash(spec: RuleSpec) -> str:
    """What `IntelRule.seed_hash` stores: the definition, `enabled` and `key` aside.

    `enabled` is excluded because switching a shared rule off is the ordinary use of an
    editable one, not an edit of what it means — and the seeder preserves it either way.
    """
    payload = json.dumps(_spec_to_mapping(replace(spec, enabled=True), with_key=False), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ── the document ───────────────────────────────────────────────────────────────


def _entity_types(raw_types: Any, errors: list[str]) -> tuple[str, ...]:
    if raw_types is None:
        return ()
    if not isinstance(raw_types, list | str):
        errors.append("entity_types must be a list")
        return ()
    values = raw_types.split(",") if isinstance(raw_types, str) else raw_types
    if any(not isinstance(value, str) for value in values):
        errors.append("entity_types must contain only strings")
        return ()
    # Preserve unknown strings for the semantic validator to report.
    return tuple(value.strip().lower() for value in values if value.strip())


def _spec_from_mapping(raw: dict[str, Any]) -> tuple[RuleSpec, list[str]]:
    """Shape and type checks for one `rules:` entry; semantics are `validate_spec`'s."""
    errors: list[str] = []

    def text(field_name: str) -> str:
        value = raw.get(field_name)
        if value is None:
            return ""
        if not isinstance(value, str):
            errors.append(f"{field_name} must be a string")
            return ""
        return value.strip()

    def flag(field_name: str, default: bool) -> bool:
        value = raw.get(field_name, default)
        if not isinstance(value, bool):
            errors.append(f"{field_name} must be true or false")
            return default
        return value

    key = text("key") or None
    if key is not None:
        key = key.lower()
    entity_types = _entity_types(raw.get("entity_types"), errors)

    tags: list[tuple[str, str]] = []
    raw_tags = raw.get("tags", [])
    if raw_tags is None:
        raw_tags = []
    if not isinstance(raw_tags, list):
        errors.append("tags must be a list of {name, color}")
        raw_tags = []
    for item in raw_tags:
        if isinstance(item, str):
            tags.extend(parse_tag_write(item, "gray"))
        elif isinstance(item, dict):
            name, color = item.get("name", ""), item.get("color", "gray")
            if not isinstance(name, str) or not isinstance(color, str):
                errors.append("tag name and color must be strings")
            else:
                tags.extend(parse_tag_write(name, color))
        else:
            errors.append("each tag must be a name or a {name, color} mapping")

    webhook = raw.get("webhook", {})
    if webhook is None:
        webhook = {}
    if not isinstance(webhook, dict):
        errors.append("webhook must be a mapping of url, method, headers, enabled")
        webhook = {}
    headers = webhook.get("headers")
    headers_json = None
    if isinstance(headers, dict):
        if any(not isinstance(k, str) or not is_list_scalar(v) for k, v in headers.items()):
            errors.append("webhook.headers must contain string keys and scalar values")
        elif headers:
            headers_json = json_dumps(headers)
    if headers is not None and not isinstance(headers, dict):
        errors.append("webhook.headers must be a mapping")
    url, method = webhook.get("url", ""), webhook.get("method", "POST")
    if url is None:
        url = ""
    if not isinstance(url, str) or not isinstance(method, str):
        errors.append("webhook url and method must be strings")
        url, method = "", "POST"
    webhook_enabled = webhook.get("enabled", bool(url))
    if not isinstance(webhook_enabled, bool):
        errors.append("webhook.enabled must be true or false")
        webhook_enabled = False

    # `criteria` is the file's word (it is what the column is called); `condition` is the
    # page's, and a file written from the page's vocabulary should load too.
    criteria = text("criteria") or text("condition")
    spec = RuleSpec(
        key=key,
        name=text("name"),
        description=text("description"),
        scope=(text("scope") or DEFAULT_RULE_SCOPE).lower(),
        entity_types=entity_types,
        criteria=criteria,
        tags=tuple(tags),
        notify=flag("notify", False),
        enabled=flag("enabled", True),
        webhook_url=url.strip() or None,
        webhook_method=method.strip().upper(),
        webhook_headers_json=headers_json,
        webhook_enabled=webhook_enabled,
    )
    if not errors:
        errors = validate_spec(spec)
    return spec, errors


def _list_from_mapping(raw: dict[str, Any]) -> tuple[ListSpec, list[str]]:
    errors: list[str] = []
    name = raw.get("name")
    if not isinstance(name, str):
        errors.append("name must be a string")
        name = ""
    match = raw.get("match", "exact")
    if not isinstance(match, str):
        errors.append("match must be exact or suffix")
        match = "exact"
    description = raw.get("description", "")
    if description is None:
        description = ""
    if not isinstance(description, str):
        errors.append("description must be a string")
        description = ""
    raw_values = raw.get("values")
    if raw_values is not None and not isinstance(raw_values, list | str):
        errors.append("values must be a list, or text with one value per line")
        raw_values = None
    if isinstance(raw_values, list) and any(not is_list_scalar(v) for v in raw_values):
        errors.append("values must contain only strings or finite numbers")
        raw_values = None
    spec = ListSpec(name=name.strip().lower(), match=match.strip().lower(), description=description.strip(), values=normalize_values(raw_values))
    if not errors:
        errors = validate_list_spec(spec)
    return spec, errors


def parse_rules_yaml(text: str) -> RulesDocument:
    """Parse with bounded diagnostics; never stringify caller-controlled containers."""
    doc = _parse_rules_yaml(text)
    truncated = len(doc.errors) > 100
    doc.errors = [message[:256] for message in doc.errors[:100]]
    if truncated:
        doc.errors.append("Additional validation errors omitted.")
    return doc


def _parse_rules_yaml(text: str) -> RulesDocument:
    """Parse a document into its clean rules and lists. Never raises on content.

    A rule or list is returned only when nothing is wrong with it, and every error names its
    entry as `rules[3] (md5): …` or `lists[0] (lolbas): …` so a 200-rule file is fixable.
    """
    if len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        return RulesDocument(errors=[f"document is larger than {MAX_DOCUMENT_BYTES // 1024} KB"])
    try:
        data = yaml_safe_load(text)
    except (yaml.YAMLError, ValueError, RecursionError) as exc:
        return RulesDocument(errors=[f"not valid YAML: {str(exc).splitlines()[0]}"])
    if not isinstance(data, dict) or not ({"rules", "lists"} & set(data)):
        return RulesDocument(errors=["expected a top-level `rules:` list and/or a `lists:` list"])

    doc = RulesDocument()
    raw_lists = data.get("lists", [])
    if raw_lists is None:
        raw_lists = []
    if not isinstance(raw_lists, list):
        doc.errors.append("`lists:` must be a list")
        raw_lists = []
    if len(raw_lists) > MAX_LISTS_PER_DOCUMENT:
        return RulesDocument(errors=[f"a document may hold at most {MAX_LISTS_PER_DOCUMENT} lists"])
    for i, raw in enumerate(raw_lists):
        if not isinstance(raw, dict):
            doc.errors.append(f"lists[{i}]: expected a mapping")
            continue
        lspec, errs = _list_from_mapping(raw)
        label = f"lists[{i}]" + (f" ({lspec.name})" if lspec.name else "")
        doc.errors.extend(f"{label}: {e}" for e in errs)
        if not errs:
            doc.lists.append(lspec)

    raw_rules = data.get("rules", [])
    if raw_rules is None:
        raw_rules = []
    if not isinstance(raw_rules, list):
        doc.errors.append("`rules:` must be a list")
        raw_rules = []
    if len(raw_rules) > MAX_RULES_PER_DOCUMENT:
        return RulesDocument(errors=[f"a document may hold at most {MAX_RULES_PER_DOCUMENT} rules"])
    for i, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            doc.errors.append(f"rules[{i}]: expected a mapping")
            continue
        spec, errs = _spec_from_mapping(raw)
        label = f"rules[{i}]" + (f" ({spec.key or spec.name})" if (spec.key or spec.name) else "")
        doc.errors.extend(f"{label}: {e}" for e in errs)
        if not errs:
            doc.rules.append(spec)
    doc.errors.extend(document_errors(doc.rules, doc.lists))
    return doc


def _spec_to_mapping(spec: RuleSpec, *, with_key: bool) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if with_key and spec.key:
        out["key"] = spec.key
    out["name"] = spec.name
    if spec.description:
        out["description"] = spec.description
    out["scope"] = spec.scope
    if spec.scope == "entity":
        out["entity_types"] = list(spec.entity_types)
    out["criteria"] = spec.criteria
    out["tags"] = [{"name": t, "color": c} for t, c in spec.tags]
    out["notify"] = spec.notify
    out["enabled"] = spec.enabled
    if spec.webhook_url:
        webhook: dict[str, Any] = {"url": spec.webhook_url, "method": spec.webhook_method}
        if spec.webhook_headers_json:
            webhook["headers"] = json_loads(spec.webhook_headers_json)
        webhook["enabled"] = spec.webhook_enabled
        out["webhook"] = webhook
    return out


class _Dumper(yaml.SafeDumper):
    """Block style throughout, and no line-folding: the `public` rule's criteria is ~190
    characters and a folded plain scalar reloads identically but reads badly."""


def dump_rules_yaml(rules: list[RuleSpec], *, lists: list[ListSpec] = (), with_keys: bool = True) -> str:
    """Serialise lists then rules in the seed files' shape, fields in reading order."""
    doc: dict[str, Any] = {}
    if lists:
        doc["lists"] = [list_to_mapping(s) for s in lists]
    doc["rules"] = [_spec_to_mapping(s, with_key=with_keys) for s in rules]
    return yaml.dump(doc, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=10_000, default_flow_style=False)


# ── the shipped directory ──────────────────────────────────────────────────────


def rules_dir() -> Path:
    """`rules/` at the project root — the `init_db.py` resolution, from inside the package."""
    return Path(__file__).resolve().parents[2] / "rules"


def load_rules_dir(directory: Path) -> RulesDocument:
    """Every rule and list in `directory/*.yml`, in file then document order.

    Every shipped rule needs a `key`. Errors are prefixed with the file name, and a file that
    does not parse does not stop the others from loading — the `sync_workflows_from_dir`
    stance.
    """
    doc = RulesDocument()
    if not directory.is_dir():
        doc.errors.append(f"no rules directory at {directory}")
        return doc
    for path in sorted(directory.glob("*.yml")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            doc.errors.append(f"{path.name}: {exc}")
            continue
        parsed = parse_rules_yaml(text)
        doc.errors.extend(f"{path.name}: {e}" for e in parsed.errors)
        doc.lists.extend(parsed.lists)
        for spec in parsed.rules:
            if not spec.key:
                doc.errors.append(f"{path.name}: rule {spec.name!r} has no key — every shipped rule needs one")
                continue
            doc.rules.append(spec)
    doc.errors.extend(f"{directory.name}/: {e}" for e in document_errors(doc.rules, doc.lists) if "duplicate key" in e or "duplicate list" in e)
    return doc


# ── the impure half: two writers ───────────────────────────────────────────────


def _new_builtin(spec: RuleSpec, *, seed_hash: str | None) -> IntelRule:
    # No owner: instance-wide, and so exempt from `watch_rules_max_per_user`, which counts
    # `owner_user_id == user.id`. `action_notify=False` + no webhook are what the seed file
    # says, and they are load-bearing rather than defaults: `_rule_may_run_on`'s exemption
    # for private jobs is conditional on them, and `evaluate_rules_for_job` skips the alert
    # ledger for a rule that neither alerts nor delivers.
    rule = IntelRule(name=spec.name, owner_user_id=None, is_builtin=True, builtin_key=spec.key, seed_hash=seed_hash)
    apply_spec(rule, spec)
    return rule


async def _register_tags(db: AsyncSession, spec: RuleSpec, owner_id) -> None:
    for tag, color in spec.tags:
        await ensure_tag_definition(db, tag, color, user_id=owner_id)


# What the first cut wrote into every seeded row's description, before `seed_hash` existed.
_FIRST_CUT_DESCRIPTION = "Built-in label. Applies the tag "


def rule_is_unedited(rule: IntelRule) -> bool:
    """Does the row still say what it was seeded with?

    Public because the Rules page reads it too, so an admin can see which shared rules have
    stopped tracking `rules/*.yml` — the question you ask when an upgrade did not change
    what you expected.

    A row with no hash was seeded before `seed_hash` existed, with an `attr:<key>` condition
    and a fixed description; that exact shape is the one NULL case treated as unedited. The
    description is part of the test, not decoration: an admin importing `key: dga` with
    `criteria: attr:dga` also leaves the hash NULL, and without it that rule was retired on
    every start.
    """
    if rule.seed_hash is not None:
        return rule.seed_hash == spec_hash(spec_from_rule(rule))
    return (rule.query or "") == f"attr:{rule.builtin_key}" and (rule.description or "").startswith(_FIRST_CUT_DESCRIPTION)


@dataclass(frozen=True)
class SyncResult:
    created: int = 0
    updated: int = 0
    kept: int = 0
    retired: int = 0
    lists_created: int = 0
    lists_updated: int = 0
    lists_kept: int = 0
    lists_retired: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        rules = f"rules: {self.created} created, {self.updated} updated, {self.kept} kept" + (f", {self.retired} retired" if self.retired else "")
        lists = f"lists: {self.lists_created} created, {self.lists_updated} updated, {self.lists_kept} kept" + (f", {self.lists_retired} retired" if self.lists_retired else "")
        return f"{rules} · {lists}"


async def sync_rules_from_dir(db: AsyncSession, directory: Path) -> SyncResult:
    """Seed `directory/*.yml`: create what is missing, update what nobody edited, keep the rest,
    and retire what the files no longer ship if nobody edited it.

    Lists first, then rules, so a rule's `list:` validates against the lists the same files
    define. A row counts as *updated* only when the file changed and the row still equalled
    its seeded definition; an edited row is *kept*, and so is one already current. `enabled`
    is preserved across an update — switching a shared rule off is not an edit of what it
    means. A shared rule whose key no file ships any more is *retired* — deleted, its tags
    left where they were written — when it still equals its seeded definition; edited, it
    has become the admin's and stays. A list is retired on the same terms, and only when no
    rule names it. Called from `init_db.py`, from `./logstotal sync-rules`, and once from the app's
    lifespan so an upgraded deployment gets a release's rules with no manual step.

    Does not commit — the caller owns the transaction, the `app/tags.py` contract.
    """
    doc = load_rules_dir(directory)
    counts: dict[str, int] = dict.fromkeys(("created", "updated", "kept", "retired", "lists_created", "lists_updated", "lists_kept", "lists_retired"), 0)

    existing_lists = {row.name: (row, current) for row, current in await load_lists(db)}
    for lspec in doc.lists:
        digest = list_hash(lspec)
        row_and_current = existing_lists.get(lspec.name)
        if row_and_current is None:
            await write_list(db, None, lspec, seed_hash=digest)
            counts["lists_created"] += 1
            continue
        row, current = row_and_current
        if row.seed_hash == digest:
            counts["lists_kept"] += 1
        elif row.seed_hash is None and list_hash(current) == digest:
            # Identical to the file but never marked: adopt it. Updating would change nothing.
            row.seed_hash = digest
            counts["lists_kept"] += 1
        elif row.seed_hash is not None and row.seed_hash == list_hash(current):
            await write_list(db, row, lspec, seed_hash=digest)
            counts["lists_updated"] += 1
        else:
            counts["lists_kept"] += 1

    known_lists = set(existing_lists) | {lspec.name for lspec in doc.lists}
    rows = {r.builtin_key: r for r in (await db.execute(select(IntelRule).where(IntelRule.builtin_key.is_not(None)))).scalars().all()}
    for spec in doc.rules:
        errs = unknown_list_errors(parse_query(spec.criteria), known_lists) if spec.scope == "entity" else []
        if errs:
            doc.errors.append(f"{spec.key}: {errs[0]}")
            continue
        digest = spec_hash(spec)
        rule = rows.get(spec.key)
        if rule is None:
            db.add(_new_builtin(spec, seed_hash=digest))
            await _register_tags(db, spec, None)
            counts["created"] += 1
        elif rule.seed_hash == digest:
            counts["kept"] += 1
        elif rule.seed_hash is None and spec_hash(spec_from_rule(rule)) == digest:
            # Identical to the file but never marked — a row an admin reset or imported to
            # exactly what ships. Adopt it: updating would change nothing, and marking it
            # is what lets the next release's change reach it.
            rule.seed_hash = digest
            counts["kept"] += 1
        elif rule_is_unedited(rule):
            enabled = bool(rule.enabled)
            apply_spec(rule, spec)
            rule.enabled = enabled
            rule.seed_hash = digest
            await _register_tags(db, spec, None)
            counts["updated"] += 1
        else:
            counts["kept"] += 1

    # Retire what the files dropped, if nobody edited it. Rules first (a retired rule frees
    # the list it named), then lists nothing names any more.
    #
    # Only from a directory that loaded cleanly. An unparseable file, a missing directory or
    # a rule the parser refused makes a shipped key *look* dropped, and retiring on that
    # deleted every unedited shared rule at once — with each "switched off" lost when the
    # fixed file re-created them.
    if doc.errors:
        return SyncResult(**counts, errors=doc.errors)
    shipped_keys = {s.key for s in doc.rules}
    for key, rule in rows.items():
        if key in shipped_keys or not rule.is_builtin:
            continue
        if not rule_is_unedited(rule):
            counts["kept"] += 1  # the admin made it theirs; the file dropping it changes nothing
            continue
        # The same Core deletes as the page's Delete, and for the same reason: no ORM cascade
        # fires here, and a dangling ledger row is silent on SQLite and a violation on PG.
        for table in (WebhookDelivery, IntelRuleMatch, JobRuleMatch):
            await db.execute(delete(table).where(table.rule_id == rule.id))
        await db.delete(rule)
        counts["retired"] += 1
    await db.flush()
    shipped_lists = {lspec.name for lspec in doc.lists}
    for name, (row, current) in existing_lists.items():
        if name in shipped_lists:
            continue
        if row.seed_hash is None or row.seed_hash != list_hash(current):
            counts["lists_kept"] += 1
            continue
        if await rules_naming(db, name):
            counts["lists_kept"] += 1
            continue
        await db.delete(row)
        counts["lists_retired"] += 1
    await db.flush()
    return SyncResult(**counts, errors=doc.errors)


@dataclass(frozen=True)
class ImportResult:
    created: int = 0
    updated: int = 0
    lists_created: int = 0
    lists_updated: int = 0
    errors: list[str] = field(default_factory=list)
    # In a shared import, how many rules had no key and so came in as the importer's own.
    as_own: int = 0

    def summary(self) -> str:
        parts = [f"{self.created} rule{'s' if self.created != 1 else ''} created, {self.updated} updated"]
        if self.as_own:
            parts[0] += f" ({self.as_own} with no key imported as your own)"
        if self.lists_created or self.lists_updated:
            parts.append(f"{self.lists_created} list{'s' if self.lists_created != 1 else ''} created, {self.lists_updated} updated")
        return "; ".join(parts)


async def import_rules(
    db: AsyncSession,
    rules: list[RuleSpec],
    lists: list[ListSpec] = (),
    *,
    user,
    as_shared: bool,
    can_write_lists: bool,
    max_per_user: int | None = None,
) -> ImportResult:
    """Upsert a document's lists and rules. **All or nothing**: any error and nothing is written.

    Lists are instance-wide, so only a caller who may write them (an admin) can import any;
    they go in by name, first, and a rule's `list:` validates against them. Rules are the one
    thing the two modes disagree on. `as_shared` (the caller checks the admin) keys on
    `builtin_key` — the row is instance-wide and ownerless, created or updated in place — and
    a rule with no key in that document is the importer's own, which is exactly what an
    admin's Download YAML holds beside the shared rules. Otherwise the rules become the
    importer's own, keyed on `name` within their rules, and creations count against
    `max_per_user`, the budget the form spends. A key in a document imported as one's own is
    ignored: exporting the shared rules and importing them back as personal copies is a
    legitimate thing to do.

    An imported row carries no `seed_hash`: an import is an edit, and the seeder leaves it
    alone from then on.

    Does not commit.
    """
    errors: list[str] = []
    if lists and not can_write_lists:
        errors.append("lists are shared across the instance — only an administrator can import them")
    for i, lspec in enumerate(lists):
        errors.extend(f"lists[{i}] ({lspec.name}): {e}" for e in validate_list_spec(lspec))
    known_lists = await _list_names(db) | {lspec.name for lspec in lists}
    for i, spec in enumerate(rules):
        label = f"rules[{i}] ({spec.key or spec.name})"
        errors.extend(f"{label}: {e}" for e in validate_spec(spec, known_lists=known_lists))
    errors.extend(document_errors(rules, lists))
    if errors:
        return ImportResult(errors=errors)

    shared_specs = [s for s in rules if s.key] if as_shared else []
    own_specs = [s for s in rules if not s.key] if as_shared else list(rules)

    # The budget before any write, lists included: "any error and nothing is written", and a
    # refusal that had already flushed the lists rendered them on the page it came back to.
    names = [s.name for s in own_specs]
    own_rows = {r.name: r for r in (await db.execute(select(IntelRule).where(IntelRule.owner_user_id == user.id, IntelRule.name.in_(names)))).scalars().all()} if names else {}
    new = [s for s in own_specs if s.name not in own_rows]
    if max_per_user is not None and new:
        owned = await db.scalar(select(func.count(IntelRule.id)).where(IntelRule.owner_user_id == user.id)) or 0
        if owned + len(new) > max_per_user:
            return ImportResult(errors=[f"importing {len(new)} new rule{'s' if len(new) != 1 else ''} would exceed your limit of {max_per_user} ({owned} in use)"])

    counts = {"created": 0, "updated": 0, "lists_created": 0, "lists_updated": 0}
    if lists:
        existing = {row.name: row for row, _current in await load_lists(db)}
        for lspec in lists:
            row = existing.get(lspec.name)
            await write_list(db, row, lspec, seed_hash=None)
            counts["lists_created" if row is None else "lists_updated"] += 1

    keys = [s.key for s in shared_specs]
    shared_rows = {r.builtin_key: r for r in (await db.execute(select(IntelRule).where(IntelRule.builtin_key.in_(keys)))).scalars().all()} if keys else {}
    for spec in shared_specs:
        rule = shared_rows.get(spec.key)
        if rule is None:
            db.add(_new_builtin(spec, seed_hash=None))
            counts["created"] += 1
        else:
            apply_spec(rule, spec)
            rule.seed_hash = None
            counts["updated"] += 1
        await _register_tags(db, spec, None)
    for spec in own_specs:
        rule = own_rows.get(spec.name)
        if rule is None:
            rule = IntelRule(name=spec.name, owner_user_id=user.id)
            apply_spec(rule, spec)
            db.add(rule)
            counts["created"] += 1
        else:
            apply_spec(rule, spec)
            counts["updated"] += 1
        await _register_tags(db, spec, user.id)
    await db.flush()
    return ImportResult(**counts, as_own=len(own_specs) if as_shared else 0)


async def _list_names(db: AsyncSession) -> set[str]:
    from app.intel.rule_lists import list_names

    return await list_names(db)
