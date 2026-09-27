# Admin UI reference

What each admin page is for, every instance-wide setting, and how rules, cases, AI analysis, backfills and the activity log behave.

## Admin panel tour

All routes under `/admin/*` require `is_superuser=True`. The pages are self-describing; what
follows is the one thing about each that is not visible on it.

Every Manage card and every page title carries a count pill, so the grid answers "how many
users, how many workflows, is anything running, is anything enabled" without opening
anything. Two of them measure different things: the Storage card's `N uploaded` is
`SUM(LogFile.size_bytes)` from the database, while `/admin/storage` reports what it finds by
walking the disk — uploads *plus* per-job tool output plus anything unowned.

| Page | What it is for | The non-obvious thing |
|---|---|---|
| **Dashboard** `/admin` | Deploy verdict, counts, maintenance actions. Three deep-linkable tabs: `#overview`, `#system`, `#maintenance` | The readiness verdict uses the same checks as the doctor command (`./logstotal doctor:docker` on a Docker host), so the two agree. A few host-level checks (Docker daemon, ports, hardware) run only from the command line, so the command can still fail where the dashboard passes. **Opening the System card never runs the checks** — it shows the result the Overview verdict already computed, and **Re-run checks** is the only thing that starts a new run. Both cards show when that run happened. Results are cached for 5 minutes per web process, so with several web processes each keeps its own |
| **Tasks** `/admin/tasks` | Everything the workers are doing, waiting to do, or scheduled to do. Three tabs: Activity, Queue, Scheduled | The **Queue** tab shows the broker queue *and* the schedule; a deferred re-run or a webhook retry sits in the second, which is why an idle-looking queue does not mean an idle worker. A row stuck at `running` with "no worker reporting" has lost its worker — **Recover** closes it. Cancelling a backfill takes effect at its next batch boundary (batches of 100–500 rows), and every item it had already finished is kept — the expensive backfills commit per item, not per batch. **Run again** starts a *new* row; the failed one is never overwritten. Queueing one that is already running hands back the run in flight instead of starting a second copy |
| **Users** `/admin/users` | Create, set password, change role, activate, delete | You cannot demote, deactivate or delete **yourself** — but you *can* set your own password, which is how you clear the default-password banner. Deactivating an account, or demoting it below member, also stops its API tokens and its watch rules (evaluation and webhook deliveries); re-enabling the account brings them back |
| **Workers** `/admin/workers` | Fleet, queue depth, stuck jobs, per-host concurrency cap | "Stuck" means the heartbeat expired. A job whose worker is still heartbeating is *not* stuck — cancel it from the job page instead ([Cancelling a job](../runbooks/workers.md#cancelling-a-job)) |
| **Settings** `/admin/settings` | Instance-wide `SiteSettings` values ([reference below](admin-ui.md#sitesettings-reference)) | Enabling parallel execution warns, non-blockingly, when it would oversubscribe CPU on a live worker |
| **Enrichment** `/admin/enrichment` | External lookup services for Intel entities | The API token is Fernet-encrypted with `ENRICHMENT_ENCRYPTION_KEY` (defaulting to `SECRET_KEY`) — rotating **either** breaks every stored token |
| **AI providers** `/admin/ai` | Language-model endpoints for the job **AI Analysis** tab | Adding a provider is only half the switch — the tab stays hidden until `show_ai_analysis` is on too. **Test** runs a real completion in the web process, so it still diagnoses a provider when the workers are down. **Duplicate** copies an endpoint, token and settings under a free name, which is how you add a second model on the same host without retyping a base URL ([AI analysis](admin-ui.md#ai-analysis)) |
| **API tokens** `/admin/api-tokens` | Bearer tokens for log ingestion, jobs, cases, the IOC feed and TAXII | The plaintext is shown **once**. A token carries its creator's visibility and never more, so mint it as the account whose access you mean to delegate. It stops working while its creator is deactivated or below member, and the activity log names the token (`api token <prefix> for <email>`) on everything it exports |
| **Activity** `/admin/activity` | Who did what, when, and from where | Empty until `activity_log_enabled` is turned on in Settings — and it stays readable after you turn it back off, which is why disabling capture does not hide existing rows. Prune is the way to remove them. The **Reference** id on a 5xx error page matches the `request_id` column, so a user's bug report maps to both a log line and an activity row |

### Token scopes

API tokens are created on `/admin/api-tokens`. Each carries one or more scopes:

| Scope | Grants |
|-------|--------|
| `ioc_feed:read` | `GET /intel/ioc-feed` (CSV / JSON / STIX / MISP) |
| `taxii:read` | The TAXII 2.1 endpoints (only when `TAXII_ENABLED=true`) |
| `case:read` | `GET /intel/cases/list.json`, and per case `detail.json`, `entities.json`, `stix`, `misp`, `ioc-pack` |
| `case:write` | Create cases and link submitted jobs to visible cases |
| `job:submit` | Submit files, list workflows, and recover submission receipts |
| `job:read` | Read grouped job statuses within the creator's visibility |

See [Multiple log files and ingestion API](ingestion-api.md) for the endpoints and examples.

## SiteSettings reference

Instance-wide settings, stored in the database and edited at `/admin/settings`: feature
switches, upload-selection and sample-size limits, and the activity-category list. Enabling
parallel execution shows a non-blocking heads-up when it would oversubscribe CPU on any
live worker host.

| Setting | Default | Effect |
|---------|---------|--------|
| `parallel_execution` | `false` | When true, the worker runs the tools in a workflow concurrently (subject to `TOOL_MAX_WORKERS`). When false, tools run serially. Turn on for fast hosts; leave off for shared infrastructure to keep memory predictable. |
| `max_finding_details` | `10` | How many matched events the UI shows under each finding. Higher = more useful but slower job-detail rendering and bigger HTML. |
| `max_upload_files` | `50` | Maximum files selectable together on the homepage, from 1 to 500. Applies after reloading the upload page. Each file still creates its own job; API submissions, concurrency and per-minute quotas are separate. |
| `show_mitre_heatmap` | `true` | Renders the MITRE ATT&CK heatmap on the job detail page. Disable on small screens or to reduce data exposure. |
| `show_event_timeline` | `true` | Renders the **activity histogram** — hourly bars stacked by MITRE tactic. Each tool's own timezone offset is preserved, so on a multi-tool job the same event can land in two different hours. |
| `show_alert_timeline` | `true` | Renders the **events timeline** — the zoomable per-alert view below the histogram, on jobs and on cases. Normalised to UTC and built from a DB-stored index so it keeps working after `JOB_OUTPUT_RETENTION_DAYS` cleanup (unlike the histogram and the process tree). Disable either or both to hide raw event metadata from non-admins. |
| `show_entities` | `true` | Toggles the Intel/Entities pages and the entities panel on job detail. Disable to hide PII-bearing observables. |
| `show_threat_detection` | `true` | Toggles the Threat Detection panel on job detail (heuristic LOLBINs / encoding / etc.). |
| `builtin_rules_enabled` | `true` | Evaluates the shared rules — `lolbin`, `privileged`, `rfc1918` and the rest listed on `/intel/rules` — which tag matching entities as each job finishes. One switch above the individual on/off toggles on `/intel/rules`, and it gates the *work*: tagging is the only thing in LogsTotal that writes a row per entity per job, so turning it off stops that table growing rather than hiding the result. Existing tags are left in place. |
| `show_process_tree` | `true` | Toggles the Process Tree panel on job detail (parent→child lineage rebuilt from matched process-creation events; needs the job's raw outputs on disk). |
| `render_markdown` | `true` | Renders case notes, entity notes and comment threads as Markdown (headings, lists, links, code). Raw HTML is always escaped and `javascript:`/`data:` links are never emitted, so this is a formatting choice, not a trust decision. Off shows the text exactly as typed. The stored text is untouched either way — flipping it back loses nothing. |
| `demo_mode` | `false` | When true, `POST /upload` and `POST /detect-preview` return **403** and the submission page shows a read-only notice. Nothing else is affected — existing jobs, admin actions and destructive operations all behave normally. For public read-only demo instances. |
| `show_ai_analysis` | `false` | Renders the **AI Analysis** tab on job pages, where a member sends one job's findings to a configured language model. Off by default because it does nothing without a provider on `/admin/ai`, and because a hosted provider means job data leaves the instance — see [AI analysis](admin-ui.md#ai-analysis) and [AI job analysis](../security.md#ai-job-analysis). Turning it off hides the tab and refuses new runs, including any still waiting in the queue; existing runs are kept. |
| `show_ai_prompt` | `true` | Keeps the exact brief each AI run sends and shows it to administrators beside the run log, so "what actually left this instance?" is answerable rather than inferred. It gates **storage**, not only display: off means the prompt is never written and prompts already kept are hidden, which is the only reading worth anything if you are turning it off for data-handling reasons. Bounded by the provider’s job or case prompt limit, falling back to `AI_MAX_PROMPT_CHARS`. |
| `activity_log_enabled` | `false` | Records who did what into the [Activity log](admin-ui.md#activity-log) — sign-ins, administrative changes and every export that moved data off this instance, with the actor's email and client IP. Off by default because storing that is a data-handling decision, not a default. It gates **writes only**: turning it off stops new rows but keeps what was already recorded, since the reason to disable an audit trail is usually "stop collecting", for which Prune is the answer rather than concealment. Retention is `ACTIVITY_RETENTION_DAYS`. |
| `activity_categories` | `null` | Which of `auth`, `admin`, `job`, `intel`, `discussion`, `export` are captured, as a CSV. `null` or empty means all six. Unticking a category stops those events being *written*, not just hidden. |

### Retention overrides — edited on `/admin/storage`

These are `SiteSettings` columns too, but they are not on the settings form: retention
belongs beside the usage figures that motivate changing it.

| Setting | Default | Effect |
|---------|---------|--------|
| `job_output_retention_days_override` | `null` | Overrides `JOB_OUTPUT_RETENTION_DAYS` for the daily output sweep and the manual run. `null` means the environment variable applies, which is how you get back to "whatever `.env` says" without remembering what that was. The page shows the effective value **and its source**, and the sweep uses the same value the page shows. |

Settings take effect on the next request — no restart needed.

## Comment threads

Cases, entities and jobs carry discussion threads. Deletes are **soft**: the body is blanked at once, so the text is genuinely gone, but the row survives as a record of who removed what. A daily prune deletes those tombstones after 180 days (see [Storage and retention](../runbooks/storage.md#automatic-row-retention)); comments that were not deleted are kept. Deleting a case, a job, or an orphaned entity removes its comments along with it.

Threads render the newest 100 comments and report the true total above them; older comments stay in the database and are reachable only via the DB.


## The jobs list

Analyst-facing behaviour is documented in the in-app guide at `/docs`. What matters
operationally:

- **`?q=` compiles entirely to SQL**, unlike the Intel grammar, so the pager's totals are
  exact. A term that cannot be parsed matches nothing and is reported above the table.
- **`?tags=` and `?q=tag:…` merge** rather than one winning, and tags are any-of throughout:
  a second tag widens the net.
- **Completions are visibility-filtered**, and `id:`/`sha256:` are never completed — a list
  of job numbers or file hashes would enumerate what those terms are careful not to leak.
- **The Compact/Roomy view and rows per page are remembered per browser** in the
  `logstotal_jobs_view` and `logstotal_jobs_per_page` cookies; `?view=` and `?per=` override
  them for one link. Rows per page is 20, 50 or 100; anything else falls back to 20.
- **Newest first.** Jobs created in the same second — a multi-file upload creates them in
  bursts — are ordered by id, so a page boundary never repeats or skips a job. A page
  number past the end shows the last page.

### Job tags

Jobs carry the **same analyst tag vocabulary** entities do — the same names and colours —
managed at `/intel/tags`, where a rename, merge, recolour or
delete reaches jobs and entities alike. Applying a tag is **member-and-above**: it writes to
the instance-wide vocabulary, so the one role with no Intel access cannot reshape it. The cap
is ten tags per submission.

One exception to "reaches everything": a tag a **live shared rule** re-applies cannot be
**merged**, in either direction. Folding it away is undone by the next matching job — history
ends up under the new name while the rule keeps minting the old one — and folding another tag
into it labels entities the rule never matched; neither is recoverable, since the rows carry
no record of which name they arrived under. Such rows are marked *shared rule* in the manager
and their Merge button is disabled. Rename, recolour and delete are still offered: equally
undone by the next job, which the mark says, but reversible. Switch the rule off on
`/intel/rules` — or the whole set with `builtin_rules_enabled` — and the tag becomes ordinary
and merges like any other.

No pruning job: one small row per (job, tag), removed with the job.

### Job watch

Any logged-in user can watch a job and be notified when someone comments on it, someone tags
it, or an AI analysis on it finishes or fails. Notifications land in the nav bell alongside
rule alerts. Admins see every *rule* but only their **own** watches, so
"Acknowledge all" clears one person's notifications and never the instance's. A watcher who
can no longer see a job — because it was made private — stops hearing about it.

To receive job-watch events over HTTP, tick **"Also send my job-watch events here"** on one
of your rules at `/intel/rules`; at most one rule per person may carry them.
Deliveries reuse that rule's URL, secret, rate limit and retry backoff, and are sent with
`X-LogsTotal-Event: job.watch` and an `entities` list that is present but empty, so a
receiver written for `rule.match` does not break.

**Known limit:** if Redis is down when a notification is written, the bell entry is still
correct but its webhook is lost and never retried. There is no reconciler.


## Investigation cases

Members group jobs and entities into cases at `/intel/cases`. A case owns no data of its
own — only links, a narrative note and a discussion thread.

**Visibility** matches saved searches: owner-only unless marked **shared**, in which case
every member sees it. Admins see all cases; only the owner or an admin can delete one.

**Deleting a case** removes its link rows, per-link notes and comments. It never touches the
jobs or entities themselves, which other cases and the dashboard still reference.

**No pruning job.** Cases accumulate until somebody deletes them, at a handful of small rows
each. Closing one (`status: closed`) hides it from the default list without deleting anything.

**Cost to watch:** the Timeline tab re-reads every linked job's raw output to build its
merged histogram. Buckets are cached in Redis per job for 15 minutes, so the first view of a
large case is the slow one. See [Known limitations](../limitations.md#scale).


## Saved searches

Members save Intel dashboard filters at `/intel`. A saved search stores the filter state,
not its results. Visibility matches cases: owner-only unless marked shared, and a shared one
is visible to every member. No pruning job, no per-user cap, one small row each.


## Rules

Members create their own rules at `/intel/rules`, a top-level destination beside Tags. A
rule is criteria in a search language plus what to do when it matches. "Watch" means only
the job subscription described above. In the activity log, rule events are recorded under
`intel.watch_rule.*` action keys.

**Not the SIGMA detection rules.** Those live in a workflow and decide what a finding *is*.
These run after an analysis finishes and decide what happens next.

**Two scopes.** A rule's criteria are written against one of two things, and the form's
*Criteria are about* selector picks which:

| Scope | Grammar | Matches | One alert per | Tags |
|---|---|---|---|---|
| Entities | the Intel dashboard's `?q=` | each matching entity in the finished job | (rule, entity, job) | the entity |
| Jobs | the jobs list's `?q=` | the finished job itself, once or not at all | (rule, job) | the job |

Both reuse the filter builder the corresponding list uses, so what you searched is what
alerts. A job rule is a single-row test — it matched or it did not — so it needs no match
cap; viewer-relative terms (`is:mine`, `is:watched`) are read from the rule's owner, and
terms that only make sense mid-run (`is:running`) simply never match a finished job. `job:`
is refused in an *entity* rule and does not exist in the jobs grammar at all.

**Three actions, each independent.**

| Action | Switch | Effect |
|---|---|---|
| Auto-tag | a non-empty Auto-tag field | Applies those tags to every match. The names join the shared vocabulary when the rule is **saved**, not when it first fires |
| Alert | "Raise an alert in my bell" | An alert the nav bell counts until acknowledged |
| Webhook | "Send deliveries for this rule" | One signed POST per (rule, job) |

Untick the alert and the rule keeps tagging and delivering; the row shows it as *silent*.
A rule with the alert off but a webhook on still records its matches — deliveries are built
from them, and they stop a re-run delivering twice — but marks them acknowledged, so
nothing reaches a bell. A rule that neither alerts nor delivers records no matches at all;
re-running a job never tags the same entity twice.

A rule applies the vocabulary's own colour to a tag that already exists, and its own swatch
only to a name nothing has used yet, so a rule firing in the background cannot repaint an
analyst's palette.

### Writing one

The **Condition** field is the rule. It highlights the grammar as you type, completes
`list:`, `tag:` and the rest against what this instance actually has, and reports underneath
how many entities (or jobs) the condition matches *right now*. **Test against recent jobs**
answers the question that number does not: how many alerts this would have raised over the
last 25 finished runs — written nowhere, so it is safe to try. It sees only jobs you could
open, so it cannot report on someone else's private submissions.

It is a multi-line field and a newline is simply whitespace to both grammars, so a long
condition can be laid out one term per line. All terms must match either way.

A save that is refused leaves the form exactly as you typed it and lists **every** reason
above the buttons — a condition naming a list that does not exist, a webhook URL that is not
a URL, extra headers that are not a JSON object. Nothing is written until all of them pass.

**Edit** opens a rule's form in place. Toggling a rule on or off, or testing a webhook,
updates only that control, so a form you have open elsewhere on the page is kept.

### Shared rules and lists

`lolbin`, `privileged`, `rfc1918` and fourteen more labels ship as **shared rules**: the same for every
member, seeded from `rules/builtin.yml`, listed on `/intel/rules` under **Shared rules**.
Each has a condition written in the entity search grammar — `list:lolbas`,
`cidr:10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`, `re:/^[0-9a-f]{32}$/` — and adds the tag
`<key>` to what it matches. Every condition is written in the grammar, so every shared rule
can be read and changed on the page; nothing ships that points at logic living in code. The
entropy-based DGA heuristic is therefore not a rule — it stays a computed attribute
(`attr:dga`) you can search for or build your own rule on. An admin edits a shared rule with
the same form analysts use for their own: condition, tags, switch it off.

**Beside the labels, the analyst rules.** Sixteen more entity rules and three job rules
ship for CTI/DFIR triage, all silent tags: offensive tooling, remote-access tools and
staging tools by file name (three lists); scripts and odd extensions on command lines;
services and scheduled tasks from user-writable paths or running a script host, and encoded
or hidden commands; built-in accounts and anonymous logons; dynamic-DNS, tunnel and
file-sharing domains (two lists); hosts named like domain controllers. `lookalike` ships
switched off until its exclusions are tuned. The job rules tag a finished analysis
`needs_triage` (a critical or high finding nobody tagged `reviewed`), `rerun` (a partial
run) or `clean` (no findings). They are shared rules like the labels: silent, under the same
site switch, and applied to private jobs too.

**Lists.** The sets a condition tests with `list:<name>` — LOLBAS names, GTFOBins names,
suspicious TLDs, and whatever you add — live in the **Lists** section of the same page,
seeded from `rules/lists.yml`. A list matches the *whole value* or a value that *ends with*
an entry (the TLD list), compared case-insensitively. An admin edits the values one per
line, creates new lists, and deletes a list nothing names; a list a rule still tests is
refused. These are the rules' own copies: `config/threat_detection.yaml` carries the
detection pipeline's sets separately, and the two may drift by choice.

**Loaded at start, edited in the UI.** The app reads `rules/*.yml` every time it starts
(`./logstotal sync-rules` does the same on a development checkout) and applies one policy:
**the file updates what nobody edited**. Every seeded rule and list remembers what it was
seeded with; at the next start a row still equal to that takes the file's newer version,
and a row an admin edited is left alone. Switching a rule off is not an edit. A rule a
release no longer ships is retired on the same terms — removed if nobody edited it, kept if
an admin made it theirs; the tags it wrote stay. So a release's fix to a shared rule
reaches every instance that did not touch it, and an admin's change survives every
restart.

**Download and Import.** The Rules page speaks the seed files' format. **Download YAML**
gives a member their own rules and an admin the shared rules (with their `key`) and the
lists as well; **Import YAML** reads the same document back, pasted or uploaded. It is all
or nothing — one bad rule imports none, and the reasons are listed beside the form. A
member's import matches their rules by name and updates them in place; new ones count
against their limit. An admin ticking *Import rules as shared rules* matches by `key`,
creating or updating ownerless rows that tag every job like the shipped ones; lists in a
document are always shared and only an admin can import them. An imported rule or list is
treated as edited from then on. The webhook signing secret is never exported and cannot be
imported.

**Shared rules write stored tags**, which is what makes them editable. Three consequences:

* **Tags are written as jobs finish.** Entities already in the database carry none of a
  rule's tags until you run the **Built-in labels** backfill
  (`POST /admin/backfill-builtin-labels`) from the Maintenance tab.
* **They can go stale.** Edit a list or a condition and the tags already written do not move
  on their own. Run that backfill again. No shipped rule tests an `attr:` term; a condition
  you wrote with one also needs the entity-attributes backfill first.
* **They grow the tag table.** Roughly one row per (entity, applicable rule). It is the only
  thing in LogsTotal that writes a row per entity per job; `builtin_rules_enabled` is the
  one switch that stops it.

The `attr:` facts are separate from these tags. `attr:lolbin` filters on attributes computed
for each entity, and the entity Overview tab's **Attributes** card shows them fresh on
every render. Where the card and the tags disagree, the gap is the answer: a backfill that
has not run, a rule somebody edited or turned off, or a tag somebody deleted.

### Before you turn one on

Two answers, and they are different questions. The **preview** under the criteria box
updates as you type and says how many entities (or jobs) match *right now* — cheap, and
enough to tell you the syntax is doing what you meant. **Test against recent jobs** runs the
criteria over the last 25 finished jobs you can see and reports how many alerts it would
have raised across how many jobs. Nothing is written: no alert, no tag, no timestamp.

That second one is the question people get wrong. A rule matching six hundred entities
across twenty-five jobs is a rule you want silent — tagging, maybe delivering, but not in
your bell.

### Jobs you watch

Listed on `/intel/rules` under **Jobs you watch**, alongside the rules. It is the same list
`/jobs` shows under its Watching tab; that tab exists too because it is open to any
logged-in user, while `/intel/rules` is member-and-above.

### When rules run

Rules run as each analysis finishes, right after its entities are saved. A rule that fails
is logged and skipped: the job is already finished, and a rule never changes its outcome.

**What they cost.** One query per enabled rule, already narrowed to that job's entities,
so the cost grows with the number of rules, not with rules × entities. These limits bound a
bad day; the first two are logged when hit:

| Limit | Value |
|---|---|
| Entity rules evaluated per job, oldest first | 200 |
| Job rules evaluated per job, oldest first | 100 |
| Matches recorded per entity rule per job | 100 (5,000 for a shared rule, which only tags) |
| Rules one account can own, both scopes together | 50 (`WATCH_RULES_MAX_PER_USER`) |

The two evaluation limits are separate budgets, so an instance with more than 200 entity
rules still evaluates its job rules.

**Alerts are per-user.** An alert belongs to its rule's owner, so acknowledgement is per
user. Re-running a job raises no duplicates: uniqueness on (rule, entity, job) and on
(rule, job) guarantees it. "Acknowledge all" clears both kinds — a sweep that left half the
badge behind would give the reader no way to tell which half.

**A rule never sees a job its owner could not open.** Private jobs are skipped for rules
owned by anyone but the submitter or an admin, which is what stops a broad rule becoming a
cross-user exfiltration channel — see [Rule webhooks](../security.md#rule-webhooks).

**Webhook deliveries** carry `X-LogsTotal-Event` as the discriminator: `rule.match` for an
entity rule, `job.match` for a job rule, `job.watch` for the job-watch events described
above, and `rule.test` for the Test button. Every shape keeps an `entities` list — empty
where there is nothing to put in it — so a receiver written against one does not break
on another. They are one POST per (rule, job) carrying up to 50 entities, retried with
60s/120s/240s backoff on network errors, timeouts and 5xx (4xx other than 429 is terminal).
Every attempt is recorded and shown on the rule owner's **Deliveries** tab. Attempts older
than `WEBHOOK_DELIVERY_RETENTION_DAYS` (default 30) are pruned daily — see
[Storage and retention](../runbooks/storage.md#automatic-row-retention).

The star means "somebody is watching this" — a derived flag read by the graph highlight,
the star column, `sort=watchlist` and the IOC feed. It clears when the last rule watching an
entity goes away.


## AI analysis

Providers have separate **Job max prompt size** and **Case max prompt size** fields, in
characters (1–2,000,000). Blank fields inherit `AI_MAX_PROMPT_CHARS` (default 60,000).
Each limit bounds the evidence brief; the system prompt is separate. New providers default
to **20,000 max output tokens**.

The **AI Analysis** tab sends a job's findings to a language model and stores the written
assessment. It is **off by default** and takes two admin-only steps to turn on:

1. **Add a provider** on `/admin/ai` — kind (`OpenAI-compatible` or `Anthropic`), base URL,
   model name, and an API token if the endpoint needs one. Click **Test**: it runs a real
   one-word completion in the web process and reports the failure directly, so it still
   diagnoses a provider on a deployment whose workers are down. Fix the configuration until
   it passes, *then* enable the tab.
2. **Enable `show_ai_analysis`** on `/admin/settings`. Until it is on, the tab does not
   render for anyone, even with a working provider.

**A worker must be running.** Inference happens in the worker, not the web process. With no
worker consuming the queue, the pane sits at *Queued — waiting for a worker* until
`HUEY_QUEUE_EXPIRY` discards the task, and the run then stays pending with nothing to move
it. If runs never start, check `/admin/workers` before touching the provider config.

**Runs are history, not a cache.** Every click adds a run and nothing overwrites or expires
it — there is no prune job, and storage grows by one small row per click (deleting a job
removes its runs). Deleting a *provider* does not delete its runs: the
provider name and model are snapshotted per row, so past analyses stay readable and
attributed.

**Stopping a run.** *Stop* appears on a queued or running analysis, for an admin or whoever
started it.

| State | Effect |
|---|---|
| Queued | Marked cancelled immediately; the worker drops the task when it reaches it |
| Running, worker alive | The worker closes the connection to the provider and records the cancellation, usually within a couple of seconds |
| Running, worker gone | Marked cancelled immediately, because nothing is left to act on the request |

Dropping the connection is what makes the provider stop working, so a stopped run stops
costing money or GPU rather than merely disappearing from the page. Cancelled is its own
status, not a failure, and no answer is saved.

**A run that never reported back.** The worker publishes a heartbeat for the duration of a
run. If a worker is restarted mid-inference the heartbeat lapses and the pane says *This run
never reported back*; **Stop** closes the row off so the job's history is not left with a
permanently in-flight entry.

**Several models on one endpoint.** **Duplicate** on `/admin/ai` copies a provider — base
URL, token, system prompt, temperature, timeouts — under a free name (`Ollama (copy)`).
Change the model and rename it. The copy is never the default, since only one provider holds
that and a copy claiming it would demote the original.

**Reviewing what was sent (admin only).** With `show_ai_prompt` on (the default), each run
keeps the exact brief it sent, readable under **Show prompt sent**. The switch governs
**storage**, not just display: turning it off stops the prompt being written *and* hides
prompts already kept — which is the behaviour you want if you are turning it off for
data-handling reasons.

**The run log (admin only).** Every run records a timestamped trace — brief size and
findings omitted, provider, base URL and model, when the request went out, when the first
tokens came back, how much text has arrived. It is written as the run happens, so it answers
"is this working?" about a run in flight. Admin-only because it names the provider's base
URL, and capped by `MAX_LOG_OUTPUT_BYTES`, keeping the tail. On a local model most of the
wait is prompt processing before the first token, which the log shows as a gap after
*Sending request*.

**Who can do what.** Starting a run is member-or-above, rate-limited per user by
`AI_RATE_LIMIT_PER_MINUTE` (default 10). Reading a finished one is open to anyone who can
view the job — on a public job, that means a public answer. Deleting a run is permanent, and
an in-flight run must be stopped first.

**Cost and failure.** A run is not retried: every failure it can produce — wrong model name,
unreachable base URL, expired token, output-token limit — is a configuration problem a retry
repeats rather than resolves. The error lands on the row and is shown in the pane. The
request is streamed and `timeout_seconds` is enforced as wall-clock across the whole read
rather than per network operation, so a gateway emitting keep-alive traffic cannot hold a run
open indefinitely. Before pointing this at a hosted API, read
[AI job analysis](../security.md#ai-job-analysis) — a run ships findings, entities and sample
event fields to a third party.


## Backfills

All of these are POST-only, return immediately, and run in the worker. Each appears on `/admin/tasks`, where you can follow it. Buttons for all of them live on the **Maintenance** tab of the `/admin` dashboard (`/admin#maintenance`), which shows a live inline status chip for each task you start.

| Trigger | What it does | When to run |
|---------|--------------|-------------|
| `/admin/backfill-similarity` | Computes the fuzzy (TLSH) hash for any uploaded file without one, and the cross-job rule signature for any finding without one | When similar-file or rule pivots are missing for older jobs, for example after restoring an old database |
| `/admin/backfill-analytics` | Recomputes per-job `analytics_json` for every terminal job | After changing `config/analytics_fields.yaml` or the analytics extractor. Restart the worker and the web app first: each process reads that file once, so a backfill run before the restart recomputes with the old fields |
| `/admin/backfill-entities` | Builds the entity list and each entity's job links from each job's analytics | After enabling `show_entities` on a database that already has jobs |
| `/admin/backfill-entity-attributes` | Recomputes each entity's derived attributes (private IP, LOLBIN, DGA-like domain, …) | After changing `config/threat_detection.yaml` — restart the worker and the web app first, since each process reads that file once |
| `/admin/backfill-builtin-labels` | Applies every enabled shared rule to every existing entity | After enabling or editing a shared rule, or editing a list: tags already written do not move on their own. Shared rules test their lists, not `config/threat_detection.yaml` |
| `/admin/backfill-relationships` | Re-parses raw job output to extract typed entity relationships and their per-job evidence | When relationships are missing for older jobs (needs their raw outputs still on disk) |
| `/admin/backfill-finding-entity-links` | Rebuilds the lookup between findings and the entities they mention | When an entity's findings are missing, for example after restoring an old database |

### Expected duration

**It tracks raw-output size, not job count**, because the work is a re-parse of each job's
tool output. Similarity is the cheap one — a TLSH digest per uploaded file. Size your
expectations from `/admin/storage`'s output total rather than from the job count.

They run in the same worker pool as analysis jobs, so a backfill will slow new uploads until
it finishes. It will not block the web tier: each one commits per item rather than per batch,
which is what keeps SQLite's single writer available to the application while it runs.

### Recovery on failure

A backfill marked `failed` on `/admin/tasks` shows its error there. Run it again — backfills are idempotent (they skip records that are already populated). If a backfill keeps failing, check `./logstotal docker:logs:worker` on the host for the underlying exception.


## Activity log

Off by default. Turn it on with `activity_log_enabled` on `/admin/settings`; it takes
effect on the next request, with no restart.

**What it records.** Sign-ins (including failures, with the account that was attempted —
never the password), user administration, configuration changes, workflow edits, maintenance
actions, job lifecycle events, analyst work in Intel (tagging, rules, alert
acknowledgement, allowlisting, case deletion), discussion activity, and every export that
moved data off the instance: the IOC feed, STIX, MISP, TAXII, case exports, findings JSON
and the raw output ZIP. Each row carries the actor's email, their client IP, the target, the
outcome, and the request id.

**A workflow edit records which fields changed, not the YAML.** A workflow decides which
tools run, against which rules, and — through `extra_args` — with which raw CLI flags, so
"who changed the tasks on the Windows workflow, and when" is worth keeping. The definition
itself is already stored on the workflow; copying it into every audit row would be both
enormous and a second, unmanaged copy of it.

**A bulk action is one row, not one per item.** Tagging two hundred entities, or
acknowledging every alert, records a single event carrying the count. One row per item
would bury everything else in the log under the fastest action in the application.

**Six categories**, each of which can be captured or suppressed on its own from
`/admin/settings`: `auth`, `admin`, `job`, `intel`, `discussion`, `export`. Unticking one
stops those events being *written*, not merely hidden. `discussion` is separate rather than
folded into `job`/`intel` because one thread serves cases, entities and jobs alike — and
because it is the most privacy-sensitive of the six, so suppressing it should not cost you
the administrative trail.

**Comment text is never recorded** — only that a comment was posted, edited or deleted, by
whom, and on what. Duplicating analyst prose here would be a second, unmanaged copy of the
thing a comment's soft delete exists to remove properly. A deletion does note when the
comment belonged to somebody else, since an admin or case owner removing a colleague's
words is the case that record exists for.

**A settings change records the fields that changed**, old value to new. Every value in
that table is a boolean or a small integer, so no secret can reach the log.

**Reading is never gated.** Turning capture off stops new rows; it does **not** hide the
ones already recorded — unlike `show_ai_prompt`, which does hide what it stored. To remove
history you already have, use Prune.

**Exporting.** Both **CSV** and **JSON**, and both carry whatever filter the page is
showing. Use JSON when the detail matters: CSV flattens the `metadata_json` column into an
unreadable string, so the changed-field diff on a settings save — the single most useful
thing recorded here — survives the export only in JSON. Both are capped at 10,000 rows and
the JSON payload sets `truncated` when the cap bit.

**Removing rows.** A daily sweep drops anything older than `ACTIVITY_RETENTION_DAYS`
(default 90; `0` keeps forever) — see
[Storage and retention](../runbooks/storage.md#automatic-row-retention). **Prune…** on the page does the same immediately for a
window you choose, and records that it did — pruning an audit log is itself an auditable
act.

**Correlation.** The **Reference** id shown on a 5xx error page is the same string as the
`request_id` column and the `request_id` field on every log line from that request. A user
reporting "it broke, here's the code" gives you both halves at once.

**What it is not.** It is a record of actions taken *through the application*, not a
tamper-proof ledger: an administrator with database access can edit it, and it is stored in
the same database as everything else. Ship it to a log collector with `LOG_FORMAT=json` if
you need an append-only copy.

---

**Related:** [Configuration](../configuration.md) · [Security](../security.md) · [Storage and retention](../runbooks/storage.md) · [Worker operations](../runbooks/workers.md) · [Docs index](../README.md)
