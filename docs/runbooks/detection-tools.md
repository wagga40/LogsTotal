# Detection tools and workflows

Which detection engines LogsTotal runs, how to keep them and their rules current, and how workflows combine them.

## Detection tools

| Tool | Runs as | Log types | Output |
|------|---------|-----------|--------|
| [Zircolite](https://github.com/wagga40/Zircolite) | **Docker image**, pinned by digest in `workflows/*.yml` | EVTX, JSON EVTX, Winlogbeat, Windows Event XML, Auditd, Sysmon for Linux, Journald | JSON array |
| [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw) | Binary | EVTX | JSONL |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | Binary | EVTX | JSONL |
| [ChopChopGo](https://github.com/M00NLIG7/ChopChopGo) | Binary | Auditd, Syslog | JSON (stdout) |

Chainsaw, Hayabusa and ChopChopGo ship as binaries under `tools/`, with their rule sets, so an installation can analyse Windows and Linux logs without downloading anything. There is no macOS build of ChopChopGo.

Zircolite is the only tool that runs as a container. The worker needs a reachable Docker daemon, and pulls the image (about 500 MB) the first time a job needs it, inside that job; pre-pull it on a slow or metered link. The image is pinned by digest, so an upstream rebuild cannot change what runs on a worker that has access to the Docker socket — see [Moving the Zircolite image pin](#moving-the-zircolite-image-pin).

Each workflow task sets its own `tool_path`, `docker_image` and `rules_path` — see [Workflows](#workflows).

### Linux log types

| Log type | Engine | Notes |
|----------|--------|-------|
| Auditd | Zircolite `-AU` | Emits one row per audit record with the native field names, which drive entities and relationships. ChopChopGo's auditd mode merges records and matches type-specific rules unreliably, so the shipped auditd workflow does not use it. |
| Syslog | ChopChopGo `-target syslog` | Zircolite does not parse free-form syslog. |
| Sysmon for Linux | Zircolite `-S` | Uses the Linux rule set. |
| Journald | Zircolite `-j` with field aliases | **Partial coverage.** ChopChopGo reads only the live journal, not an uploaded file, so it is not used. Zircolite reads a `journalctl -o json` export, and `tools/zircolite/rules/zircolite_journald.yaml` maps `_EXE`, `_CMDLINE`, `_COMM`, `_HOSTNAME` and `_UID` to the field names the Sysmon and auditd rules expect. Rules that need fields journald does not record (parent process, hashes, network details) cannot match. |

ChopChopGo reads its field mappings from `tools/chopchopgo/mappings/` and a subset of the SigmaHQ Linux rules from `tools/chopchopgo/rules/`. Its target (`syslog` or `auditd`) follows the job's log type; a task can override it with `target`.

Zircolite tags events that carry no host name with `host: "offline"`. LogsTotal ignores that value, so it never becomes a `computer` entity.

### Windows Event XML

Exports come in two layouts: a bare sequence of `<Event>` elements (`wevtutil qe /f:xml`) and a document with an `<Events>` root. Zircolite needs a different option for each, so LogsTotal inspects each file and picks the right one. Do not put `-x` or `--evtxtract-input` in a task's `extra_args`: an explicit input option overrides that choice, and the wrong one parses a fraction of the file while still reporting success.

## Checking for updates

A stale rule set does not announce itself: it reports a clean job. Check how current the tools and rules are with:

```bash
./logstotal tools:check
```

It compares each engine's version and each rule snapshot's commit with upstream, verifies the installed binary and rule checksums, and reports the upstream date of each snapshot. It changes nothing, so it is safe on a production host; it needs internet access.

- **A new major version is reported as BREAKING, not as an update.** These tools rename commands and options between major versions, and LogsTotal builds their command lines, so a major version needs testing before use. `./logstotal tools:update` refuses one unless you add `--allow-major` after the tool name (`./logstotal tools:update -- hayabusa --allow-major`); it also requires that option when the installed version cannot be read.
- **Rule sets matter more than binaries.** A binary one minor version behind detects the same things; a rule set six months behind does not.
- `./logstotal tools:check -- --strict` exits non-zero when an update is pending, a version is unknown, a file has changed or upstream is unreachable — useful in a scheduled check.

## Updating rule sets

Rule sets are snapshots shipped with each release, not live mirrors: nothing fetches newer rules on its own.

| Tool | Rules live in | Upstream | Refresh with |
|---|---|---|---|
| Zircolite | `tools/zircolite/rules/*.json` (compiled) | [Zircolite rules](https://github.com/wagga40/Zircolite/tree/master/rules) | `./logstotal tools:update -- zircolite` |
| Chainsaw | `tools/chainsaw/sigma/`, `tools/chainsaw/rules/`, `tools/chainsaw/mappings/` | [SigmaHQ](https://github.com/SigmaHQ/sigma), [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw) | `./logstotal tools:update -- chainsaw` |
| Hayabusa | `tools/hayabusa/rules/`, `tools/hayabusa/config/` | [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) | `./logstotal tools:update -- hayabusa` |
| ChopChopGo | `tools/chopchopgo/rules/`, `tools/chopchopgo/mappings/` | [SigmaHQ](https://github.com/SigmaHQ/sigma) Linux rules | `./logstotal tools:update -- chopchopgo` |

`./logstotal tools:update -- <tool>` (one or more tool names) downloads the latest release binaries, rules and matching mappings or configuration. Each download must match the SHA-256 digest GitHub publishes for it, the expected executable name and the right architecture; if anything fails, the command exits non-zero before replacing any of that tool's files. The previous files are kept under `backups/tools-<tool>-*/`, and the installed versions are recorded in `tools/<tool>/upstream.json`. For Zircolite it refreshes the compiled rules only (keeping `zircolite_journald.yaml`); the container image is moved separately.

Run updates while no job is running, then check each tool against real logs before relying on it: upload the [sample logs](https://github.com/wagga40/LogsTotal/blob/main/samples/README.md) and compare the findings with those from before the update. On larger logs compare the matched events as well as the rule names — an upstream fix can move an event to a more specific rule without losing the detection.

The containers run the files built into the image, so apply an update with `./logstotal docker:up`, which rebuilds the image and restarts the services. A fleet worker runs its own copy: update the tree you deploy from and deploy it again with `./logstotal deploy`.

> [!NOTE]
> An upgrade of LogsTotal replaces `tools/` with the release's copy, including any rules you edited there. Keep your own rules out of that directory (below).

To run existing jobs against new rules, **Resubmit** them from the job page. Existing findings are not re-evaluated.

### Keeping your own rules

Put your rules outside the install directory and point the task's `rules_path` at them in `workflows/*.yml`. Each task has its own `rules_path`, so you can move one tool and leave the rest. On Docker the path must also exist inside the worker container: mount it with a Compose override file.

```yaml
tasks:
  - tool: hayabusa
    tool_path: tools/hayabusa/hayabusa-intel-lin
    rules_path: /srv/sigma/hayabusa-rules/    # outside the install — upgrades leave it alone
```

### Moving the Zircolite image pin

The container is pinned by digest so that an upstream rebuild cannot change what runs on a worker with access to the Docker socket. To move it, on a machine with Docker:

```bash
docker pull wagga40/zircolite:<new-version>
docker inspect --format='{{index .RepoDigests 0}}' wagga40/zircolite:<new-version>
```

Put that `repo@sha256:…` in every `docker_image:` line in `workflows/*.yml`, keeping the `:<version>@` form so the tag stays readable, then load the workflows again (see [Workflows](#workflows)). Test the new image before relying on it.

## Workflows

A workflow is a list of tools to run against a log file. Manage workflows on `/workflows`, or in the YAML files under `workflows/`.

The web service loads every `workflows/*.yml` into the database each time it starts, matching on the workflow's `name`. On Docker the files are built into the image, so after editing one run `./logstotal docker:up` to rebuild and restart. On a development checkout, `./logstotal sync-workflows` loads them without a restart.

> [!IMPORTANT]
> A workflow edited on `/workflows` whose name matches a file under `workflows/` is overwritten from that file the next time the web service starts. To keep an edit made in the browser, save it under a new name, or make the same change in the file.

An excerpt from the shipped `workflows/windows_full.yml`:

```yaml
tasks:
  - tool: chainsaw
    tool_path:                                    # per-architecture binaries
      x86_64-linux: tools/chainsaw/chainsaw-intel-lin
      aarch64-linux: tools/chainsaw/chainsaw-arm-lin
      aarch64-darwin: tools/chainsaw/chainsaw-mac
    rules_path:                                   # a list: one --sigma per entry
      - tools/chainsaw/sigma/rules
      - tools/chainsaw/sigma/rules-emerging-threats
      - tools/chainsaw/sigma/rules-threat-hunting
    timeout: 300                                  # per-task execution timeout in seconds
    threads: 2                                    # CPU threads for this tool
  - tool: zircolite
    # Runs as a container; pinned by digest (see "Moving the Zircolite image pin").
    docker_image: wagga40/zircolite:4.0.0@sha256:552f1900fb5533a58fdad1ae61f46c09018271787d5d7a2d08cb318d3221461f
    rules_path: tools/zircolite/rules/rules_windows_merged.json
    timeout: 300
```

> [!NOTE]
> **Name Chainsaw rule directories individually.** `tools/chainsaw/sigma/` holds five SigmaHQ rule sets: `rules`, `rules-emerging-threats`, `rules-threat-hunting`, `rules-dfir` and `rules-compliance`. The shipped workflow uses the first three; add the others to `rules_path` if you want them. Chainsaw loads a directory recursively, so pointing `rules_path` at `tools/chainsaw/sigma/` itself would load all five at once. The deprecated and unsupported SigmaHQ sets are not shipped.

### Task keys

| Key | Meaning |
|-----|---------|
| `tool` | `zircolite`, `chainsaw`, `hayabusa` or `chopchopgo` |
| `tool_path` | Path to the binary: a string, or a map keyed by `{arch}-{os}` (`x86_64-linux`, `aarch64-linux`, `aarch64-darwin`). A task with no entry for the host's architecture is skipped with a message instead of failing the job |
| `docker_image` | Run the tool from this container image instead of a binary. The shipped Zircolite tasks use it. Takes precedence over `tool_path` if both are set |
| `dockerfile` | Build the image from a Dockerfile instead of pulling it |
| `rules_path` | The rules for this task — a directory or a compiled bundle, depending on the tool. May be a **list** of directories, which Chainsaw turns into one `--sigma` option each. A container-run tool accepts a single path and refuses a list |
| `timeout` | Execution timeout in seconds. The tool's whole process group is killed when it expires |
| `threads` | CPU threads for this tool. **Defaults to 1 when omitted**; the shipped workflows set `2` for Hayabusa and Chainsaw. Zircolite ignores it. See [Scaling](../scaling.md) |
| `target` | ChopChopGo only: `syslog` or `auditd` |
| `extra_args` | Extra command-line options, appended as given |
| `options` | Tool-specific settings, such as Hayabusa's `min_level` or Chainsaw's `status` (passed to `--status`; unset by default, so rules of every status load) |

### Workflow keys

These sit beside `tasks:` and describe the workflow:

| Key | Meaning |
|-----|---------|
| `name` | Display name, and the key the loader matches on: renaming a workflow in its file adds a second workflow rather than renaming the first |
| `description` | Shown beside the name in the upload form, cut to 60 characters |
| `log_types` | The detected log types this workflow accepts. **An empty list accepts every type**, including `unknown`. Also editable on `/workflows` |
| `is_default` | Pre-select this workflow on the upload form. At most one workflow holds it |

### The default workflow

`is_default` decides which workflow the upload form pre-selects, and nothing else: it is not a fallback on the server, and every upload still names its workflow.

It only breaks ties. Dropping a file narrows the list to the workflows whose `log_types` accept the detected type, and the default is chosen from those. The six shipped workflows accept different log types, so the flag matters only once you add a workflow for a type another one already covers.

Ticking it on `/workflows` clears it on every other workflow. Keep `is_default: true` in exactly one file under `workflows/`, because the loader writes the value from each file as it is.

---

**Related:** [Scaling](../scaling.md) · [Upgrade and roll back](upgrading.md) · [Troubleshooting](../troubleshooting.md)
