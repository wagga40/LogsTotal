# Third-party notices

LogsTotal's own source is MIT-licensed ([LICENSE](LICENSE)). It does not stand alone: the
repository **redistributes** compiled detection-tool binaries, Sigma rule sets and
front-end bundles, several of them under copyleft licences whose terms are stricter than
MIT. Those components keep their own licences — the MIT grant in `LICENSE` covers only the
code written for this project.

This file lists every redistributed component, its licence, and where its corresponding
source lives. If you fork, package or ship LogsTotal, these obligations travel with you.

---

## Detection tools

Each tool's upstream licence text is committed alongside its binaries in
`tools/<tool>/LICENSE`.

| Component | Version | Licence | Upstream (corresponding source) |
|---|---|---|---|
| **Chainsaw** | 2.18.0 | GPL-3.0-only | <https://github.com/WithSecureOpenSource/chainsaw> |
| **Hayabusa** | 4.4.0 | AGPL-3.0-only | <https://github.com/Yamato-Security/hayabusa> |
| **ChopChopGo** | 1.1.0 | GPL-3.0-only | <https://github.com/M00NLIG7/ChopChopGo> |
| **RSigma** | 0.28.0 | MIT | <https://github.com/timescale/rsigma/tree/v0.28.0> |
| **Zircolite** | 4.8.0, image `wagga40/zircolite` | LGPL-3.0-only | <https://github.com/wagga40/Zircolite> |
| **Tailwind CSS CLI** (standalone, build-time only) | 3.4.19 | MIT | <https://github.com/tailwindlabs/tailwindcss> |

**Binaries under GPL-3.0 and AGPL-3.0 carry a corresponding-source obligation.** The
binaries in `tools/chainsaw/`, `tools/hayabusa/` and `tools/chopchopgo/` are unmodified
upstream release artifacts; the complete corresponding source for each is the tagged
release at the URL above. Anyone who receives a copy of this repository, or an archive or
container image built from it, is entitled to that source under the same terms.

Zircolite is **not** vendored as a binary — the default workflows run it from the
`wagga40/zircolite` container image at analysis time (see
[docs/installation.md](docs/install/prerequisites.md)). Only its rule sets are committed here.

Nothing under `tools/` is linked into, or derived from, LogsTotal's own code. The tools are
executed as separate processes over a command-line interface, and LogsTotal parses their
output. That is why the MIT licence on this project's code and the copyleft licences on
those binaries coexist rather than conflict.

## Command runner

| Component | Version | Licence | Upstream |
|---|---|---|---|
| **Task** (go-task) | pinned in `scripts/lib/task_bin.sh` | MIT | <https://github.com/go-task/task> |

Release archives carry the unmodified upstream Linux release tarballs in `tools/go-task/`,
each with its `LICENSE`, so `./logstotal` can run on a host with no network. The repository
itself does not contain them.

## Sigma rule sets

| Component | Location | Licence | Upstream |
|---|---|---|---|
| SigmaHQ rules (Windows + Linux subsets) | `tools/chainsaw/sigma/`, `tools/chopchopgo/rules/`, `tools/hayabusa/rules/`, `tools/zircolite/rules/`, `tools/rsigma/rules/` | Detection Rule License 1.1 (DRL 1.1) | <https://github.com/SigmaHQ/sigma> |
| Chainsaw rules + EVTX mappings | `tools/chainsaw/rules/`, `tools/chainsaw/mappings/` | GPL-3.0-only | <https://github.com/WithSecureOpenSource/chainsaw> |
| Hayabusa rules + config | `tools/hayabusa/rules/`, and compiled into `tools/zircolite/rules/rules_windows_all.json` | Detection Rule License 1.1 (DRL 1.1) | <https://github.com/Yamato-Security/hayabusa-rules> |
| ChopChopGo mappings | `tools/chopchopgo/mappings/` | GPL-3.0-only | <https://github.com/M00NLIG7/ChopChopGo> |

The full DRL 1.1 text ships at [`LICENSES/DRL-1.1.md`](LICENSES/DRL-1.1.md). It permits use,
modification, redistribution and commercial use. It requires that anyone sharing the rules
keeps each rule's author, a link to the rule set and the licence; and that anything
reporting a match keeps the rule's author — which is why every LogsTotal finding names its
rule's author, on screen and in `findings.json`.

### Community rule sources in Zircolite's `windows_all` rule set

`tools/zircolite/rules/rules_windows_all.json`, which the Windows workflows load, is compiled
by [Zircolite](https://github.com/wagga40/Zircolite/tree/master/rules) from the SigmaHQ and
Hayabusa rules above and from the sources below. Every compiled rule carries its `source`,
`license` and `author`, and each source's licence text ships as
`tools/zircolite/rules/licenses/<source>.txt`.

| Source | Licence | Upstream |
|---|---|---|
| adpack | MIT | <https://github.com/404SecNotFound/Active-Directory-Pentest-Detection-Pack> |
| dragon | MIT | <https://github.com/frknaykc/Dragon-ThreatResearchHQ> |
| hatchepsoute | Apache-2.0 | <https://github.com/Hatchepsoute/sigma-rules> |
| huntress | MIT | <https://github.com/huntresslabs/threat-intel> |
| joesecurity | GPL-3.0 | <https://github.com/joesecurity/sigma-rules> |
| loldrivers | Apache-2.0 | <https://github.com/magicsword-io/LOLDrivers> |
| lolrmm | Apache-2.0 | <https://github.com/magicsword-io/LOLRMM> |
| mbabinski | GPL-3.0 | <https://github.com/mbabinski/Sigma-Rules> |
| mdecrevoisier | CC0-1.0 | <https://github.com/mdecrevoisier/SIGMA-detection-rules> |
| reversinglabs | MIT | <https://github.com/reversinglabs/reversinglabs-siem-rules> |
| tsale | GPL-3.0 | <https://github.com/tsale/Sigma_rules> |
| tyrian | MIT | <https://github.com/zshguy/tyrian-detection-pack> |
| wrg11 | MIT | <https://github.com/WRG-11/wrg-sigma-rules> |

The GPL-3.0 rules are distributed as data in the compiled rule set and evaluated by a
separate process, like the GPL-3.0 Chainsaw rules above. Their licence and
corresponding-source obligations travel with them.

Rule sets are snapshots, not live mirrors. See
[Detection tools and workflows](docs/runbooks/detection-tools.md#updating-rule-sets) for how to
refresh them.

## Front-end bundles

Served locally from `app/static/vendor/` — LogsTotal loads no CDN at runtime. Versions are
declared in `Taskfile.yml` and refreshed with `./logstotal vendor:update`.

| Component | Version | Licence |
|---|---|---|
| htmx | 2.0.11 | BSD-2-Clause (<https://github.com/bigskysoftware/htmx>) |
| htmx-ext-alpine-morph | 2.0.2 | BSD-2-Clause (<https://github.com/bigskysoftware/htmx-extensions>) |
| Alpine.js | 3.17.4 | MIT (<https://github.com/alpinejs/alpine>) |
| Alpine Morph plugin | 3.17.4 | MIT (<https://github.com/alpinejs/alpine>) |
| Tailwind CSS (Play CDN build, dev mode only) | 3.4.17 | MIT (<https://github.com/tailwindlabs/tailwindcss>) |
| Prism.js (+ json/sql/yaml, Tomorrow theme) | 1.30.0 | MIT (<https://github.com/PrismJS/prism>) |
| Mermaid | 11.17.2 | MIT (<https://github.com/mermaid-js/mermaid>) |
| Sigma.js | 3.0.3 | MIT (<https://github.com/jacomyal/sigma.js>) |
| graphology | 0.26.0 | MIT (<https://github.com/graphology/graphology>) |
| graphology-library | 0.8.0 | MIT (<https://github.com/graphology/graphology>) |

## Python dependencies

Installed from PyPI at build time, not vendored — see `requirements.txt` (generated) and
`pyproject.toml` (source of truth). Their licences are those declared on PyPI; none is
redistributed in this repository. `pdm list --fields name,version,licenses --csv` prints
the resolved set for a given lock.

One exception is adapted into this repository's own source rather than installed:

| Component | Where | Licence |
|---|---|---|
| fastapi-users-db-sqlalchemy 7.0.0 (user table base, `GUID` type, database adapter) | `app/auth/sqlalchemy_adapter.py` | MIT, Copyright (c) 2021 François Voron (<https://github.com/fastapi-users/fastapi-users-db-sqlalchemy>) |

The MIT licence requires its notice to travel with the code, so here it is:

> Permission is hereby granted, free of charge, to any person obtaining a copy of this
> software and associated documentation files (the "Software"), to deal in the Software
> without restriction, including without limitation the rights to use, copy, modify, merge,
> publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
> to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or
> substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
> INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
> PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
> FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
> OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
> DEALINGS IN THE SOFTWARE.

## Sample logs

`samples/` contains small, curated log files used for evaluation and by
`tests/test_sample_logs.py`. They are synthetic or derived from public detection-engineering
corpora and contain no real personal data.
