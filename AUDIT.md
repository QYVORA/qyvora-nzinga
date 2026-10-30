# NZINGA — Capability Audit, Gap Analysis and Conformance Review

**Framework:** `qyvora-nzinga` · **Audit date:** 2026-10-21 · **Audit type:** read-only, evidence-based
**Deliverable:** A (per-framework audit report), sections 1–16 as required by `PROMPT.md` §13

---

## 1. Framework identity and intended domain

| | |
|---|---|
| Canonical name | `nzinga` |
| Domain | **Authorized open-source intelligence (OSINT) collection, correlation and reporting.** Passive/public-source reconnaissance only; it never interacts with, scans or exploits a target. |
| Repository | `products/QYVORA-AI/frameworks/qyvora-nzinga` |
| Module | `github.com/QYVORA/qyvora-nzinga` (independent Go module; does **not** import `qyvora-common` — verified in `go.mod`) |
| Entry point | `cmd/nzinga` → `internal/cli` (`ExecuteArgs`, `internal/cli/root.go:86,100`) |
| Version reported by shipped binary | `{"framework":"nzinga","version":"v0.1.0","commit":"228573f","date":"2026-10-21T01:20:17Z","build_user":"wsuits6","go_version":"go1.27.1","arch":"amd64","os":"linux",…}` (`version -o json`, verified live, exit 0) |
| Size (measured) | 12,203 non-test Go lines, 2,792 test Go lines, 21 `_test.go` files (`find … \| xargs wc -l`) |
| Shared dependencies | `github.com/QYVORA/qyvora-script v0.1.0`, `github.com/QYVORA/qyvora-tui v0.11.0` (brand helpers only; session engine not linked — see §10) |
| CLI grammar | `<tool> <tier> <module> [<action>] [target] [flags]`, tiers `recon` / `exploit` / `report` (`internal/cli/root.go:164-197`) |
| Git state at audit start and end | `main...origin/main [ahead 1]`; staged rename `nzinga-main-logo.png → assets/nzinga-main-logo.png` **preserved throughout**; `bin/`, `sessions/`, `reports/` gitignored (`.gitignore:2,9,12`) |

Domain boundary statement (own README/§"About", `internal/cli/root.go:41` banner): collection from public
sources, normalization, correlation into claims/relationships, rule-based evaluation, evidence-driven
reporting. No scanning, no exploitation, no target interaction.

## 2. Audit scope and evidence sources

**Method.** Static source inspection plus non-destructive local execution of the shipped binary.
No feature implementation, no refactoring, no configuration changes, no repository edits other than this file.

**Evidence read.** `README.md`, `docs/*.md` (Architecture, CLI, Configuration, Getting-Started, Reporting,
Rules, Security-Model, Sessions, Sources, Targets, Roadmap), `Makefile`, `.github/workflows/{ci,release}.yml`,
`internal/cli/*`, `internal/pipeline/*`, `internal/intelligence/sources/*`, `internal/events/*`,
`internal/rules/*`, `internal/search/*`, `internal/exitcode/*`, `internal/config/*`, `internal/safety/*`,
`internal/reporting/*`, plus the ecosystem contracts: `shared/qyvora-common/contract/contract.go`,
`shared/qyvora-common/conformance/runner.go`, `shared/qyvora-common/README.md`,
`knowledge/qyvora-docs/09-technical/cross-project/standards/QYVORA-TOOL-OUTPUT-SPEC.md` (§1–§8),
and the pre-captured help snapshot `docs/audit/help/nzinga.txt`.

**Commands executed (all local, exit codes captured without shell pipelines):** `version -o json`,
`capabilities` (`-o json`), `--help` and per-command `--help`, `recon assess --sim` (and `assess --sim`,
the hidden pre-tier alias), `--dry-run` variants, `recon sources list`, `recon dorks list`,
`recon target list/set/show`, `report`, `report findings|evidence|graph|relationship|session` in
terminal/json/markdown/html, `recon analyze` (`rules`), `script --help`, `exploit`, plus deliberate
negative probes (unknown flags, unknown commands, invalid `-o` value, no-session report,
unauthorized live collection, SIGINT-cancellation probe is **not** part of this framework — see §13).

**Environment isolation.** Structured runs used `QYVORA_NZINGA_SESSION_DIR=/tmp/opencode/nz/sessions` and
`QYVORA_NZINGA_REPORT_DIR=/tmp/opencode/nz/reports` so result files land outside the repository.

**Disclosures (artifacts and deviations created during this audit):**

1. Two files were written into the repository's *gitignored* output directories by early probes before the
   environment overrides were applied: `sessions/sess-c9adc9ab3eccfc86.session.json` and
   `reports/report.terminal` (both timestamped 02:33, 2026-10-21). They are ignored by git; `git status`
   still shows only the pre-existing staged rename.
2. One README example was executed **with `-y` and therefore attempted a live collection**:
   `nzinga assess -y domain:example.com --profile standard -o json` (§4.6/§12 evidence). The tool
   degraded honestly (`[nzinga][WARN] collect: status 502`, no findings, no fabricated data). This was the
   only live *target-collection* attempt in the audit and it was not repeated.
3. Temporary unstripped binaries were built to `/tmp/opencode/uns/` for symbol inspection. The repository's
   `bin/nzinga` was **not** rebuilt (mtime 01:20, pre-audit).
4. `nzinga updates` was executed during the follow-up probe pass and therefore made **one live GitHub API
   request** (`GET api.github.com/repos/QYVORA/qyvora-nzinga/releases/latest`, `internal/selfupdate/github.go:11,47-48`),
   returning `update available: v0.1.0 -> 0.10.1`. This is an update-metadata query about nzinga itself, not a
   probe of any OSINT target; `--install` was not run and nothing was downloaded.
5. Structured follow-up runs (`assess --sim`, `report …`) used
   `QYVORA_NZINGA_SESSION_DIR=/tmp/opencode/nz/sessions` and `QYVORA_NZINGA_REPORT_DIR=/tmp/opencode/nz/reports`,
   so no additional session/report file landed in the repository.
6. No source, configuration, dependency, documentation or user file was modified. Only this `AUDIT.md` is new.

**Verified vs inferred.** Every behaviour claim below marked *verified* was reproduced against the shipped
binary or read in source at the cited `file:line`. Claims about absent behaviour are labelled
*inferred from absence* (search performed, nothing found) or *unverified*.

## 3. Existing capability inventory

Commands (all verified to exist via `--help`, exit 0):

| Surface | Members | Evidence |
|---|---|---|
| Root utilities | `capabilities`, `completion`, `help`, `script` (`build`/`run`), `updates`, `version` | `internal/cli/root.go:162` |
| Tier `recon` | `assess`, `discover`, `collect` (`domain`/`infrastructure`/`ip`/`organization`/`username`), `analyze` (alias `rules`), `target` (`list`/`set`/`show`), `sources`, `dork`, `dorks` (`list`/`show`) | `internal/cli/root.go:174-183` |
| Tier `exploit` | **empty by design** — running it exits 2 with *"the exploit tier is empty: nzinga collects and correlates from public sources and never interacts with a target"* (verified) | `internal/cli/root.go:185-191` |
| Tier `report` | root render (`-f/--format`, `--out`), `findings`, `evidence`, `graph`, `relationship` (`graph`/`show`) | `internal/cli/root.go:193-195`, `internal/cli/assess.go:203-216` |
| Hidden pre-tier aliases | `assess`, `discover`, `collect`, `analyze`, `target`, `sources`, `dork`, `dorks`, `findings`, `evidence`, `graph`, `relationship` (all verified resolving) | `internal/cli/root.go:204-217`, `hiddenAlias` at `:225-231` |

Pipeline: 7 ordered stages `discover → collect → normalize → correlate → analyze → validate → report`
(`internal/pipeline/pipeline.go:34-40`, dispatch `:152-164`), each stage appended to `session.stages`
(`:103`) and announced on the event stream.

Intelligence sources (registered in `internal/cli/root.go:324-330`):
`crt.sh` (certificate + subdomain enumeration), `dns`, `whois` (TCP/43, configurable `sources.whois.port`),
`github` (repository/username, token optional), `abuseipdb` (token required for live use),
`search` (dorking, opt-in), `simulation` (offline dataset). The `Source` contract
(`internal/intelligence/sources/source.go:31-43`) is `ID/Name/Capabilities/Collect/Simulate/Describe`
with `ErrUnauthorized` (`:27`) enforcing that **live sources run only for an authorized target** and the
simulation source is the only one allowed offline (package comment `:6-13`).

Search/dorking: `internal/search/providers.go` — `SimulationProvider` (`:29-39`) and a generic JSON
`APIProvider` (`:97-184`) plus an embedded dork template catalog loaded by `loadDorkCatalog`
(`internal/cli/root.go:335+`), overridable by `sources.search.custom_wordlist_path`.

Rules/analysis: five built-in detections `OSINT-001…OSINT-005`
(`internal/rules/builtin/builtin.go:25,65,153,210,273`), re-runnable via `recon analyze`/`rules`.

Authorization gate: `-y/--authorized`, config key `authorized`, `QYVORA_AUTHORIZED=true`
(`internal/cli/authorization.go:22-27`), interactive TTY prompt, otherwise a clean refusal
(`:42` declined, `:45` non-interactive) — both return **exit 1** (verified: live `recon assess`
in a non-TTY without `-y` → `authorization declined; intelligence collection aborted`, exit 1).

Profiles `quick|standard|deep` (`internal/config/config.go:25-27`), report dir default `reports`
(`:67`), session dir default empty → `sessions` (`:70`).

## 4. Capability status matrix

Statuses: IMPLEMENTED / PARTIALLY IMPLEMENTED / STUBBED / PLANNED / MISSING / UNVERIFIED / NOT APPLICABLE.

| # | Capability | Status | Evidence |
|---|---|---|---|
| 1 | Full 7-stage intelligence pipeline (`assess`) | IMPLEMENTED (verified) | `--sim` run: 7 stages, 53 observations, 0 failed sources, risk 28/100 low |
| 2 | Stage-level entry points (`discover`, `collect <type>`) | IMPLEMENTED | `internal/cli/root.go:174-183`; `collect` requires authorization (verified exit 1) |
| 3 | Offline simulation dataset (`--sim`, auto demo-auth) | IMPLEMENTED (verified) | `assess --sim` exit 0 without `-y`; `docs/Security-Model.md:49` |
| 4 | Live source collection (crt.sh, dns, whois, github, abuseipdb, search) | IMPLEMENTED, *partially live-verified* | source registry + `Source` interface; only one degraded live attempt (status 502) recorded — see §2 |
| 5 | Entity/relationship correlation, claim graph | IMPLEMENTED (verified) | `report graph -o json` → `{"edges":[{id,from,to,type,source,confidence,timestamp}…]}`; `23 nodes, 22 edges` |
| 6 | Rule engine + risk scoring | IMPLEMENTED (verified) | 5 built-in rules; `risk_calculated` event; risk 28/100 in sim run |
| 7 | Event stream (JSONL, `--events`) | IMPLEMENTED (verified, envelope conforms) | 76 lines captured; all carried `framework:"nzinga"`, `schema_version:"1.0"`, 32-hex `execution_id`, RFC3339 `timestamp`, `level`, dotted `event` |
| 8 | Report renderers terminal/json/yaml/markdown/html | IMPLEMENTED (verified) | `report`, `report -f markdown`, `report --format html`, `report -o json` all exit 0 |
| 9 | Capability advertisement (`capabilities -o json`) | PARTIALLY IMPLEMENTED | works (exit 0, 22 records) but emits a **bare array**, not `contract.CapabilityManifest` — see §10 |
| 10 | Exit-code contract 0/1/2/130 | IMPLEMENTED, with one verified exception | `internal/exitcode/exitcode.go:14-19`; probes: unknown flag→2, unknown root command→2, invalid `-o`→2; **exception:** `NoArgs`/`ExactArgs` validator usage errors → **1** (`version bogus`, `capabilities bogus`, `dorks list bogus`) — §14 G-13 |
| 11 | Exit code `3` (unsupported/refused) | MISSING | constant absent; authorization decline uses **1** (`authorization.go:42,45`) while `contract.go:15-16` reserves 3 for authorization-decline/domain-unsupported |
| 12 | Canonical `contract.Result` shape for reports | PARTIALLY IMPLEMENTED | report JSON is the raw `models.Session`; no `identity`/`context` blocks (verified top-level keys) |
| 13 | `report findings -o json` structured output | PARTIALLY IMPLEMENTED | emits a JSON **array of 5-element positional arrays** (`["OSINT-002","medium","…","probable","detected"]`) — verifiable but not self-describing |
| 14 | Interactive TUI | NOT APPLICABLE (retired) | no session engine linked (§10); `nzinga tui` prints brand/help, exit 0 |
| 15 | Active exploitation / target interaction | NOT APPLICABLE | domain excludes it; `exploit` tier exits 2 with an explicit explanation (verified) |
| 16 | `script` (.qs) engine | IMPLEMENTED, unexercised | `script build|run` commands exist; not executed during audit → behaviour UNVERIFIED |
| 17 | Config profiles, env precedence, `--dry-run` | IMPLEMENTED (verified) | `--dry-run` prints the would-collect plan with sources, exit 0 when authorized |
| 18 | SIGINT → 130 with event flush | UNVERIFIED | `signal.NotifyContext` wired (`internal/cli/root.go:87`) but no interrupt was forced during audit |
| 19 | Rate limiting / backoff for live APIs | PARTIALLY IMPLEMENTED | API-key honest failure documented for AbuseIPDB; no generic backoff/pagination found (inferred from source search) |
| 20 | Correlation across sessions / historical store | MISSING | sessions are per-run files; no cross-session index (inferred from `internal/session`-style store usage in `report` "latest session" wording) |

## 5. Reconnaissance and discovery findings

- **Passive-first design is real.** The discovery stage only normalizes and validates the target
  (`internal/pipeline/pipeline.go:170-197`); there is no active probing code path. Subdomain/certificate
  discovery uses public CT logs (`crt.sh`), DNS resolution and WHOIS — appropriate for the domain.
- **Authorization is the actual control, not a prompt.** Live sources return `ErrUnauthorized`
  (`sources/source.go:27`) and the CLI gate runs before any collection. Verified: without `-y` in a
  non-TTY the run aborts with exit 1 before any observation is produced.
- **Honest degradation is implemented.** Sim run reported `53 observations (0 source(s) failed)`; the
  live attempt reported `status 502` as a warning and produced no fabricated findings.
- **Discovered entity metadata is rich.** Sim report carried `domains[] (state, confidence, sources,
  discovered_at)`, `hostnames[]`, `ips[]`, `emails[]`, `certificates[]`, `organizations[]`,
  `observations[]`, `claims[]`, `graph_nodes/graph_edges`, `evidence[]`, `risk_score`, `risk_level`,
  `attributes`.
- **Gap (P2):** discovery is target-scoped only; there is no attack-surface expansion beyond the
  supplied target (no recursive subdomain expansion with depth control, no ASN/whois-netblock walk,
  no per-source concurrency/limit flags exposed on the CLI). *Inferred from absence* of such flags in
  the persistent flag set (`internal/cli/root.go` global flags).

## 6. Analysis and assessment findings

- **Correlation produces a typed graph** with edge confidence (`observed`… ) and provenance `source`
  fields (verified in `report graph -o json`), and findings are deduplicated in the session model
  (`internal/rules/rules.go:101-113` sorts by rule id; dedupe by `RuleID` at `:111`).
- **Rule engine is declarative and small**: 5 rules, each with id/title/category/severity/confidence
  and evidence binding (`f.RuleID = r.ID`, `internal/rules/rules.go:101`). Re-run via `recon analyze`.
- **Risk scoring** is computed in the validate stage and emitted both as an event (`risk.calculated`)
  and as `risk_score`/`risk_level` in the report (verified `28/100`, `low`).
- **Gap (P1):** findings in `-o json` are positional tuples (§4 item 13) so an orchestrator cannot map
  `severity`/`confidence` without knowing column order; the session's `findings[]` object array is
  available in the full report but not from the `findings` subcommand.
- **Gap (P2):** no negative/false-positive suppression feedback loop (no way to mark a finding as
  suppressed that survives into later runs); sessions are independent.
- **Gap (P3):** no `--explain`/rule trace output showing which evidence satisfied which rule
  (partially available in terminal rendering only; not verified in JSON).

## 7. Exploitation-related capability findings

**Status: NOT APPLICABLE for target interaction, IMPLEMENTED as an explicit contract.**

- The `exploit` tier exists only so the shared three-tier grammar is uniform (`internal/cli/root.go:164-169`).
  Invoking it returns exit **2** with the message *"the exploit tier is empty: nzinga collects and
  correlates from public sources and never interacts with a target"* (verified for `nzinga exploit`,
  `nzinga exploit bogus`, `nzinga exploit capabilities`).
- Consequence for orchestration: an orchestrator can discover "no exploitation surface" without
  parsing prose, but only via the exit code + stderr text — there is no structured
  `unsupported`/`3` signal (see §10, §14 gap G-3).
- Exploitation-*related* assessment that is in-domain (exposure and configuration findings derived from
  public data) is covered by the rule engine: `OSINT-002` infrastructure overlap, `OSINT-003` exposed
  email, `OSINT-005` etc. These are report-level findings, not active tests.

## 8. High-level implementation candidates

High-level = buildable now with existing hardware, dependencies and authorization model (PROMPT §6).

1. **Canonical result wrapper** — emit `contract.Result`-shaped JSON (`identity`/`context`/`findings`/
   `evidence`/`risk`) alongside the session model for `assess -o json`. Removes the biggest
   orchestrator-side normalization cost (see §10).
2. **Exit code 3 adoption** — map authorization decline/domain-unsupported to `3` per `contract.go:15-16`,
   keeping `1` for runtime failure.
3. **Object-shaped `report findings -o json`** — reuse the session's finding objects instead of tuples.
4. **Capability manifest wrapper** — `{"framework","version","commands":[…]}` over the existing 22 records.
5. **Source-level controls** — per-source enable/disable, page/concurrency limits, retry/backoff,
   and `--max-observations` to make live runs bounded and repeatable.
6. **Session diff / re-assess** — compare a new assessment against a stored one (drift detection).
7. **Structured `unsupported` response** for the empty exploit tier (JSON on `-o json`) instead of
   prose-only.
8. **Additional passive sources** consistent with the domain (e.g. archive/snapshot history, passive
   DNS, RDAP normalization, additional CT log instances), each behind the same authorization gate.

## 9. Low-level deferred technique inventory

**DEFERRED — SPECIALISED PREREQUISITES.** These are in-domain or adjacent OSINT/intelligence techniques
that cannot be implemented on the current environment. Recorded, not silently dropped (PROMPT §6).

| Technique | Objective | Requires | Status | Why deferred / unlock conditions |
|---|---|---|---|---|
| RF/SDR transmitter geolocation and direction-finding | Locate emitters physically | SDR hardware, antennas, calibrated site access | MISSING → DEFERRED | No RF hardware in the environment; unlock: SDR + licensed spectrum use |
| Cellular/SS7/CDR correlation | Telephony metadata intelligence | Carrier/roaming-provider contracts, lawful-access authorization | MISSING → DEFERRED | Restricted data access beyond public sources; unlock: contractual data sharing |
| Satellite/licensed geospatial feed analysis | Change detection on infrastructure | Commercial imagery subscriptions, tasking rights | MISSING → DEFERRED | Paid/licensed feeds; unlock: licensed API access |
| Hardware implant / device teardown inspection | Physical evidence recovery | Teardown lab, ESD bench, imaging tools | MISSING → DEFERRED | Physical access and lab; unlock: lab provisioning |
| Covert/active human-source (HUMINT) style elicitation | Gather non-public data | Identities, OPSEC controls, legal review | NOT APPLICABLE → DEFERRED | Conflicts with the passive, public-source-only charter; would require an explicit scope change and legal review |

## 10. Common-layer conformance

Reference: `shared/qyvora-common/contract/contract.go`, `conformance/runner.go:222-293`,
`knowledge/…/QYVORA-TOOL-OUTPUT-SPEC.md` §1–§8. Frameworks intentionally do not import the contract
(`contract.go:4-8`, `qyvora-common/README.md`) — verified: no `qyvora-common` in `go.mod` or any `.go` import.

| Contract element | Nzinga behaviour | Verdict |
|---|---|---|
| Exit codes 0/1/2/130 (`contract.go:19-24`) | `internal/exitcode/exitcode.go:14-19` implements exactly these; probes confirmed 0 (success), 1 (runtime/authz), 2 (flag/root-command usage, `root.go:142` `SetFlagErrorFunc`), — | CONFORMANT for the probed flag/root-command cases; 130 UNVERIFIED at runtime |
| Spec §1 Rule 1: "usage error MUST NOT be exit 1" | cobra validator errors surface as plain errors → exit **1**: verified `nzinga version bogus`, `capabilities bogus`, `dorks list bogus` (all `Args: cobra.NoArgs` at `version.go:15`, `capabilities.go:14`, `dork.go:77`) and `script` with no file (`ExactArgs(1)`, `script.go:35` → "accepts 1 arg(s), received 0") | **NONCONFORMANT for the NoArgs/ExactArgs class (verified)** — same defect class as sekhmet, see §14 G-13 |
| Exit code `3` (spec §1 normative list; `contract.go:15-16` "authorization-decline and domain-unsupported by convention use 3") | No `3` constant; authorization decline returns 1 (`internal/cli/authorization.go:42,45`, verified live) | **NONCONFORMANT** with the contract convention |
| `VersionResult` (`contract.go:76-84`) | Full shape incl. `framework`,`version`,`commit`,`date`,`os`,`arch` + extra build fields; semver `v0.1.0` | CONFORMANT (shape superset) |
| `Envelope` JSONL (`contract.go:33-41`, spec §2) | `internal/events/events.go:31,68-75`; 76/76 captured lines valid with all 7 fields | CONFORMANT |
| Event vocabulary (spec §3) | 21 verbs defined (`events.go:34-54`); 13 observed live | PARTIALLY CONFORMANT — **nzinga has no row in the spec §3 table**, so its vocabulary is undocumented for consumers |
| `CapabilityManifest` (`contract.go:69-74`) | `capabilities -o json` returns a bare `[]` of 22 objects (no `framework`/`version`/`commands`) | **NONCONFORMANT** (shape), CONFORMANT (exit 0) |
| `Result` (`contract.go:100-107`) | Reports are the raw session model (`internal/reporting/reporting.go:57` `json.MarshalIndent(s,…)`); no `identity`/`context` | **PARTIALLY CONFORMANT**; spec §6 has no nzinga report section at all (documented variance by omission) |
| Dedup contract (spec §7) | Findings sorted/deduped by rule id (`internal/rules/rules.go:101-113`); no upward-confidence merge documented | PARTIALLY CONFORMANT (dedupe exists, merge semantics not specified for nzinga) |
| TUI retirement (`conformance/runner.go:286-289,305+`) | Unstripped temp build: **0 `qyvora-tui` session symbols** → `tui-retired ok`. Shipped `bin/nzinga` is stripped (`file`: `stripped`, Makefile `-s -w`) → the runner reports `cannot inspect symbols` | CONFORMANT in substance, UNVERIFIED by the runner on release artifacts |

**Conformance engine run (performed, `qyvora-conformance --bin …`):** `version-semver ok`,
`usage-exit-2 ok`, `unknown-cmd-exit-2 ok`, `capabilities ok`, `tui-retired FAIL(no symbol section)` on the
shipped binary; on the unstripped build `tui-retired ok` and `version-semver` fails only because a raw
`go build` leaves `version=dev` (expected, `internal/version` default `dev`, `internal/version/*.go`).

**Duplication notes.** `internal/events`, `internal/exitcode`, `internal/errors` and the `hiddenAlias`
pattern each re-implement contracts that other frameworks implement identically — acceptable per the
"native implementation" rule, but they are the exact places where drift appears (nzinga lacks `3`,
sekhmet has it). This is the highest-value target for a shared conformance assertion.

## 11. AI orchestration readiness

| Requirement | Status | Evidence |
|---|---|---|
| Stable framework identity | CONFORMANT | `version -o json` carries `framework:"nzinga"` + build metadata |
| Version/compatibility metadata | PARTIALLY CONFORMANT | shape OK; local/`make` builds stamp `VERSION ?= v0.1.0` (`Makefile:12`) while the repo tag is `v0.10.1` — a stale default that misreports the code under test |
| Machine-readable capabilities | PARTIALLY CONFORMANT | 22 records with `risk`, `noise_level`, `authorization_required`, `changes_state`, `confirmation_required`, `target_types`, `schema`, `duration`; but bare array, not a manifest (§10) |
| Explicit operation inputs/outputs | PARTIALLY CONFORMANT | per-capability `schema`/`output` present; command-level `inputs`/`deterministic` flags absent vs `contract.Command` |
| Predictable exit codes | PARTIALLY CONFORMANT | 0/1/2 verified for flags and unknown root command; `3` unused; validator usage errors exit **1** (`version bogus`, `capabilities bogus`, `dorks list bogus`); tier-group unknown subcommand prints help with **exit 0** (`nzinga recon bogus`) while `report bogus` silently renders the latest report — both can look like success |
| Structured results and evidence | PARTIALLY CONFORMANT | rich session JSON; no `identity`/`context`; `report findings -o json` tuples |
| Prerequisite/authorization declaration | CONFORMANT | capabilities advertise `authorization_required`, `risk`, `noise_level`; runtime refusal is explicit and early |
| Timeouts / cancellation | PARTIALLY CONFORMANT | `signal.NotifyContext` (`root.go:87`) + `config.Timeout` (`root.go:360`); no `--timeout` CLI flag surfaced in help; exit 130 untested |
| Safe execution defaults | CONFORMANT | no network without authorization; `--dry-run`; `--sim` offline; no destructive operations exist |
| Read-only vs state-changing distinction | CONFORMANT | `changes_state` field present per capability; target registration is the only persistent write |
| Honest unsupported reporting | PARTIALLY CONFORMANT | prose + exit 2 for empty exploit tier; no structured unsupported signal |
| Result/event correlation | CONFORMANT | single `execution_id` across all events of a run (32-hex, stable per process) |
| Shared common-layer compatibility | PARTIALLY CONFORMANT | native implementation by design; three shape deltas listed in §10 |

**Recommended architecture (proposal only, not implemented):** (a) keep the native implementation rule but
add a per-repo `contract` golden test that unmarshals `-o json`, `capabilities -o json` and one event line
against `qyvora-common/contract` types; (b) normalize exit codes through one `exitcode` helper that includes
`3`; (c) have the orchestrator treat `capabilities` as `CapabilityManifest` **after** the wrapper lands —
until then it must accept a bare array (documented variance).

## 12. CLI, repository-layout, and documentation findings

**CLI (verified).** Global flags: `--allow-shellout`, `-y/--authorized`, `-c/--config`, `--dry-run`,
`--events`, `--json`, `-o/--output` (`terminal,json,markdown,html,yaml`), `--profile`, `-q`, `--sim`,
`--target`, `--type`, `--update`, `-v`. `report` root adds `-f/--format` + `--out`
(`internal/cli/assess.go:214-215`) while `-o` also produced JSON — two overlapping selectors for one
concept (minor inconsistency).

Positive: unknown flag → 2, unknown root command → 2 with a clean `unknown command … (try 'nzinga --help')`
message (`internal/cli/root.go:72`), invalid `-o xml` → 2 with the valid set listed, empty-tier → 2.

**Findings:**

- **D-1 (P1) `README.md` example is broken:** `nzinga findings -f json` (`README.md:95`) →
  `Error: unknown shorthand flag: 'f' in -f`, exit 2. The `findings` subcommand accepts `-o`, not `-f`
  (verified both ways). Every other README quick-start line was re-verified and works
  (`assess --sim`, `assess -y … --sim`, `sources list`, `capabilities`, `report session --format json`,
  `relationship graph`).
- **D-2 (P1) `docs/CLI.md` documents commands that do not do what it claims.** The file is a generated
  tier × command cross-product (80 lines). Verified: `nzinga recon findings`, `recon graph`,
  `recon capabilities`, `recon version`, `recon evidence`, `recon report` all print the
  *parent tier help* and exit **0** (no such subcommand exists — `internal/cli/root.go:174-183,193-195`);
  `nzinga report version`, `report capabilities`, `report bogus` instead **render the latest report** and exit 0,
  silently ignoring the unrecognized argument (`report` root takes no argument validation);
  `nzinga exploit assess`, `exploit capabilities`, `exploit bogus` exit **2** (empty tier). Its header
  claim "Every pre-tier command remains available as a hidden alias" is true only for the 12 aliases at
  `root.go:204-217`.
- **D-3 (P2) `README.md` exit-code section (`:103-105`) omits `3`**, and matches the code but not the
  ecosystem contract (§10).
- **D-4 (P2) `docs/CLI.md` / `docs/*.md` help rows vs reality:** `nzinga recon tui` is listed as
  "start the interactive terminal application"; the TUI is retired (no session symbols linked) and the
  command prints help/banner.
- **D-5 (P3) `Makefile:12` `VERSION ?= v0.1.0`** vs repo tag `v0.10.1` — any local `make build`
  reports a version that is not the tag (release path uses goreleaser with the tag —
  `.github/workflows/release.yml:67,85`).
- **D-6 (P3) negative-command ergonomics:** an unknown *subcommand* under a tier prints help with exit 0
  (`nzinga recon bogus`), so scripted typos exit successfully.
- **D-7 (P1) cobra validator usage errors exit 1, not 2 (spec §1 Rule 1).** `nzinga version bogus`,
  `nzinga capabilities bogus`, `nzinga dorks list bogus` → `Error: unknown command "bogus" for …` with
  **exit 1**; `nzinga script` with no file → `accepts 1 arg(s), received 0`, exit 1 (all verified).
  Cause: `Args: cobra.NoArgs`/`ExactArgs` errors are not routed through `SetFlagErrorFunc`
  (`root.go:142` maps only flag errors to 2) and `ExecuteArgs` falls through to the runtime-error path.
  Automation reading exit codes cannot distinguish these from runtime failures.
- **D-8 (P3) stray arguments are silently ignored by several leaf commands (exit 0).** Verified:
  `nzinga report bogus`, `findings bogus`, `evidence bogus`, `graph bogus`, `relationship bogus`,
  `analyze bogus`, `target list bogus`, `sources list bogus`, `updates bogus` all complete normally with
  exit 0, discarding the extra argument — a mis-typed positional looks like success.

**Repository layout.** Standard fleet layout: `cmd/ internal/ pkg/ docs/ configs/ assets/ scripts/
examples/ sessions/ reports/ bin/`, root `README.md`, `CHANGELOG.md`, `SECURITY.md`, `GOVERNANCE.md`,
`CONTRIBUTING.md`, `SUPPORT.md`, `CODE_OF_CONDUCT.md`, `NOTICE`, `LICENSE`, `Makefile`,
`.github/workflows/{ci,release}.yml`. `sessions/`, `reports/`, `bin/` are gitignored as intended.
Assets are canonical (`assets/nzinga.png`, `.desktop`, logo rename staged — preserved).

## 13. Testing and verification findings

**Performed on 2026-10-21 (this audit):**

| Check | Command | Result |
|---|---|---|
| Vet | `go vet ./...` | **exit 0**, no output |
| Unit tests | `go test ./... -count=1 -timeout 240s` | **exit 0**; 21 test files, 2,792 test lines; `ok`/`no test files` across all packages, no `FAIL` |
| Race detector | `go test -race -count=1 ./...` | **exit 0**, 15 packages `ok`, no races (contrast: sekhmet's suite fails `-race` — see `qyvora-sekhmet/AUDIT.md` §13) |
| Format gate (CI equivalent) | `gofmt -l .` | **0 files** (clean); CI also runs it (`.github/workflows/ci.yml`, generated from `qyvora-dist/ci.template.yml`) |
| Conformance runner | `qyvora-conformance --bin …` | 4/5 checks pass on shipped binary; `tui-retired` indeterminate (stripped); unstripped build → `tui-retired ok` |
| Event envelope | 76-line capture parsed field-by-field | all lines conform |
| Exit-code matrix | 14 initial + 28 follow-up invocations | as recorded in §4/§10/§12 |

**CI/CD (read, not executed).** `ci.yml`: gofmt → `go vet` → `go test` → clean `CGO_ENABLED=0`
linux/amd64 build. `release.yml`: goreleaser on tags, artifact naming `${TOOL}_${VERSION}_…`.

**Gaps (prioritised):**

- **T-1 (P1) No conformance step in CI.** Neither workflow runs `qyvora-conformance`, so the machine
  contract is not enforced on push (the engine exists and passes for this repo).
- **T-2 (P2) No race-enabled test in CI** (`make test-race` exists at `Makefile:54` but is unused) and
  no lint configuration at all (no `.golangci.yml` in this repo; sekhmet has one).
- **T-3 (P2) No golden/fixture tests for machine output.** The only test touching the envelope is
  `internal/pipeline/pipeline_test.go`; there is no test asserting `version -o json`,
  `capabilities -o json` or `report -o json` shape, which is why the manifest/tuple deltas went
  undetected.
- **T-4 (P3) Interrupt path untested** (exit 130 + flush) — the signal wiring exists but no test or
  manual verification was performed → **UNVERIFIED**.
- **T-5 (P3) Live-source integration untested** (no network fixtures); honest-degradation behaviour is
  only covered for the simulation source.

## 14. Prioritized gaps and recommendations

| ID | P | Gap | Why it matters | Evidence | Prerequisite / next step |
|---|---|---|---|---|---|
| G-1 | P1 | Reports are not `contract.Result`; no `identity`/`context` | Orchestrator must branch on nzinga-specific shape | `internal/reporting/reporting.go:57`; live report keys | Add an optional wrapper; keep session model for humans |
| G-2 | P1 | `capabilities -o json` is a bare array, not `CapabilityManifest` | Manifest-driven discovery cannot read `framework`/`version`/`commands` | live capture; `contract.go:69-74` | Wrap existing records; add golden test |
| G-3 | P1 | Authorization decline exits `1`; no `3` for declined/unsupported | Automation retries a permanent refusal as a runtime failure | `authorization.go:42,45`; `contract.go:15-16` | Introduce `exitcode.Unsupported=3`; map decline |
| G-4 | P1 | `report findings -o json` emits positional tuples | Not self-describing; brittle for agents | verified twice | Emit finding objects already present in the session |
| G-5 | P1 | Tier-group unknown subcommand → help + **exit 0** | Typos look like success to automation | `nzinga recon bogus` → 0 | Return `2` for unknown subcommands |
| G-6 | P2 | No CI conformance/golden tests; no lint; no race run | Contract regressions ship silently | `.github/workflows/ci.yml` | Add `qyvora-conformance` + golden tests |
| G-7 | P2 | Stale `VERSION ?= v0.1.0` default vs tag `v0.10.1` | Local builds misreport version | `Makefile:12`, `git describe` = `v0.10.1-1-g228573f` | Derive default from `git describe` |
| G-8 | P2 | Documentation deltas: `README.md:95`, `docs/CLI.md`, `docs/CLI.md` TUI row, README exit codes | Users copy commands that fail or do nothing | verified in §12 | Fix examples; regenerate CLI reference from the real command tree |
| G-9 | P2 | No per-source limits/backoff/concurrency controls | Live runs are not reliably bounded/repeatable | absent from flag set | Add flags; wire to shared HTTP client |
| G-10 | P3 | Overlapping `-f/--format` and `-o/--output` on `report` | Confusing contract for agents | `assess.go:214` + global `-o` | Standardize on `-o` |
| G-11 | P3 | No cross-session comparison/drift detection | Repeated assessments can't be diffed | sessions are independent files | Design-only; needs session index |
| G-12 | P3 | nzinga verb set missing from spec §3 | Consumers can't rely on documented verbs | spec §3 has no nzinga row | Update the spec (documentation change) |
| G-13 | P1 | `NoArgs`/`ExactArgs` validator usage errors exit **1**, not 2 | Violates spec §1 Rule 1; automation cannot separate "fix invocation" from "runtime failure" | `version.go:15`, `capabilities.go:14`, `dork.go:77`, `script.go:35`; live probes exit 1 | Route validator errors through the same 2-mapping used for flag errors (`root.go:142`) |
| G-14 | P3 | Leaf commands silently ignore stray positional arguments (exit 0) | Mis-typed invocations report success and run with unintended defaults | `report/findings/evidence/graph/relationship/analyze/target list/sources list/updates bogus` → 0 | Add `Args: cobra.NoArgs` and map those errors to 2 (pairs with G-13) |

Priority scheme per PROMPT §7: P0 critical (none found — no blocking defect, no security/reliability
emergency), P1 high, P2 medium, P3 low. **Priority is not implementation authorization.**

## 15. Dependencies, prerequisites, and unresolved questions

**Dependencies (declared).** Go toolchain (`go 1.27.1` used), `qyvora-script v0.1.0`, `qyvora-tui v0.11.0`
(brand helpers), `spf13/cobra`+`viper`, standard library. Optional external API keys:
`sources.github.token`, `sources.abuseipdb.token` (missing keys degrade honestly), `sources.whois.port`
(default 43), `sources.search.custom_wordlist_path`.

**Prerequisites for live use.** Explicit authorization (`-y`, config `authorized`, or
`QYVORA_AUTHORIZED=true`); network egress to public sources; API keys for rate-limited providers.
Both `QYVORA_AUTHORIZED` (code, `authorization.go:26`) and `QYVORA_NZINGA_AUTHORIZED`
(`docs/Security-Model.md:47`, viper prefix) were **verified** to grant authorization.

**Unresolved questions (documented uncertainty, not findings):**

1. Whether `-o json` on the `report` root is honoured via the persistent flag or the `-f` path — both
   produced identical JSON (mechanism not traced).
2. Whether `script build|run` enforces `--allow-shellout` as documented — **not executed** (§4 item 16).
3. Whether live collection succeeds end-to-end against real sources — only one degraded attempt (502)
   occurred; **not verified**, by audit constraint.
4. Interrupt → exit 130 and event flush — wiring present, behaviour **UNVERIFIED**.
5. Whether the conformance runner can ever check `tui-retired` on release artifacts — currently impossible
   because release builds are stripped (`-s -w`); this affects every fleet tool, not just nzinga.

## 16. No-feature-implementation statement

**No feature implementation was performed during this audit.** No production code, test, configuration,
dependency, build script, documentation file or asset was created, modified or deleted. The framework was
not refactored, no missing command or technique was implemented, no common-layer or conformance-engine
change was made, and no planned capability was recorded as implemented. The staged, pre-existing user
change (`nzinga-main-logo.png → assets/nzinga-main-logo.png`) and the repository's `main...origin/main
[ahead 1]` state were preserved unchanged. The only repository addition is this `AUDIT.md`; audit runtime
artifacts were directed to `/tmp/opencode/…` except the two gitignored files disclosed in §2.
All recommendations in §8, §10, §11 and §14 remain recommendations pending an explicit implementation phase.
