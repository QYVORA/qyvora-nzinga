# nzinga CLI Reference

Run `nzinga` with no arguments to enter the interactive console (REPL).

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | success |
| `1`  | operational/run error |
| `2`  | usage error |
| `130`| interrupted (128 + SIGINT) |

## Global options

`nzinga` commands accept the standard profile flags:

| Flag | Meaning |
|------|---------|
| `--profile <quick\|standard\|deep>` | collection depth/width profile (default `standard`) |
| `-o, --output <terminal\|...>` | output mode |
| `--yaml`, `--json` | structured output |
| `-v, --verbose` | verbose logging |
| `-q, --quiet` | quiet logging |
| `-y, --authorized` | confirm target authorization (consent gate) |
| `--sim` | offline demo mode using the simulation dataset (auto demo-auth) |
| `--dry-run` | print the plan and exit without collecting |
| `--log-level <level>` | log level |
| `--session-dir <dir>` | session store directory |

See `docs/Configuration.md` for the full configuration reference; any flag maps to a
config key.

## Commands

### `assess [target]`

Run the full intelligence pipeline:
`discover → collect → normalize → correlate → analyze → validate → report`.

With no target uses the current saved target (`nzinga target show`). Collects
live sources only after the authorization gate passes.

### `discover [target]` (alias `find`)

Run only the DISCOVER stage: resolve and validate the target, then persist a
discover-only session. Shares the pipeline's discovery implementation, so a
validated target from `discover` behaves identically in a full `assess`.

### `relationship`

Inspect the intelligence relationship graph of the latest session.

- `relationship graph` (alias `edges`) — render nodes and edges.
- `relationship show` — summarize relationship types and counts.

### `collect <domain|organization|username|ip|infrastructure> <value>`

Run collection and analysis for a specific target type:
`nzinga collect domain example.com`.

### `analyze`

Re-run the rule engine and risk assessment over the latest session.

### `findings`

List rule findings from the latest session.

### `evidence`

List evidence artifacts from the latest session.

### `graph`

Render the relationship graph (nodes and edges) from the latest session.

### `report [--format terminal|markdown|html|json|yaml] [--out <path>]`

Render the structured intelligence report from the latest session.
Supported formats: `terminal` (default), `markdown`, `html`, `json`, `yaml`.

### `sources [list|show]`

List intelligence sources and their capabilities, or show the complete
source catalog (id, name, capabilities, risk, authorization required).

### `target`

Manage collection targets.

- `target set [value]` — select and authorize the current target
  (`nzinga target set example.com`). Refuses targets that have not passed the
  authorization gate.
- `target list` — list known targets.
- `target show` — show the current target.

### `capabilities`

List nzinga's machine-readable tool contract (operations, rules, events,
formats).

### `updates [--install]`

Check for nzinga updates (SHAKA-derived self-update flow). Bare `updates`
checks whether a newer release is available; `--install` downloads, verifies,
and installs the latest release.

### `completion [bash|zsh|fish|powershell]`

Generate a shell completion script; source it to enable tab completion.

### `version`

Print framework name, version, commit, build date, build user, and Go build
info.

## Console (REPL)

`nzinga` with no subcommand starts a readline console. Console collection
runs default to the offline simulation dataset.

| Command | Meaning |
|---------|---------|
| `sources`, `capabilities` / `tools` | catalog tables |
| `use <target>` | set the console's current target |
| `run [target]` | run the pipeline against the console target (offline demo by default) |
| `assess [target]` | run the pipeline (offline demo by default) |
| `discover [target]` | discover-only run |
| `domain \| organization \| username \| ip \| infrastructure <value>` | typed collection |
| `analyze` | findings + risk for latest session |
| `findings` | findings table |
| `evidence` | evidence table |
| `graph`, `relationship` | nodes/edges and relationship summary |
| `report` | full report render |
| `show`, `status` | console target, profile, directory, saved target |
| `back` | `cd ..` |
| `target \| tgt` | target management |
| `banner`, `version`, `history`, `cd`, `shell` | shell utilities |
| `help`, `exit` | help and exit |