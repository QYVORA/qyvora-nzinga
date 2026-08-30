# Sessions

A session ties one intelligence run to one target and everything it learned:
the target identity, discovered entities, the relationship graph, observations,
claims, findings, evidence, risk score/level, and per-run stage history. It is
the single source of truth for every renderer.

Data model: `pkg/models/session.go`.

## Lifecycle

1. **Create** — `models.NewSession()` assigns a fresh id (`sess-<hex>`), the
   start time, and runs `Begin` to record the target (`session.TargetID` and
   `session.Target` human-readable typed name).
2. **Run** — the pipeline populates entities, edges, observations, claims,
   findings, evidence, and risk; each stage appends to `sess.Stages`.
3. **Persist** — `internal/session.Store.Save` writes
   `sessions/<id>.session.json` (owner-only, mode 0600). The store directory
   is `session.dir` (default `./sessions`).
4. **Reopen** — `nzinga analyze|findings|evidence|graph|report` load the
   latest session via `Store.List` (newest first by file modification time) and
   `Store.Load`. `list`, `analyze`, and every latest-session command operate on
   this newest run.

## Contents

| Field | Meaning |
|-------|---------|
| `id`, `target_id`, `target` | run and target identity |
| `profile`, `start`, `end`, `stages` | run metadata and stage log |
| `domains`, `hostnames`, `ips`, `people`, `emails`, `usernames`, `social_accounts`, `repositories`, `certificates`, `asns`, `organizations` | discovered entities |
| `observations` | raw normalized data points |
| `claims` | higher-level assertions formed during correlation |
| `graph_nodes`, `graph_edges` | the relationship graph |
| `findings` | rule results |
| `evidence` | provenance artifacts |
| `risk_score`, `risk_level` | target risk |
| `output_dir`, `errors` | run bookkeeping |
| `attributes` | summarized analysis context for reporting |

## Storage details

- Files: `<session-dir>/<id>.session.json`, mode 0600.
- `session.Store.List()` returns ids **newest-first by file modification
  time**, so the latest session is always `ids[0]` — this ordering is
  unit-tested (older revisions sorted by id and implicitly picked stale runs).
- Errors in loading a missing session surface cleanly as command errors; the
  latest-session commands accept either a session id or a file path.

## Targets

Target selection is independent of sessions. `target.Set` registers a target
and makes it current; state persists to `target.state`
(`~/.config/qyvora/nzinga/targets.json`, mode 0600) so a target chosen in one
process survives to the next. See `docs/CLI.md` (`target`) and
`docs/Security-Model.md` (authorization gate).