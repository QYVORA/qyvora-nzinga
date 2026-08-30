# Reporting and Events

## Report formats

`nzinga report [--format <f>] [--out <path>]` renders the latest session.

| Format | Purpose |
|--------|---------|
| `terminal` | human-readable console render (default) |
| `markdown` | markdown document |
| `html` | standalone HTML page |
| `json` | machine-readable session dump |
| `yaml` | YAML dump (keys match the JSON field names) |

The default report directory is `report.dir` (`reports`). Terminal rendering
shows run metadata (session id, typed target, profile, timestamps), a risk
summary, discovered-entity counts, claims/observation totals, and the full
finding list with severity, confidence, and status.

The terminal, markdown, and html renderers display the human-readable target
(`session.Target`), falling back to `session.TargetID` when absent.

## Event stream

`--events <target>` writes a JSONL event stream alongside the run; the target
may be `stdout`, `stderr`, or a file path. Every line is one event object with
the shared QYVORA envelope (contract frozen):

```json
{"schema_version":"1.0","timestamp":"...","execution_id":"...",
 "framework":"nzinga","level":"info","event":"scan.started","data":{}}
```

Levels: `info`, `warning`, `error`. Implementation: `internal/events.Stream`
(concurrency-safe, unwritable errors are dropped, never fatal).

### Verb table

| Verb | Meaning |
|------|---------|
| `scan.started`, `scan.completed` | run lifecycle |
| `stage.started`, `stage.completed` | pipeline stage lifecycle (carries `stage` and `work` in data) |
| `domain.discovered`, `organization.discovered`, `hostname.discovered`, `ip.discovered`, `username.discovered`, `email.discovered` | entity discovery |
| `observation.collected` | raw normalized data point |
| `claim.created` | claim formed during correlation |
| `relationship.discovered` | graph edge created |
| `finding.discovered` | rule finding emitted |
| `analysis.completed` | rule engine finished |
| `evidence.collected` | evidence artifact recorded |
| `risk.calculated` | target risk computed |
| `report.generated` | report written |
| `warning`, `error` | degraded operations / failures |

Consumers route on event names, never on terminal output.

## Session persistence

Sessions are the durable source of truth: `sessions/<id>.session.json`
(`session.dir`, mode 0600). Every report render loads from the store — there
is no separate report-only state. See `docs/Sessions.md`.