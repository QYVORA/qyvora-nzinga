# nzinga Architecture

nzinga is an **authorized OSINT and intelligence collection framework**. It
collects data about a declared target from public sources, normalizes it into
a typed intelligence model, correlates it into claims and rule findings, and
produces transparent, reproducible reports and risk scores.

Framework name: `nzinga`. Every artifact (events, sessions, reports) carries
the framework identifier and a shared QYVORA-shaped envelope so downstream
consumers can route on stable keys.

## Layout

```
cmd/nzinga/                  program entry point
internal/
  banner/                    startup identity banner
  capabilities/              machine-readable tool contract catalog
  cli/                       cobra command tree + console REPL
  config/                    viper config: defaults, env, file search
  core/                      the Env shared by commands and the pipeline
  errors/                    user/operator error taxonomy
  events/                    JSONL event envelope + verbs
  exitcode/                  frozen exit-code contract (0/1/2/130)
  intelligence/
    correlation/             claim formation from observations
    domain/                  per-target-type collection orchestration
    normalization/           observation -> entities/edges/evidence
    relationships/           graph edges between entities
    sources/                 Collector interface, registry, client, sources
  logger/                    leveled logger
  output/                    terminal rendering helpers
  pipeline/                  the fixed 7-stage pipeline runner
  reporting/                 session -> report renderers
  risk/                      severity/confidence/impact/exposure -> score
  rules/                     rule engine + metadata
    builtin/                 OSINT-001..004 detection rules
  safety/                    operation safety metadata + authorization model
  selfupdate/                signed-version self-update (SHAKA-derived)
  session/                   session store (persistence) on disk
  target/                    authorized target manager (file-backed)
  version/                   build identity
pkg/models/                  the single source of truth data model
  entity.go, finding.go, evidence.go, graph.go, observation.go,
  session.go, severity.go, confidence.go, target.go, risk.go
```

## Pipeline

One target, one run, seven fixed stages in order:

```
DISCOVER -> COLLECT -> NORMALIZE -> CORRELATE -> ANALYZE -> VALIDATE -> REPORT
```

Implemented by `internal/pipeline` (`Runner.Run`). Semantics:

- **Discover** resolves the target object (`Target`, `TargetID`) and validates
  it (e.g. an `ip` target must be a literal address).
- **Collect** runs the enabled sources against the target through a
  `sources.Registry`. Live sources run only for an **authorized** target; the
  offline `simulation` source is the only source with no authorization
  requirement. Collectors degrade honestly: a failing source is recorded in
  the session's `Errors` and the rest of the run continues.
- **Normalize** converts the observation vocabulary into typed entities
  (`Domain`, `Hostname`, `IP`, `Person`, `Email`, `Username`, `SocialAccount`,
  `Repository`, `Certificate`, `ASN`, `Organization`), relationship edges, and
  evidence items. Normalization never fabricates: values it cannot type remain
  observations only.
- **Correlate** forms claims (identity / infrastructure / attribution /
  exposure / consistency) from observations.
- **Analyze** runs the rule engine; findings are deduplicated by fingerprint.
- **Validate** reports state transitions; risk is computed only over
  non-false-positive, non-resolved findings.
- **Report** writes the requested renderers and (optionally) the JSONL event
  stream.

## Data model

`pkg/models.Session` is the single source of truth for every renderer. It
holds the target identity, all discovered entities, the graph (nodes +
directed edges), observations, claims, findings, evidence, risk score/level,
and per-run stage history. Edges use a typed relationship vocabulary
(`resolves_to`, `hosts`, `belongs_to`, `registers`, `owns`, `uses`,
`controls`, `attributed_to`, `related`).

Observation identity is `source + key + target + value`; findings merge by
`Fingerprint()` (a canonical hash that is independent of map/slice order).

## Authorization and safety

The framework is read-only by design. The gate is **authorization, not
technical escalation**: a target must pass the consent gate (methods: `-y`,
`--authorized`, `QYVORA_AUTHORIZED=true`, interactive prompt, or demo mode
`--sim`) before any live source executes. See `docs/Security-Model.md`.

## Safety posture and risk scoring

All initial source operations are `Risk S1`, read-only, reversible, and they
never change remote state. The safe default posture serves every capability.
Per-finding risk is derived from explicit components (severity, confidence,
per-category exposure) and documented, not an opaque formula; target risk is a
weighted 0..100 score with thresholds (`none`/`low`/`medium`/`high`/`critical`).

## Observations on provenance

Files that are derived from or inspired by the SHAKA project (internal
tooling codebase) are noted with their lineage in the source headers:

- `internal/selfupdate/` — signed version self-update flow (SHAKA-derived).
- `internal/cli/console.go` — readline REPL shell (SHAKA-derived).
- `internal/capabilities/` — machine-readable tool contract (SHAKA-derived).
- `internal/risk/` — transparent severity/confidence risk model (SHAKA-derived).

Where such modules were adapted, they preserve the SHAKA output contract and
only extend it with nzinga's intelligence-specific verbs.