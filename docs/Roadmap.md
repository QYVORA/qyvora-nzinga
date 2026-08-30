# nzinga Roadmap

Status markers: **done** (shipped), **next** (planned, highest value first),
**backlog** (accepted, unprioritized). Capability and CLI additions are
[*framework-compatible*](docs/Architecture.md): the exposed contract
(`pkg/models`, events, report formats, exit codes) does not silently change.

## Collection

- **done** — First-party sources: crt.sh (certificate transparency), DNS,
  WHOIS, GitHub, offline simulation dataset.
- **done** — Shared hardened HTTP/TCP client: timeouts, retries, rate limit,
  response caps, optional proxy, configurable UA.
- **done** — `--dry-run` source plan; per-source `enabled` config; bounded
  `collection.source_concurrency` with order-stable results.
- **next** — Shodan/AbuseIPDB/Censys adapters behind their auth tokens.
- **next** — Source health checks (`nzinga sources --health`).
- **backlog** — Synthetic dataset coverage for organization and IP targets.

## Analysis

- **done** — Normalization vocabulary, correlation into claims, builtin
  rules, risk assessment with evidence verification.
- **done** — Observation provenance: `source_type`, `observed_at`,
  `collected_at`, `raw_reference`, content hash.
- **next** — Rule packs (user-loadable rule sets) with a stable rule schema.
- **next** — Temporal consistency checks using `observed_at` (e.g. certificate
  validity windows).
- **backlog** — Machine-learned entity resolution for near-duplicate hosts.

## Reporting & sessions

- **done** — Terminal, markdown, HTML, JSON and YAML reports; session store
  with replay (`nzinga findings/evidence/graph/report` on the latest session).
- **next** — Signed session snapshots (Ed25519) so evidence can be shared
  tamper-evidently.
- **backlog** — HTML + template reports.

## Safety & operations

- **done** — Authorization gate; per-source risk metadata; read-only,
  reversible-by-construction sources; NO_COLOR/tty-aware console.
- **next** — Collection budget enforcement (per-run max requests) integrated
  with the rate limiter.
- **backlog** — opt-in telemetry that is auditable and off by default.

## Packaging & CI

- **done** — Makefile + install.sh; staged `DESTDIR` installs; desktop entry
  and icon; GitHub Actions CI (gofmt, vet, race tests, build, golangci-lint).
- **done** — Cross-platform release workflow with checksums.
- **next** — Homebrew tap formula; container images.

## Framework commitment

- **done** — Machine-readable capability contract with input/output schemas
  (`nzinga capabilities --json` exposes every tool's Schema).
- **next** — MCP server exposing the capability contract to agents.