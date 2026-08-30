# Development

## Prerequisites

- Go 1.26+ (the module pins cobra v1.10.2 and chzyer/readline v1.5.1).
- A network-free module cache is sufficient for builds once `go.sum` is
  populated.

## Building

```sh
make build          # builds bin/nzinga with version ldflags
go build ./...      # plain build of every package
```

In environments without a git checkout (no `.git`), Go's VCS stamping fails;
use `-buildvcs=false`:

```sh
go build -buildvcs=false ./...
go test -buildvcs=false ./...
```

## Verification gate

`make check` runs `fmt` → `vet` → `test`:

```sh
go vet ./...
go test ./... -count=1 -timeout 60s
```

Individual targets:

```sh
make fmt            # gofmt -w cmd internal pkg
make vet            # go vet ./...
make test           # go test ./... -count=1 -timeout 60s
make test-race      # same with -race, 120s timeout
```

## Testing

Test files live beside their packages. Coverage today:

- `pkg/models` — dedupe identity (source+key+target+value), fingerprint
  stability over map/slice order, persistence roundtrip, confidence ordering.
- `internal/session` — save/load roundtrip, mtime ordering (newest first),
  missing-session errors, owner-only file mode.
- `internal/target` — persistence across managers, unauthorized-target
  refusal, corrupt-state fallback, parent-directory creation.
- `internal/intelligence/normalization` — apex A records never create hostname
  entities, edge creation is order-independent when the hostname observation
  arrives later, out-of-zone hostnames never attribute to the queried zone,
  `within`/`apexDomainOf`/`isHostnameLike` helpers, observation dedupe.
- `internal/rules/builtin` — each rule fires on a crafted context and does not
  fire without its prerequisite; the OSINT-002 IP-address regression; engine
  determinism (same session → same findings, same order); rule contract fields.
- `internal/risk` — level thresholds (0/1/35/60/80), score bounds, category
  exposure, false-positive/resolved exclusion, empty assessment.
- `internal/safety` — S1 read-only assertions, posture rejection rules.
- `internal/intelligence/sources` — hardened client (UA, response cap,
  redirect SSRF guard, default no-follow, same-origin follow, retry recovery,
  cancellation, proxy), registry enablement incl. the `crt.sh` dot-key case.
- `internal/pipeline` — stage order, contracted event envelope, demo target
  findings, offline IP roundtrip, invalid-IP rejection, nil-session guard.

## Code layout

- `internal/` framework code (single `go.mod` root at the repository root).
- `pkg/models` the shared data model; import it from any package, never the
  reverse.
- `cmd/nzinga` the program entry point.

## Contribution notes

- No `TODO` markers, no panic stubs, no fabricated data; unhealthy paths
  degrade honestly and are logged.
- New source operations must register safety metadata with risk S1.
- SHAKA-derived modules note their lineage in the doc comment (see
  `docs/Architecture.md`).