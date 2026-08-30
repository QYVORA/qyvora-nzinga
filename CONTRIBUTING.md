# Contributing

Thanks for contributing to NZINGA.

## Code of conduct

By participating you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Project scope

NZINGA is an **authorized open-source intelligence** framework. It collects
from public sources, normalizes and correlates the results, applies
deterministic rules to surface evidence-backed findings, and reports honestly.
It is deliberately **not** a scanner, **not** an exploitation tool, and
**not** a mass-enumeration platform. It answers "what can be learned about a
single, authorized target from public sources?" — nothing more. Contributions
that push against those boundaries will be declined even if technically
impressive.

Design goals: see [Architecture](docs/Architecture.md) and
[Security Model](docs/Security-Model.md). The honest-confidence rule is
normative: absence is never reported as absence-proof, and no finding is ever
fabricated to make output look complete.

## Development setup

```sh
go test ./...      # offline; requires no live network
make vet
make fmt
```

Run everything with one command:

```sh
make check      # fmt + vet + test
```

See [Architecture](docs/Architecture.md) for layout and style conventions.

## How to contribute

1. **Discuss first.** Open an issue for non-trivial features or API changes
   before writing code.
2. **Branch** from `main`: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`.
3. **Implement**, following package conventions (see `docs/Architecture.md`
   "codes of conduct" — no TODOs, no `panic("not implemented")`, no stubs).
4. **Fuzz the honesty contract:** new sources must degrade honestly (report
   non-collectable as such), never fabricate findings, and respect the
   shared hardened client (timeouts, size caps, no off-origin redirects).
5. **Open a PR.** Explain what changed and why, and which tests cover it.

## Review and merging

- Small fixes and docs: reviewed and merged by a maintainer.
- New features and API changes: discussed and reviewed; behavioural changes
  to the exit-code contract, the event schema, or the reporting formats are
  treated as breaking changes.
- Security-sensitive changes (authz gate, HTTP hardening, confidence model):
  reviewed by a maintainer against the [Security Model](docs/Security-Model.md).