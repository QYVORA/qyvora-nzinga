NZINGA
Authorized Open-Source Intelligence Framework

NZINGA is the QYVORA OSINT / intelligence framework: authorized open-source
intelligence collection, cross-source correlation, and evidence-driven
reporting. It collects from public sources, normalizes the results, correlates
observations into claims, applies deterministic rules to surface findings, and
produces reproducible evidence-backed reports in terminal, JSON, Markdown,
HTML, and YAML.

NZINGA is one of six QYVORA security frameworks:

| Framework | Focus                        | Accent            |
|-----------|------------------------------|-------------------|
| SHAKA     | Active Directory security    | Royal blue        |
| AKSUM     | Network/configuration audit  | Gold              |
| JABARI    | SIEM/security analytics      | Lime grain        |
| TOHA3EE   | Offensive/attack tooling     | Red               |
| ANANSI    | Platform utilities & ops    | Cyan              |
| NZINGA    | OSINT / intelligence         | Amber #FFB000     |

## Intent

NZINGA answers one question, honestly: "what can be learned about a target
exclusively from public, open sources?" It is not a scanner and it is not an
exploitation tool. It collects, normalizes, correlates, and reports. Findings
are evidence-backed; every claim traces to collected observations, and no
absence is ever reported as absence-proof.

## Operate only within authorization boundaries

NZINGA performs authorized reconnaissance only. Live collection against
third-party infrastructure requires explicit authorization of the operator,
confirmable in the tool (the `-y/--authorized` gate). The gate is enforced in
the CLI: without authorization, live sources are not executed. The `--sim`
flag runs against an offline deterministic dataset with no network activity
and no authorization requirement.

- Authorize a run: `nzinga assess -y domain:example.com`
- Explore offline: `nzinga assess --sim`
- Start the interactive console: `nzinga`

## Build

Requires Go 1.26+.

```
make build
make check    # gofmt + vet + test
```

The binary is written to `bin/nzinga`.

## Install

```
./install.sh            # per-user install under ~/.local
./install.sh --system   # system-wide install under /usr/local
```

## Quick start

```
nzinga assess --sim                          # offline demo pipeline
nzinga assess -y domain:example.com --sim    # demo dataset embed
nzinga sources list                          # enabled public sources
nzinga capabilities                          # advertised tool contract
nzinga report session --format json          # JSON report (no stubs)
```

Typical usage against a live target:

```
nzinga assess -y domain:example.com --profile standard -o json
nzinga findings -f json
nzinga relationship graph
```

`-y/--authorized` (or `QYVORA_AUTHORIZED=true`) asserts the operator holds
authorization for the target. `--dry-run` plans the run and shows which
sources would be executed without touching the network.

## Exit codes

`0` success, `1` runtime failure, `2` usage error, `130` interrupted (128+SIGINT).
Automation must distinguish these without parsing output.

## Output formats

`terminal | json | markdown | html | yaml` all render from the same shared
session/report model. `-o json`, `-o yaml`, `-o markdown`, `-o html`, or the
`--json` shorthand are fully functional; there are no stub renderers.

## Architecture

Collectors (public sources) -> normalization -> entity/relationship graph ->
correlation -> rules -> risk -> reporting. See `docs/Architecture.md`,
`docs/Rules.md`, and `docs/Reporting.md` for the design.

## Documentation

- `docs/Architecture.md` - design, decisions, sibling-repo derivations
- `docs/Getting-Started.md` - install, first runs, profiles
- `docs/CLI.md` - every command and flag
- `docs/Configuration.md` - config keys, precedence, profiles
- `docs/Targets.md` - target typing and authorization gate
- `docs/Reporting.md` - the five output formats
- `docs/Rules.md` - builtin rules OSINT-001..004 and finding lifecycle
- `docs/Correlation.md` - observation -> claim -> finding pipeline
- `docs/Security-Model.md` - authorization, SSRF guard, size caps, honest confidence
- `docs/Installation.md` - build/install/uninstall for all platforms
- `docs/Roadmap.md` - direction and open items

## Development

See `CONTRIBUTING.md`. Tests cover collection (offline), normalization,
correlation, rules determinism, risk, rendering, and the authorization gate.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.