# nzinga Quick Start

nzinga is a **read-only intelligence (OSINT) collection and analysis
framework**. It discovers public facts about a target you already own or have
permission to assess, normalizes them into entities, correlates them into
claims, detects risks with evidence-backed rules, and renders reports you can
export, audit, and share.

## 1. Install

See `docs/Installation.md`. Two supported paths:

```sh
# Homebrew-style one-liner (Linux/macOS)
./install.sh

# or via the Makefile
make build            # produces bin/nzinga
sudo make install     # /usr/local/bin + icons + .desktop entry
```

Verify:

```sh
nzinga version
nzinga --help
```

## 2. Run the interactive console

Bare `nzinga` starts the console (plain-line mode when stdin is not a TTY):

```sh
nzinga
```

The console keeps a persistent working **target** and **profile**. Start with:

```
help      # every command
show      # console target, profile, directory, saved target
```

## 3. Try the offline simulation first

The `simulation` source ships a deterministic offline dataset for
`example.com`, `example.net` and `example.org`. It never touches the network
and always runs authorized:

```sh
# plan only, no network
nzinga assess --dry-run -y --sim example.com

# full run against the offline dataset
nzinga assess -y --sim example.com
```

You will see findings (e.g. exposed admin emails, overlapping hosting,
consistency checks), an amber risk score out of 100, and the relationship
graph between the domain and its discovered hosts.

## 4. Assess a real target you control

Once you confirm authorization, run live sources:

```sh
nzinga assess --authorized example.com
nzinga assess --authorized "org:Acme Corp"
nzinga assess --authorized "username:jane"
```

Authorization is a consent gate: every live source is skipped unless the run
is explicitly authorized (`-y/--authorized` or `QYVORA_AUTHORIZED=true`).

## 5. Read the output

```sh
nzinga findings          # detections behind the risk score
nzinga evidence          # the sha256-hashed facts backing each finding
nzinga graph             # entity relationship graph
nzinga relationship show # relationship type/count summary
nzinga report -f json    # machine-readable session
nzinga report -f markdown -o report.md
```

## Next steps

- `docs/CLI.md` — every command and flag.
- `docs/Configuration.md` — config file, environment variables, profiles.
- `docs/Targets.md` — the five target types and what each runs.
- `docs/Rules.md` — the builtin detection rules.
- `docs/Reporting.md` — report formats and sessions.