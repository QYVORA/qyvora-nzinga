# Release

## Versioning

The version is embedded at build time via `-ldflags`:

```sh
go build -ldflags "-X github.com/QYVORA/qyvora-nzinga/internal/version.Version=<tag> \
    -X github.com/QYVORA/qyvora-nzinga/internal/version.Commit=<sha> \
    -X github.com/QYVORA/qyvora-nzinga/internal/version.Date=<builddate> \
    -X github.com/QYVORA/qyvora-nzinga/internal/version.BuildUser=<user>" ./cmd/nzinga
```

Unstamped builds report the compile-time default and `commit none`. Release
artifacts must **never** report a dev/unstamped build (QYVORA output spec,
section 4). The `Makefile` stamps all four variables:

```sh
make build          # bin/nzinga, stamped with VERSION/COMMIT/DATE/USER
make install        # system-wide install (PREFIX=/usr/local, typically root)
make install-user   # per-user install under ~/.local
make uninstall      # remove system install
make uninstall-user # remove user install
```

The install layout also ships a Hicolor icon and a `.desktop` entry to
`share/applications` (see the top of the `Makefile`).

## Self-update

`nzinga updates` runs the SHAKA-derived self-update flow:

- Bare `updates` checks whether a newer release exists and reports.
- `updates --install` downloads, verifies, and installs the newer release.
- The mechanism uses signed/verified version metadata; a missing or invalid
  metadata response degrades honestly (no silent partial install).

## Release checklist

1. `make check` is green (fmt, vet, unit tests).
2. End-to-end verification across the required surface:
   - `assess --sim` offline demo for each target type
     (`example.com`, `example.net`, `example.org`, a username, an
     organization, an IP address);
   - every report format (`terminal`, `markdown`, `html`, `json`, `yaml`);
   - the `--events` JSONL stream (envelope + verbs);
   - `--dry-run` plan output;
   - the authorization gate (declined → exit 1, granted → proceeds);
   - the console REPL (`sources`, `capabilities`, `assess`,
     `findings`, `evidence`, `graph`, `report`);
   - `target set/list/show` across processes.
3. Confirm no stray `sessions/` or `reports/` artifacts in the repository
   root after verification runs.
4. Stamp the version and build release artifacts with the correct ldflags.
5. Update `CHANGELOG.md` and tag the release.

## Version

Current release version: `v0.1.0`.