# nzinga Installation

## Requirements

- Go 1.22+ (release builds)
- No runtime dependencies: nzinga is a single self-contained binary.

## Build from source

```sh
make build
```

produces `bin/nzinga` with version ldflags stamped from `git describe`.
Install everything (binary, PNG icon, desktop entry, pixmap):

```sh
sudo make install PREFIX=/usr/local
```

Layout (`PREFIX=/usr/local`):

```
/usr/local/bin/nzinga
/usr/local/share/applications/nzinga.desktop
/usr/local/share/icons/hicolor/512x512/apps/nzinga.png
/usr/local/share/pixmaps/nzinga.png
```

A staged install is supported for packaging:

```sh
make install DESTDIR=/tmp/stage
```

## Install script

`./install.sh` detects the platform, builds (or downloads the matching
release binary when published), and installs to `~/.local` or `/usr/local`:

```sh
./install.sh
```

Uninstall: remove the four files listed above plus `~/.config/qyvora/nzinga/`
and `~/.local/share/qyvora/nzinga/` if you no longer need your target state,
sessions or history.

## First-run state

State is kept under the QYVORA user config directory and is never installed
with the binary:

| Path | Purpose |
|------|---------|
| `~/.config/qyvora/nzinga/config.yaml` | user configuration |
| `~/.config/qyvora/nzinga/targets.json` | persisted target manager (0600) |
| `~/.qyvora/nzinga_history` | console history |
| `reports/` (cwd) | rendered reports |
| `sessions/*.session.json` | per-run sessions (0600) |

See `docs/Configuration.md` and `docs/Sessions.md` for details.