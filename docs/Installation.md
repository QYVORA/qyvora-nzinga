# nzinga Installation

## Requirements

- Go 1.26+ (the version pinned by `go.mod`)
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

`./install.sh` is a zero-config installer. It detects your operating system,
CPU architecture, and shell, downloads the matching prebuilt binary from
GitHub Releases (verifying its SHA-256 against the published `checksums.txt`),
and falls back to building from source when no release is available yet. By
default it installs under `~/.local` and adds the directory to your `PATH`
(sudo is only used when installing system-wide):

```sh
curl -fsSL https://raw.githubusercontent.com/QYVORA/qyvora-nzinga/main/install.sh | bash
```

Or from a checkout:

```sh
./install.sh
```

On Linux the installer also installs the nzinga app icon and a `.desktop`
entry (NVIDIA-style brand icon in your app menu), so nzinga appears with its
logo — not as a bare command.

### Windows

```powershell
irm https://raw.githubusercontent.com/QYVORA/qyvora-nzinga/main/install.ps1 | iex
```

Installs the checksum-verified binary under `%LOCALAPPDATA%\Programs\nzinga\bin`,
adds it to your user PATH, installs the nzinga icon, and creates a Start Menu
shortcut. Pin `$env:NZINGA_VERSION` or `$env:NZINGA_PREFIX` to control the
version or install location.

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