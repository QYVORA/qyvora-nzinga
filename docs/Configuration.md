# nzinga Configuration

Configuration is resolved in this order (later overrides earlier):

1. Built-in defaults.
2. A YAML config file, searched at the locations below.
3. Environment variables (`QYVORA_NZINGA_*`).
4. CLI flags.

Config file search directories (first match wins):

- `$QYVORA_NZINGA_CONFIG` explicit path, else:
- `~/.config/qyvora/nzinga/`
- the working directory (`./config.yaml`, `./nzinga.yaml`)
- `$XDG_CONFIG_HOME/qyvora/nzinga/` when set

The file is `config.yaml` with type `yaml`. A missing config file is not an
error; a malformed one is.

## Environment variables

All keys map to `QYVORA_NZINGA_<KEY>` with `.` and `-` replaced by `_`:

| Key | Env var |
|-----|---------|
| `collection.timeout_seconds` | `QYVORA_NZINGA_COLLECTION_TIMEOUT_SECONDS` |
| `sources.github.token` | `QYVORA_NZINGA_SOURCES_GITHUB_TOKEN` |
| `authorized` | `QYVORA_NZINGA_AUTHORIZED` |
| `target.state` | `QYVORA_NZINGA_TARGET_STATE` |

## Key reference

### Profiles

`profile` selects collection depth/width: `quick`, `standard` (default), `deep`.

### Output and logging

| Key | Default | Meaning |
|-----|---------|---------|
| `output` | `terminal` | default output mode |
| `verbose` | `false` | verbose logs |
| `quiet` | `false` | quiet logs |
| `json` | `false` | structured output |
| `authorized` | `false` | pre-authorize targets (consent gate) |
| `log.level` | `info` | log level |

### Reporting

| Key | Default | Meaning |
|-----|---------|---------|
| `report.dir` | `reports` | report output directory |
| `report.format` | `terminal` | default report format |

### Session and target state

| Key | Default | Meaning |
|-----|---------|---------|
| `session.dir` | `./sessions` | session store directory |
| `target.state` | `~/.config/qyvora/nzinga/targets.json` | persisted target manager state (0600) |

### Collection (shared hardened client)

| Key | Default | Meaning |
|-----|---------|---------|
| `collection.timeout_seconds` | `15` | per-request timeout |
| `collection.source_concurrency` | `1` | bounded source parallelism during a run (≥1; 1 = sequential) |
| `collection.user_agent` | framework UA | User-Agent sent on requests |
| `collection.max_response_bytes` | `1048576` | response body cap |
| `collection.redirects` | `false` | follow redirects (off = raw response) |
| `collection.http_proxy` | `` | outbound HTTP proxy URL |
| `collection.max_retries` | `2` | retries for transient failures |
| `collection.rate_limit_per_second` | `2` | token-bucket rate cap |

### Sources

Each source has `enabled`; disabled sources never run.

| Key | Default | Meaning |
|-----|---------|---------|
| `sources.crt_sh.enabled` | `true` | crt.sh certificate transparency |
| `sources.dns.enabled` | `true` | DNS resolution |
| `sources.whois.enabled` | `true` | registry WHOIS |
| `sources.whois.port` | `43` | WHOIS TCP port |
| `sources.github.enabled` | `true` | GitHub public API |
| `sources.github.token` | `` | optional GitHub token |
| `sources.simulation.enabled` | `true` | offline simulation dataset |

> Note: the `crt.sh` source id contains a dot, which collides with the config
> key delimiter. Its config key intentionally uses an underscore:
> `sources.crt_sh.enabled` (the canonical id remains `crt.sh`).

## Example

```yaml
profile: standard
verbose: false
authorized: false

report:
  dir: reports
  format: terminal

collection:
  timeout_seconds: 30
  user_agent: nzinga/0.1
  max_response_bytes: 4194304
  redirects: false
  http_proxy: ""
  max_retries: 3
  rate_limit_per_second: 1

sources:
  crt_sh:
    enabled: true
  dns:
    enabled: true
  whois:
    enabled: true
    port: 43
  github:
    enabled: true
    token: ""
  simulation:
    enabled: true
```