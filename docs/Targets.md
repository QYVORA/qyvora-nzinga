# nzinga Targets

A **target** is the subject of an assessment. nzinga supports five typed
targets; the type selects which sources run and which capabilities apply.

| Type | Prefix | Example | What runs |
|------|--------|---------|-----------|
| `domain` | `domain:` | `example.com` | crt.sh, DNS, WHOIS, GitHub, simulation |
| `organization` | `org:` | `org:Acme` | GitHub, simulation |
| `username` | `username:` | `jane` | GitHub, simulation |
| `ip` | `ip:` | `203.0.113.10` | simulation |
| `infrastructure` | `infrastructure:` | `203.0.113.0/24` | crt.sh, DNS, WHOIS, GitHub, simulation |

A bare value (no `type:`) is typed by the shared target resolver — a
registered domain resolves to `domain`, anything IPv4/range resolves to
`ip`/`infrastructure`, otherwise it is treated as a username/organization
candidate.

## Selecting a target

```sh
# one-shot by value
nzinga assess example.com
nzinga assess "org:Acme Corp"

# persistent console target
> use example.com
> run

# persisted target state (survives runs)
> target set example.com
> status           # shows the saved target
```

## Authorization is per target

The safety gate (`docs/Security-Model.md`) is **authorization, not just
confirmation**. A live collection only runs against a target that has been
explicitly authorized:

```sh
nzinga assess --authorized example.com          # authorize for this run
QYVORA_AUTHORIZED=true nzinga assess example.com
nzinga target set --authorized example.com      # persist authorization
```

The offline `simulation` source is the only source that runs without
authorization, and it only ever uses its deterministic `example.*` dataset.

## Target state

Concrete targets are persisted via the target manager so a console session
can resume or re-run against the same subject later:

```sh
nzinga target set --authorized example.com
nzinga target show
nzinga target list
```

State lives in `~/.config/qyvora/nzinga/targets.json` (0600).