# CLI Reference

`nzinga` follows the shared QYVORA tier grammar:

```
nzinga <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon`, `exploit`, or `report`. Every pre-tier command remains available as a hidden alias.

## recon

| Command | Purpose |
|---------|---------|
| `nzinga recon analyze` | Re-run the rule engine and risk assessment over the latest session |
| `nzinga recon assess` | Run the full intelligence pipeline: discover→collect→normalize→correlate→analyze→validate→report |
| `nzinga recon capabilities` | List nzinga's machine-readable tool contract |
| `nzinga recon collect` | Collect intelligence for a target type |
| `nzinga recon completion` | Generate shell completion scripts |
| `nzinga recon discover` | Run the discovery stage only: resolve and validate the target |
| `nzinga recon dork` | Run search-engine dorking over a domain (opt-in search source) |
| `nzinga recon dorks` | List the embedded dork query templates by category |
| `nzinga recon evidence` | List evidence collected in the latest session |
| `nzinga recon findings` | List findings from the latest session |
| `nzinga recon graph` | Render the relationship graph from the latest session |
| `nzinga recon help` | Help about any command |
| `nzinga recon relationship` | Inspect the intelligence relationship graph of the latest session |
| `nzinga recon report` | Render an intelligence report from the latest session |
| `nzinga recon sources` | List intelligence sources and their capabilities |
| `nzinga recon target` | Manage collection targets |
| `nzinga recon tui` | start the interactive terminal application |
| `nzinga recon updates` | Check for and install nzinga updates |
| `nzinga recon version` | Print nzinga version and build information |

## exploit

| Command | Purpose |
|---------|---------|
| `nzinga exploit analyze` | Re-run the rule engine and risk assessment over the latest session |
| `nzinga exploit assess` | Run the full intelligence pipeline: discover→collect→normalize→correlate→analyze→validate→report |
| `nzinga exploit capabilities` | List nzinga's machine-readable tool contract |
| `nzinga exploit collect` | Collect intelligence for a target type |
| `nzinga exploit completion` | Generate shell completion scripts |
| `nzinga exploit discover` | Run the discovery stage only: resolve and validate the target |
| `nzinga exploit dork` | Run search-engine dorking over a domain (opt-in search source) |
| `nzinga exploit dorks` | List the embedded dork query templates by category |
| `nzinga exploit evidence` | List evidence collected in the latest session |
| `nzinga exploit findings` | List findings from the latest session |
| `nzinga exploit graph` | Render the relationship graph from the latest session |
| `nzinga exploit help` | Help about any command |
| `nzinga exploit relationship` | Inspect the intelligence relationship graph of the latest session |
| `nzinga exploit report` | Render an intelligence report from the latest session |
| `nzinga exploit sources` | List intelligence sources and their capabilities |
| `nzinga exploit target` | Manage collection targets |
| `nzinga exploit tui` | start the interactive terminal application |
| `nzinga exploit updates` | Check for and install nzinga updates |
| `nzinga exploit version` | Print nzinga version and build information |

## report

_No report-tier modules._

## Utilities

| Command | Purpose |
|---------|---------|
| `nzinga analyze` | Re-run the rule engine and risk assessment over the latest session |
| `nzinga assess` | Run the full intelligence pipeline: discover→collect→normalize→correlate→analyze→validate→report |
| `nzinga collect` | Collect intelligence for a target type |
| `nzinga discover` | Run the discovery stage only: resolve and validate the target |
| `nzinga dork` | Run search-engine dorking over a domain (opt-in search source) |
| `nzinga dorks` | List the embedded dork query templates by category |
| `nzinga evidence` | List evidence collected in the latest session |
| `nzinga findings` | List findings from the latest session |
| `nzinga graph` | Render the relationship graph from the latest session |
| `nzinga relationship` | Inspect the intelligence relationship graph of the latest session |
| `nzinga sources` | List intelligence sources and their capabilities |
| `nzinga target` | Manage collection targets |
| `nzinga tui` | start the interactive terminal application |

