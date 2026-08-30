# Safety and Authorization

nzinga is a **read-only** intelligence collection framework. Its safety model
is architectural, not incidental: every collection operation carries metadata
(class, risk level, target type, authorization requirement, whether it changes
remote state, whether it is reversible), and the gate is **authorization, not
technical escalation**.

Implementation: `internal/safety` (operation metadata + `IsAllowed`) and the
target consent gate in `internal/target` / the CLI.

## Operation metadata

```go
type OperationMetadata struct {
    ID, Name, Description string
    Class                 Class        // discovery | enumeration | analysis
    Risk                  models.RiskLevel
    TargetType            string
    AuthRequired          bool
    Confirm               bool
    ChangesState          bool
    Reversible            bool
}
```

The known operations (`nzinga.certificate.enumerate`, `nzinga.dns.resolve`,
`nzinga.whois.lookup`, `nzinga.username.enumerate`, `nzinga.analyze`) are all:

- **Risk S1** (no harmful side effects);
- **read-only** (`ChangesState == false`);
- **reversible**;
- surfaced in the `capabilities` catalog with their safety metadata.

`IsAllowed(op, safeOnly)`: with the safe-only posture, operations at risk ≥ S3
are refused; any operation is refused if it changes remote state and is not
reversible. Because the initial set is all S1 read-only, the safe default
posture serves every capability without degrading the tool.

## The authorization gate

Live sources execute **only** for an authorized target:

| Method | Effect |
|--------|--------|
| `-y` / `--authorized` flag | grants authorization non-interactively |
| `QYVORA_NZINGA_AUTHORIZED=true` | grants authorization via environment |
| interactive prompt | operator confirms scope |
| `--sim` | demo mode; offline simulation dataset (auto demo-auth) |
| declined / absent | refuses with **exit code 1** and a clear message |

`target.Set` refuses to register a target that is not authorized
(`ErrUnauthorizedTarget`) — the gate cannot be bypassed by pre-selecting a
target. A target stores its `Authorization` record (granted, at, scope, by,
method) and persists with the manager state (mode 0600).

The offline `simulation` source is the only source that runs without an
authorization; it never touches the network.

## Hardened collection

Independent of the consent gate, the shared HTTP client applies defensive
defaults even against its own operator — response caps, refused cross-origin
redirects (SSRF guard), bounded retries, rate limiting. See
`docs/Sources.md` and `docs/Configuration.md`.

## Safety invariants (tested)

- No known source operation changes remote state; all are reversible S1.
- Safe-only posture accepts every known operation.
- Off-dangerous operations are refused in safe mode.
- Simulated/offline data never leaks to the network.
- Normalization never fabricates entities; untypable observations remain
  observations only.