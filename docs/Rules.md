# Detection Rules

Rules run during the ANALYZE stage over the normalized session. They produce
`Finding` objects carrying a rule id, severity, confidence, category, affected
target, and evidence. Findings are merged by `Fingerprint()` so repeated runs
are stable, and false positives / resolved findings are excluded from risk.

Rule engine: `internal/rules` (interface + engine) and `internal/rules/builtin`
(the rule set). All builtin rules report their metadata in `rules.All()` and
in the `capabilities` catalog.

## OSINT-001 — Username reuse across sources

- **Category:** `identity-reuse`
- **Severity:** informational
- **Result:** the sharing reveals that the same human operates multiple
  platform accounts.

Requires the same username/handle observed on at least two distinct platforms
(e.g. GitHub + Twitter). Information from a single platform does not fire.

## OSINT-002 — Infrastructure overlap across domains

- **Category:** `network`
- **Severity:** medium
- **Result:** two separate domains resolve through the same IP address,
  which is weak evidence that the domains are operated by the same
  organization.

Requires: the session holds at least two distinct domains, and hostnames of
each domain share a common IP edge (`resolves_to`). The finding attributes
carry the shared address as its literal value (the IP entity's `Address`),
**never** the graph node id — a known regression is guarded by a unit test.

## OSINT-003 — Personally identifying email exposed in public registries

- **Category:** `pii-exposure`
- **Severity:** medium
- **Result:** a mailbox is observable in registry data (WHOIS) or certificate
  logs (crt.sh), where it is publicly queryable.

Only fires when the observation source is a public registry source
(`whois` or `crt.sh`). Simulation/offline observations alone do not fire it.

## OSINT-004 — DNS wildcard resolves unknown hostnames

- **Category:** `dns-wildcard`
- **Severity:** informational
- **Result:** the zone answers records for hostnames that were never
  enumerated, expanding the attack surface.

Fires on a wildcard observation (`dns.wildcard=true` recorded on the session
and its observation stream).

## Session attribute summary

During ANALYZE the session also receives a `dns.wildcard` attribute and a
compact claim/relationship summary in `session.Attributes` for convenient
reporting; the rule engine reads both observations and attributes.

## Writing a rule

A rule implements:

```go
type Rule struct {
    ID         string
    Name       string
    Category   string
    Severity   models.Severity
    Confidence models.Confidence
    Detect     func(ctx *rules.Context) []*models.Finding
}
```

`rules.Engine` evaluates all rules against one session, collects findings,
deduplicates by fingerprint, and sorts by severity (descending), then rule id.
Rules must be deterministic: the same session yields the same findings in the
same order (enforced by tests).