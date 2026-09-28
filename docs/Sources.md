# Intelligence Sources

Sources implement the collection layer. Every source declares stable metadata
(id, name, category, capabilities, safety) that drives the `sources` and
`capabilities` catalogs and the plan shown by `--dry-run`.

Source interface: `internal/intelligence/sources/source.go`
(`Source`, `Registry`). The registry orders sources deterministically by id;
`Registry.Enabled(config)` respects each source's `sources.<id>.enabled` flag.
Source ids that contain dots (e.g. `crt.sh`) map to underscore config keys
(`sources.crt_sh.enabled`), a viper-key collision that is unit-tested.

## Catalog

| id | name | category | capabilities |
|----|------|----------|--------------|
| `crt.sh` | crt.sh Certificate Transparency | certificate | `certificate.enumerate`, `subdomain.enumerate` |
| `dns` | DNS | dns | `dns.resolve` |
| `github` | GitHub public API | code | `username.lookup`, `repository.enumerate` |
| `search` | Search-engine dorking | search | `search.dork` |
| `whois` | WHOIS registry | registry | `whois.lookup` |
| `simulation` | Offline simulation dataset | simulation | `domain.enumerate`, `subdomain.enumerate`, `dns.resolve`, `whois.lookup`, `certificate.enumerate`, `username.lookup`, `repository.enumerate`, `email.enumerate` |

All source operations are risk `S1`, read-only, reversible, and never change
remote state (see `docs/Security-Model.md`).

## Behavior

- **crt.sh** (`crt_sh.go`) — queries a certificate transparency search for a
  domain, emitting certificate SAN hostnames (and email SANs). Needs the
  shared HTTP client; in offline mode the demo dataset is used.
- **dns** (`dns.go`) — A/AAAA/NS/MX/TXT/CNAME resolution for enumerated
  hostnames. Detects wildcard zones (`dns.wildcard`).
- **whois** (`whois.go`) — registry WHOIS lookup over TCP on port 43
  (`sources.whois.port`), emitting registrant contact info (emails, org).
- **github** (`github.go`) — username/platform lookups and repository
  enumeration via the GitHub public API. Optional token in
  `sources.github.token`.
- **search** (`search.go`) — **opt-in** dorking source; `sources.search.enabled`
  defaults to `false`, so it never runs in a default collection pass. It
  executes curated query templates from the embedded dork catalogue against a
  provider and emits `NodeUsername`, `NodeEmail`, and `NodeSocialAccount`
  observations. It accepts `TargetDomain`, `TargetUsername`, and
  `TargetOrganization` targets, and, like other live sources, requires an
  authorized target. It needs a sanctioned provider: `search.provider` = `api`
  (with `search.endpoint`) or `simulation` (the only provider that needs no
  endpoint). Enabling the source with no provider configured yields an explicit
  configuration error. Search hits are unverified index references and are
  always recorded `StateInferred`/`ConfidencePossible` — never as confirmed
  facts. The framework never bypasses CAPTCHA or anti-automation controls: a
  challenged surface or an HTTP 429 response is reported as a typed
  blocked/rate-limit notice, and results are never fabricated.
- **simulation** (`simulate.go`) — the offline dataset. Never touches the
  network, requires no authorization, and covers `example.com`,
  `example.net`, and `example.org`.

## Dork catalogue

The embedded catalogue holds exactly 477 templates across 12 categories:
human-focused (username, name, email, employer), infrastructure
(exposed-services, exposed-docs, login-panels, subdomains), and the original
general, documents, social, and technology. The username category's 430
templates are search expressions (`site:<host>` / `inurl:` queries) derived
exclusively from the MIT-licensed Sherlock project data; they are not profile
URLs. Every template contains a `{target}` placeholder and is validated at
load. A custom wordlist (`sources.search.custom_wordlist_path`) merges with
this catalogue, or replaces it when `sources.search.builtin_enabled=false`;
custom templates are validated against the DorkTemplate schema on load and
duplicate IDs with built-in templates are rejected.

## Offline simulation dataset

- `example.com`: wildcard zone, cert SANs (`www`, `api`, `cdn`, `staging`,
  `mail`, `blog`, `dev`, `files`, `remote`, `status`, `vpn`), `mail.example.net`
  SAN, emails `admin@example.com` and `abuse@example.com`, registrant
  "Example Corp", NS `ns1/ns2.example.net`, the A record `203.0.113.10` and
  AAAA `2001:db8::10`, and a Mail example.net hostname sharing the same IP so
  OSINT-002 fires from the example.net side.
- `example.net`: resolves `mail.example.net → 203.0.113.10` (shared IP).
- `example.org`: silent (no findings).
- Other values: the source reports that the offline data set does not cover
  the value (honest degradation — no fabricated observations).

## Shared hardened client

`internal/intelligence/sources/client.go` applies defensive defaults for every
HTTP source (see `docs/Configuration.md` → `collection.*`):

- per-request context cancellation/timeouts;
- response bodies capped at `collection.max_response_bytes`;
- redirects refused unless explicitly enabled; cross-origin redirects are
  refused even then (SSRF guard);
- bounded retries for transient failures (GET/HEAD/OPTIONS only);
- optional per-second rate limiter;
- User-Agent applied from `collection.user_agent` unless the source overrides it.

These behaviors are covered by unit tests (`client_test.go`).