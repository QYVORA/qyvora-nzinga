# Changelog

All notable changes to NZINGA are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Human-centric OSINT dork templates** — 430 username enumeration search
  dorks derived from the Sherlock project (MIT licensed), covering 400+ social
  platforms and web services. New dork categories:
  `username`, `name`, `email`, `employer` (human-focused) plus `exposed-docs`,
  `login-panels`, `subdomains` (infrastructure-focused). Templates embedded at
  build time in `internal/search/dorks/human/` and `internal/search/dorks/infra/`
  subdirectories.
- **Username dorks are search expressions, not profile URLs** — each Sherlock
  profile check is converted to a `site:`/`inurl:` dork so every template is a
  query a search provider can execute. Direct profile-URL checks and
  WhatsMyName-derived data are intentionally not shipped (share-alike
  licensing), so nothing is claimed that the provider path cannot actually run.
- **Custom wordlist support** — config keys `sources.search.custom_wordlist_path`
  (path to custom YAML file) and `sources.search.builtin_enabled` (default true).
  Custom templates merge with built-in catalog, or replace it entirely when
  `builtin_enabled=false`. Custom files validated against DorkTemplate schema
  on load; duplicate IDs with built-in templates are rejected.
- **Extended target type support** — search source now supports `TargetUsername`
  and `TargetOrganization` in addition to `TargetDomain`. Source outputs include
  `NodeUsername`, `NodeEmail`, and `NodeSocialAccount` entity types for
  human-centric reconnaissance.
- **Data attribution** — NOTICE file documents the Sherlock data source (MIT)
  with license terms and transformation process. Data is deduplicated by
  domain, filtered for NSFW sites, and converted to search dorks. No upstream
  application code or license files vendored.
- **Transformation script** — `scripts/transform-dorks.go` one-time tool to
  parse Sherlock `data.json` and emit Nzinga YAML templates. Script filters
  NSFW sites, converts profile URLs to `site:` dorks, validates placeholders,
  and generates human/infra category files.

### Changed

- **Dork loading** — `internal/search/dork.go` now recursively loads YAML files
  from subdirectories via `walkDir` function. `go:embed` directive updated to
  include `dorks/human/*.yaml` and `dorks/infra/*.yaml`. Total embedded
  templates: 477 across 12 categories (5 original + 7 new).
- **Unified version system** — `internal/version` identity now also carries
  official QYVORA contact details (website, support, location), surfaced by
  `nzinga version` in terminal and machine formats.
- **Contact details** — the `version` command, README, and `SECURITY.md`
  surface official QYVORA contact: https://qyvora.org ·
  qyvorasec@gmail.com · Tamale, Ghana.
- **Owner-domain accuracy** — `apexDomainOf` now honors a curated two-label
  public-suffix table (`example.co.uk`, `blog.example.com.au`, …) so inferred
  owner domains are registrable domains instead of TLD fragments, and returns
  empty for IP literals so no invalid owner is claimed.
- **Machine-output purity** — informational messages move to stderr when a
  machine-readable format is active.
- **ANSI hygiene** — terminal colors are disabled when stdout is piped or
  redirected or `NO_COLOR` is set; the console `clear` command only emits
  control sequences to an interactive terminal.
- Fatal config/event errors no longer call `os.Exit(1)` directly; they surface
  through `Execute`'s exit-code contract.

### Added

- **Search engine dorking** — expanded from 30 to 477 dork templates across
  12 YAML category files (original: general, documents, social, technology,
  exposed-services; new: username, name, email, employer, exposed-docs,
  login-panels, subdomains). The CLI `dork` command and console `dork`/`dorks`
  commands scan a configured search provider and render results with source,
  snippet and `StateInferred` / `ConfidencePossible` status (results are
  unverified).
- **Search intelligence source** — collector stage `search` (opt-in,
  `sources.search.enabled=false` by default) feeds surfaced search hits into
  evidence with caps and categorized dork coverage. Config: `search.provider`,
  `search.endpoint`, `search.token`, `search.method`, `search.query_param`,
  `sources.search.max_queries` (default 25), `sources.search.categories`,
  `sources.search.custom_wordlist_path`, and `sources.search.builtin_enabled`.
- **Anti-automation honesty** — when a provider responds with a CAPTCHA /
  challenge or HTTP 429 rate limit, NZINGA reports
  `anti-automation challenge detected and not bypassed` (or a rate-limit
  notice) instead of fabricating results; no CAPTCHA or anti-bot defenses are
  ever bypassed. A provider with no endpoint configured yields an explicit
  configuration error unless `--sim` is used.
- Exit-code contract (0 success / 1 runtime / 2 usage / 130 interrupted).
- Build identity (`internal/version`) stamped by Makefile and release CI.
- Brand banner (amber #FFB000 crown emblem) and 512px icon + desktop entry.
- Configuration loading via viper (`QYVORA_NZINGA_*` env namespace,
  `-c/--config`), profiles quick/standard/deep.
- Structured output contract: terminal/json/markdown/html/yaml rendering from
  a shared session/report model (no stubbed renderers).
- Session model and persistence (`sessions/*.session.json`, mode 0600).
- Event envelope (schema_version 1.0, framework `nzinga`) with JSONL emission.
- Intelligence source interface, registry, shared hardened HTTP client, and
  collectors: crt.sh, DNS, WHOIS, GitHub plus an offline simulation source.
- Evidence, Observation, and Claim model types with content hashing.
- Relationship graph across discovered entities.
- Correlation stage producing findings from observations/claims.
- Builtin rules engine (OSINT-001..004) with deterministic evaluation.
- Risk scoring (0-100, S1-S4 levels).
- Pipeline stages DISCOVER -> COLLECT -> NORMALIZE -> CORRELATE -> ANALYZE
  -> VALIDATE -> REPORT.