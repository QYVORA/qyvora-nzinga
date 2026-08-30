# Changelog

All notable changes to NZINGA are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial scaffold: module `github.com/QYVORA/qyvora-nzinga`, `go 1.26.5`.
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