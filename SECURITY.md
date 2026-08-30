# Security Policy

## Authorized use only

NZINGA is an **authorized use** intelligence framework. It performs OSINT
collection from public sources and must only be operated against targets you
own or are explicitly authorized to research. Unauthorized use may violate law
and policy in your jurisdiction and is out of the project's scope by design.
Every live run carries an authorization gate (the `-y/--authorized` flag or
`QYVORA_AUTHORIZED=true`); without it the framework refuses to execute live
sources. See the [Security Model](docs/Security-Model.md).

## Hardening guarantees

The framework applies defense measures even against its own operators:

- A shared hardened HTTP client: context cancels on interruption, fixed
  timeouts, response-size caps, and an off-origin redirect guard (SSRF).
- Output escaping in every renderer (HTML is escaped, never injected).
- Honest confidence instead of fabricated completeness: a seven-value
  confidence dimension and a "not observed" state keep absence from being
  reported as absence-proof.

## Reporting a vulnerability

Please report security vulnerabilities **privately** — do not open a public
issue for them.

- **Contact:** create a private advisory in this repository (GitHub Security
  → Report a vulnerability), or contact the maintainers per `GOVERNANCE.md`.
- **What to include:**
  - affected version / commit,
  - description of the issue and its impact,
  - steps to reproduce,
  - any suggested mitigation.

## Supported versions

The latest release and the `main` branch are supported. Security fixes land
in the next release and are backported only to the latest release branch.

## Our commitment

We treat reports confidentially, respond within a reasonable window, and
acknowledge reporters in the release notes unless anonymity is requested.
Abusing this framework against unauthorized targets is not a bug report — it
is misuse, and out of scope for the project.