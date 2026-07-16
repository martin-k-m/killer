# Security Policy

Killer is a security tool, so we take the security of Killer itself seriously.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, report privately using GitHub's
[private vulnerability reporting](https://github.com/martin-k-m/killer/security/advisories/new)
(Security → Advisories → *Report a vulnerability* on the repository).

Include, where possible:

- a description of the issue and its impact,
- steps to reproduce (a minimal `.klr` file or project is ideal),
- affected version (`killer version`), and
- any suggested remediation.

We aim to acknowledge reports within **72 hours** and to provide a resolution or
mitigation timeline after triage. We'll credit reporters in the changelog unless
you prefer to remain anonymous.

## Scope

Relevant reports include, for example:

- Killer executing untrusted `.klr` input in an unsafe way.
- Path handling that lets a scan or report read or write outside the project.
- Crashes or resource exhaustion triggered by crafted source or `.klr` files.

## Using Killer responsibly

`killer test` sends real requests to whatever target you point it at. Only run
attacks against systems you own or are explicitly authorized to test. Killer is
for defensive security testing of your own software.
