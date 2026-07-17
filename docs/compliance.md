# Compliance mapping

`killer compliance` maps the findings Killer **actually detects** onto a
security framework — today **OWASP Top 10 (2021)** — with a CWE reference per
mapped finding.

> This is a *mapping*, not a certification audit. It tells you which framework
> categories the issues Killer found relate to. It does not certify SOC 2,
> ISO 27001, NIST, or OWASP compliance.

## Usage

```sh
killer compliance          # terminal report
killer compliance --json   # machine-readable
```

`killer compliance` runs a scan and also folds in any confirmed vulnerabilities
from your latest saved `killer test` run.

## How categories are reported

Each OWASP category comes out as one of three states — and the distinction is
the point:

| Status | Meaning |
| ------ | ------- |
| **Warning** | A finding mapping to this category was detected. |
| **Passed** | Killer has a rule covering this category and it found nothing. |
| **Not assessed** | Killer has **no rule** that maps to this category. |

"Not assessed" is deliberate: Killer will **never** mark a category `Passed`
when it cannot actually check it. Categories like A10 (SSRF) or A09 (Logging
failures) show as *Not assessed* rather than giving false assurance.

## Example

```
KILLER COMPLIANCE REPORT

Framework:  OWASP Top 10 (2021)

  ✓ A01:2021  Broken Access Control                        Passed
  • A02:2021  Cryptographic Failures                       Not assessed
  ⚠ A03:2021  Injection                                    Warning
      → OS Command Injection (dangerous-command)
  ⚠ A07:2021  Identification and Authentication Failures   Warning
      → Use of Hard-coded Credentials (hardcoded-secret)

CWE references
  CWE-78 OS Command Injection  ×3
  CWE-798 Use of Hard-coded Credentials  ×3
```

## Extending the mapping

The mapping table lives in [`mappings/compliance.toml`](../mappings/compliance.toml),
embedded into the binary at build time (like the built-in `.klr` suites). It is
TOML rather than YAML on purpose — Killer ships zero heavy runtime dependencies
and already parses TOML, so no new parser is pulled in. To cover a new finding,
add a `[[mapping]]` entry; to add a framework, add `[[category]]` entries.
