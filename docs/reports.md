# Reports

`killer report` renders the most recent saved `killer test` run in whichever
format fits your audience. The format flags are mutually exclusive; the default
is the grouped terminal report.

```sh
killer report               # grouped terminal report (default)
killer report --executive   # high-level summary
killer report --technical   # detailed, per-finding
killer report --json        # raw results
killer report --markdown    # Markdown, e.g. for a PR comment
killer report --html        # self-contained HTML file
```

## Executive

For stakeholders. Leads with the **security score** (the latest value recorded
by `killer scan`), a **risk band** (LOW / MEDIUM / HIGH derived from the score
and the run), the headline findings, and concrete recommendations that point at
`killer explain <id>`.

```
KILLER EXECUTIVE REPORT

Project:  payment-api
Security score:  72/100
Risk:  HIGH

Coverage:  128 tested · 3 vulnerable · 0 errored

Major findings
  ✗ sql_login_bypass  [critical]

Recommendations
  → Use parameterized queries / prepared statements.
      killer explain KLR-SQLI
```

## Technical

For engineers. Each confirmed vulnerability lists its **target**, the
**evidence** (which expectations failed and what was observed), the
**remediation**, and a reference — plus any static rule findings with
`file:line`.

## JSON & Markdown

- `--json` emits the full saved run for dashboards and CI.
- `--markdown` produces a table + per-finding sections suitable for pasting
  into a pull request or wiki.

## HTML

`--html` writes a self-contained HTML file (default `killer-report.html`, or
`--out <path>`) with no external assets.
