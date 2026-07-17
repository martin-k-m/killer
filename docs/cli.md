# CLI reference

Run `killer --help` or `killer <command> --help` for the authoritative, built-in
help. This page summarizes each command.

## `killer scan [PATH]`

Static analysis of a directory (default `.`). Records a snapshot for `history`.

| Flag | Description |
| ---- | ----------- |
| `--quiet` | Print a one-line summary instead of the full report. |
| `--fail-on-issues` | Exit non-zero if any critical/high issue is found. |
| `--no-record` | Do not record a snapshot in `.killer/history/`. |

## `killer test [PATH]`

Run `.klr` attacks (and static `.klr` rules) against a target.

| Flag | Description |
| ---- | ----------- |
| `--suite <NAME>` | Run a built-in suite (`web`, `api`, `authentication`, `database`, `crypto`, `filesystem`) instead of files. |
| `--url <URL>` | Base URL that relative targets resolve against. |
| `--parallel [N]` | Run across N worker threads (omit N to auto-size to the CPU). |
| `--format <FMT>` | `terminal` (default) or `json`. |
| `--project <DIR>` | Project to run static `.klr` rules over (default `.`). |
| `--no-save` | Do not write results to `.killer/results/`. |
| `--fail-on-issues` | Exit non-zero if any vulnerability is found. |

`PATH` may be a single `.klr` file or a directory of them; it defaults to the
`[klr] directory` in `.killer.toml`, or the current directory.

## `killer dependencies [PATH]`

Analyze the project's declared dependencies across ecosystems, entirely from
local manifests — nothing is fetched.

| Flag | Description |
| ---- | ----------- |
| `--details` | List every dependency (name, version, ecosystem, dev/prod, usage). |
| `--json` | Emit the analysis as JSON (for CI). |

Manifests read: `Cargo.toml`, `package.json`, `requirements.txt`, `go.mod`,
`pom.xml`, and `*.csproj`. Reports per-ecosystem counts, production vs
development split, duplicate versions, and "possibly unused" candidates.
There is **no vulnerability/CVE lookup** — that needs a dataset Killer does not
ship. "Possibly unused" is a best-effort import heuristic (reliable for Cargo,
npm, PyPI, and Go; usage is reported as unknown for Maven and NuGet). See
[dependencies.md](dependencies.md).

## `killer compliance [PATH]`

Map the findings Killer detects onto the **OWASP Top 10 (2021)**, with a CWE
reference per mapped finding.

| Flag | Description |
| ---- | ----------- |
| `--json` | Emit the compliance report as JSON. |

Each category is reported as `Warning` (a mapped finding was detected),
`Passed` (Killer covers it and found nothing), or `Not assessed` (Killer has no
rule for it — never silently "passed"). This is a mapping of what Killer
detects, **not a certification audit**. The mapping table lives in
`mappings/compliance.toml` and is extensible. See [compliance.md](compliance.md).

## `killer graph [PATH]`

Build a structural graph of the project: which source files import which
external modules, and which dependencies each manifest declares. Reports the
most-imported modules, import hotspots, and dependencies that appear to be
declared but unused.

| Flag | Description |
| ---- | ----------- |
| `--json` | Emit the full node/edge graph as JSON instead of a summary. |

Imports are extracted for Rust, JavaScript/TypeScript, Python, Go, Java, and
Ruby; declared dependencies are read from `Cargo.toml`, `package.json`,
`requirements.txt`, and `go.mod`. Usage matching is a heuristic (hyphen/
underscore normalization plus an inline `crate::path` scan for Rust), so the
"possibly unused" list is a hint, not a guarantee. This is a structural graph,
not a semantic/data-flow one.

## `killer benchmark [PATH]`

Time repeated scans of a project and report throughput.

| Flag | Description |
| ---- | ----------- |
| `--runs <N>` | Number of scan iterations to time (default `5`). |

Prints per-run latency, min/avg, and files-per-second / lines-per-second.

## `killer fuzz`

Generate adversarial inputs and, optionally, fire them at a target. Uses the
same generators as the `.klr` `mutate`/`fuzz` construct, so a quick fuzz on the
command line and a `.klr` file exercise the target identically.

| Flag | Description |
| ---- | ----------- |
| `--list` | Print the generator catalog and exit. |
| `--field <NAME>` | Request field to mutate (default `input`). |
| `--generators <CSV>` | Comma-separated generator names (default: all). |
| `--url <URL>` | Target to fire at; relative URLs resolve against the configured `base_url`. Without this, inputs are only previewed. |
| `--method <METHOD>` | HTTP method when a target is set (default `POST`). |
| `--project <DIR>` | Project used to resolve config/`base_url` (default `.`). |
| `--fail-on-issues` | Exit non-zero if any input triggers a 5xx fault or an unreachable target. |

Firing inputs sends the same JSON body a `.klr` `mutate` would. An input is
reported as an *anomaly* when the server answers with a 5xx status (a fault the
input triggered) or the request cannot be completed at all.

## `killer watch [PATH]`

Re-run a scan whenever a source file changes. The watcher polls (it takes
periodic modification-time snapshots and diffs them) rather than subscribing to
OS file events, keeping the zero-heavy-dependency build intact. It honors the
same ignore rules as `killer scan`, so build artifacts and `.killer/` state
never trigger a rerun. Press Ctrl-C to stop.

| Flag | Description |
| ---- | ----------- |
| `--interval <SECS>` | Seconds between checks for changes (default `2`). |

## `killer report [PATH]`

Render the most recent saved test run. The format flags below are mutually
exclusive; the default is the grouped terminal report.

| Flag | Description |
| ---- | ----------- |
| `--executive` | High-level summary: security score, risk band, headline findings, recommendations. |
| `--technical` | Detailed report: evidence, severity, and remediation per finding. |
| `--json` | Emit the raw results as JSON. |
| `--markdown` | Emit a Markdown report (for PR comments, wikis). |
| `--html` | Write a self-contained HTML report instead of terminal output. |
| `--out <PATH>` | Output path for the HTML report (default `killer-report.html`). |

The `--executive` score is the latest value recorded by `killer scan`. See
[reports.md](reports.md).

## `killer history [PATH]`

Show the recorded security-score trend for a project.

## `killer review [PATH]`

Review only the lines a git diff changed.

| Flag | Description |
| ---- | ----------- |
| `--staged` | Review staged changes only. |
| `--base <REF>` | Diff against a base ref (e.g. `origin/main`). |
| `--fail-on-issues` | Exit non-zero on any blocking (critical/high) finding. |

## `killer ci [PATH]`

Run the full gate — scan + static `.klr` rules + review — with a non-zero exit
on any blocking finding. Designed for pipelines.

| Flag | Description |
| ---- | ----------- |
| `--base <REF>` | Diff base ref for the review step. |

## `killer github enable [PATH]`

Write `.github/workflows/killer.yml` so the gate runs on every push and PR.

| Flag | Description |
| ---- | ----------- |
| `--force` | Overwrite an existing workflow file. |

## `killer explain <ISSUE_ID>`

Explain a security issue. Known ids: `KLR-SQLI`, `KLR-PATH-TRAVERSAL`,
`KLR-RATE-LIMIT`, `KLR-SESSION`, `KLR-GENERIC`.

## `killer init [PATH]`

Write a documented `.killer.toml`.

| Flag | Description |
| ---- | ----------- |
| `--force` | Overwrite an existing config file. |
| `--scaffold` | Also create a `security-tests/` directory with a runnable starter `.klr` file. |

## `killer doctor [PATH]`

Diagnose a project's Killer setup and environment — git availability, a valid
`.killer.toml`, the configured `.klr` directory, and a writable `.killer/`.

| Flag | Description |
| ---- | ----------- |
| `--fix` | Repair what can be fixed automatically (e.g. create a config). |

## `killer version`

Print the version, active scan rules, known issue ids, and built-in suites.
