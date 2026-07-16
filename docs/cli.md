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

## `killer report [PATH]`

Render the most recent saved test run.

| Flag | Description |
| ---- | ----------- |
| `--html` | Write a self-contained HTML report instead of terminal output. |
| `--out <PATH>` | Output path for the HTML report (default `killer-report.html`). |

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

## `killer doctor [PATH]`

Diagnose a project's Killer setup and environment — git availability, a valid
`.killer.toml`, the configured `.klr` directory, and a writable `.killer/`.

| Flag | Description |
| ---- | ----------- |
| `--fix` | Repair what can be fixed automatically (e.g. create a config). |

## `killer version`

Print the version, active scan rules, known issue ids, and built-in suites.
