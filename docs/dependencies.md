# Dependency intelligence

`killer dependencies` analyzes your project's declared dependencies across
ecosystems — entirely from local manifest files. Nothing is fetched, and there
is **no vulnerability database**: it answers the questions your own files can
answer.

## Usage

```sh
killer dependencies            # summary + warnings
killer dependencies --details  # full per-dependency table
killer dependencies --json     # machine-readable, for CI
```

## Supported manifests

| Ecosystem | Manifest |
| --------- | -------- |
| Rust (Cargo) | `Cargo.toml` |
| Node (npm) | `package.json` |
| Python (PyPI) | `requirements.txt` |
| Go (modules) | `go.mod` |
| Java (Maven) | `pom.xml` |
| C# (NuGet) | `*.csproj` |

For each dependency Killer records its **name**, **version** (where the manifest
declares one), **ecosystem**, whether it is a **development** or **production**
dependency, and — where detectable — whether it appears to be **used**.

## What it reports

- **Ecosystem counts** — how many packages come from each manifest.
- **Production vs development** split.
- **Duplicate versions** — the same package pinned to more than one version
  (common in monorepos).
- **Possibly unused** — a dependency that is declared but never imported.

## Example

```
KILLER DEPENDENCY ANALYSIS

Ecosystems
  Node (npm)     86 packages
  Rust (Cargo)   42 packages

Production:   104
Development:  24
Total:        128

Warnings
  ⚠ lodash  possibly unused
  ⚠ react   duplicate versions: 18.2.0, 18.3.1
```

## Honest limits

- **No CVE / advisory data.** Killer does not ship a vulnerability database, so
  it does not claim a package is "vulnerable", "malicious", or "typosquatting".
  Those need a dataset that a local, zero-dependency tool cannot carry.
- **"Possibly unused" is a heuristic.** It matches your imports to declared
  package names (with hyphen/underscore normalization, plus an inline
  `crate::path` scan for Rust). It is reliable for Cargo, npm, PyPI, and Go;
  for Maven and NuGet, usage is reported as *unknown* rather than guessed,
  because import forms there do not track package names. Treat the list as a
  prompt to review, not a verdict.
