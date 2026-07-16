# Governance

Killer is an open-source project under the Apache 2.0 license. This document
describes how decisions are made. It is intentionally lightweight — the project
is young, and this will grow with the community.

## Roles

- **Maintainers** review and merge changes, cut releases, and set direction.
  The current maintainer is [@martin-k-m](https://github.com/martin-k-m).
- **Contributors** are anyone who opens an issue or pull request. See
  [CONTRIBUTING.md](CONTRIBUTING.md).

## Decision making

- Small changes (bug fixes, docs, new rules/suites) are merged by a maintainer
  once CI is green and the change fits the project's conventions.
- Larger changes (new commands, `.klr` language changes, new dependencies)
  should start as an issue so the design can be discussed before implementation.
- When there's disagreement, maintainers seek consensus; if none is reached, a
  maintainer makes the final call, favoring the project's stated principles
  (small, dependency-light, honest about scope).

## Releases

Releases follow [Semantic Versioning](https://semver.org). A release requires a
green CI run (format, lint, tests, audit) and an updated
[CHANGELOG.md](CHANGELOG.md). Tagging `vX.Y.Z` triggers the release pipeline.

## Becoming a maintainer

Sustained, high-quality contributions — code, review, triage, docs — are the
path to maintainership. Maintainers may invite active contributors to join.

## Code of Conduct

All participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
