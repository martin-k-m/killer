//! Dependency rules.
//!
//! Deliberately empty. Manifest analysis *is* implemented, but not as a
//! [`Rule`](crate::analyzer::Rule): the [`Rule`](crate::analyzer::Rule) trait is
//! per-file, whereas dependency analysis needs a whole-project view (a manifest
//! plus every source file that might import from it). It therefore lives in its
//! own modules and commands:
//!
//! - [`crate::dependencies`] — `killer dependencies`: inventory across six
//!   ecosystems (`Cargo.toml`, `package.json`, `requirements.txt`, `go.mod`,
//!   `pom.xml`, `*.csproj`), with duplicate-version and possibly-unused
//!   detection. Local manifests only — there is no CVE/advisory dataset.
//! - [`crate::graph`] — `killer graph`: the structural import/dependency graph
//!   those checks are derived from.
//!
//! The [`Category::Dependencies`](crate::analyzer::Category::Dependencies)
//! variant is kept so report grouping and the rule registry stay ready should a
//! genuinely per-file dependency rule ever be added here.
