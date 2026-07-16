//! Dependency rules.
//!
//! Reserved for Phase 2, which will parse manifests (`Cargo.toml`,
//! `package.json`, `requirements.txt`, …) and build a dependency graph to flag
//! vulnerable or outdated packages.
//!
//! The [`Category::Dependencies`](crate::analyzer::Category::Dependencies)
//! variant already exists so that report grouping and the rule registry are
//! ready for these rules to be added without structural changes. No dependency
//! rules ship in Phase 1.
