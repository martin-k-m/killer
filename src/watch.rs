//! A dependency-free file watcher used by `killer watch`.
//!
//! There is no filesystem-notification crate here (that would pull in a large
//! platform-specific dependency, against the project's zero-heavy-deps rule).
//! Instead the watcher takes periodic *snapshots* — a map from each scanned
//! source file to its last-modified time — and [`diff`]s consecutive snapshots
//! to decide what changed. The scan honors the same ignore rules as `killer
//! scan`, so build artifacts and `.killer/` state never trigger a rerun.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::UNIX_EPOCH;

use crate::config::Config;
use crate::scanner;

/// A point-in-time view of the project's source files: path → mtime (in
/// nanoseconds since the Unix epoch).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    files: BTreeMap<String, u128>,
}

impl Snapshot {
    /// Number of files captured.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the snapshot captured no files.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// The set of files that changed between two snapshots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub removed: Vec<String>,
}

impl Changes {
    /// Whether anything changed at all.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.removed.is_empty()
    }

    /// Total number of changed files.
    pub fn count(&self) -> usize {
        self.added.len() + self.modified.len() + self.removed.len()
    }

    /// Every changed path, added+modified+removed, sorted.
    pub fn all_paths(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self
            .added
            .iter()
            .chain(&self.modified)
            .chain(&self.removed)
            .map(String::as_str)
            .collect();
        v.sort_unstable();
        v
    }
}

/// Capture a snapshot of `root`, honoring `config`'s ignore rules.
///
/// Files whose modification time cannot be read are simply omitted, so they
/// register as "removed" until they become readable again.
pub fn snapshot(root: &Path, config: &Config) -> Snapshot {
    let scan = scanner::scan(root, config);
    let mut files = BTreeMap::new();
    for file in &scan.files {
        if let Some(mtime) = mtime_nanos(&root.join(&file.path)) {
            files.insert(file.path.clone(), mtime);
        }
    }
    Snapshot { files }
}

/// Compute what changed going from `old` to `new`.
pub fn diff(old: &Snapshot, new: &Snapshot) -> Changes {
    let mut changes = Changes::default();

    for (path, mtime) in &new.files {
        match old.files.get(path) {
            None => changes.added.push(path.clone()),
            Some(prev) if prev != mtime => changes.modified.push(path.clone()),
            Some(_) => {}
        }
    }
    for path in old.files.keys() {
        if !new.files.contains_key(path) {
            changes.removed.push(path.clone());
        }
    }

    changes.added.sort();
    changes.modified.sort();
    changes.removed.sort();
    changes
}

/// Last-modified time of a file in nanoseconds since the Unix epoch.
fn mtime_nanos(path: &Path) -> Option<u128> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(modified.duration_since(UNIX_EPOCH).ok()?.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(entries: &[(&str, u128)]) -> Snapshot {
        Snapshot {
            files: entries.iter().map(|(p, m)| (p.to_string(), *m)).collect(),
        }
    }

    #[test]
    fn no_changes_when_identical() {
        let a = snap(&[("src/main.rs", 1), ("src/lib.rs", 2)]);
        let b = a.clone();
        assert!(diff(&a, &b).is_empty());
    }

    #[test]
    fn detects_added_modified_removed() {
        let old = snap(&[("a.rs", 1), ("b.rs", 2), ("c.rs", 3)]);
        let new = snap(&[("a.rs", 1), ("b.rs", 9), ("d.rs", 4)]);
        let changes = diff(&old, &new);
        assert_eq!(changes.added, vec!["d.rs"]);
        assert_eq!(changes.modified, vec!["b.rs"]);
        assert_eq!(changes.removed, vec!["c.rs"]);
        assert_eq!(changes.count(), 3);
        assert!(!changes.is_empty());
    }

    #[test]
    fn snapshot_reads_source_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        std::fs::create_dir(dir.path().join("target")).unwrap();
        std::fs::write(dir.path().join("target").join("junk.rs"), "// ignored").unwrap();

        let snap = snapshot(dir.path(), &Config::default());
        // The source file is captured; the build artifact under target/ is not.
        assert_eq!(snap.len(), 1);
        assert!(!snap.is_empty());
    }
}
