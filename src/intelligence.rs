//! The Project Intelligence Engine.
//!
//! Killer scans — and now it *remembers*. Every scan is recorded as a
//! [`Snapshot`] under `.killer/history/`, so Killer can show how a project's
//! security score and finding counts move over time ("Improved +16, fixed 23").
//!
//! Storage is a set of JSON files rather than a real database: it needs no C
//! toolchain (keeping the build portable), is trivially diffable, and is more
//! than enough for a local, single-project history. The on-disk layout mirrors
//! the Phase 4 spec:
//!
//! ```text
//! .killer/
//! ├── project.json      # summary index (this module)
//! ├── history/          # one Snapshot per scan
//! └── results/          # .klr test runs (see results.rs)
//! ```

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::report::Report;

/// A point-in-time record of a project's health.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Sortable id (typically epoch seconds); also the history file stem.
    pub id: String,
    /// Human-readable timestamp.
    pub timestamp: String,
    /// Optional short label (e.g. a git commit or tag).
    #[serde(default)]
    pub label: Option<String>,
    pub security_score: u32,
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub warning: usize,
    pub info: usize,
    pub files: usize,
    pub lines_of_code: usize,
}

impl Snapshot {
    /// Build a snapshot from a completed scan report.
    pub fn from_report(id: &str, timestamp: &str, report: &Report) -> Snapshot {
        let c = report.severity_counts();
        Snapshot {
            id: id.to_string(),
            timestamp: timestamp.to_string(),
            label: None,
            security_score: report.score(),
            total_findings: c.total(),
            critical: c.critical,
            high: c.high,
            warning: c.warning,
            info: c.info,
            files: report.stats.files,
            lines_of_code: report.stats.lines_of_code,
        }
    }
}

/// A summary index written to `.killer/project.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectIndex {
    pub name: Option<String>,
    pub created: Option<String>,
    pub last_updated: Option<String>,
    pub snapshot_count: usize,
    pub latest_score: Option<u32>,
    pub best_score: Option<u32>,
}

/// The delta between the first and most recent snapshots.
#[derive(Debug, Clone, PartialEq)]
pub struct Trend {
    pub first: Snapshot,
    pub latest: Snapshot,
    /// `latest.security_score - first.security_score` (can be negative).
    pub score_change: i64,
    /// Net reduction in findings since the first snapshot (0 if it grew).
    pub findings_fixed: usize,
    /// Net increase in findings since the first snapshot (0 if it shrank).
    pub findings_added: usize,
    pub snapshot_count: usize,
}

/// A JSON-backed store for project intelligence rooted at `<root>/.killer`.
pub struct IntelStore {
    root: PathBuf,
}

impl IntelStore {
    pub fn new(root: &Path) -> Self {
        IntelStore {
            root: root.to_path_buf(),
        }
    }

    fn killer_dir(&self) -> PathBuf {
        self.root.join(".killer")
    }

    fn history_dir(&self) -> PathBuf {
        self.killer_dir().join("history")
    }

    fn index_path(&self) -> PathBuf {
        self.killer_dir().join("project.json")
    }

    /// Record a snapshot, updating the summary index. Returns the file written.
    pub fn record(&self, snapshot: &Snapshot, project_name: Option<&str>) -> Result<PathBuf> {
        let dir = self.history_dir();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;

        let safe = sanitize(&snapshot.id);
        let path = dir.join(format!("{safe}.json"));
        let json = serde_json::to_string_pretty(snapshot).context("serialize snapshot")?;
        std::fs::write(&path, json)
            .with_context(|| format!("failed to write {}", path.display()))?;

        self.update_index(snapshot, project_name)?;
        Ok(path)
    }

    fn update_index(&self, snapshot: &Snapshot, project_name: Option<&str>) -> Result<()> {
        let mut index = self.load_index().unwrap_or_default();
        if index.created.is_none() {
            index.created = Some(snapshot.timestamp.clone());
        }
        if project_name.is_some() {
            index.name = project_name.map(str::to_string);
        }
        index.last_updated = Some(snapshot.timestamp.clone());
        index.latest_score = Some(snapshot.security_score);
        index.best_score = Some(match index.best_score {
            Some(best) => best.max(snapshot.security_score),
            None => snapshot.security_score,
        });
        index.snapshot_count = self.load_history().map(|h| h.len()).unwrap_or(0);

        let json = serde_json::to_string_pretty(&index).context("serialize index")?;
        std::fs::write(self.index_path(), json).context("write project.json")?;
        Ok(())
    }

    /// Load the summary index if present.
    pub fn load_index(&self) -> Option<ProjectIndex> {
        let text = std::fs::read_to_string(self.index_path()).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Load all snapshots, sorted oldest-first by id.
    pub fn load_history(&self) -> Result<Vec<Snapshot>> {
        let dir = self.history_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut snapshots = Vec::new();
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("failed to read {}", dir.display()))?
            .flatten()
        {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(snap) = serde_json::from_str::<Snapshot>(&text) {
                    snapshots.push(snap);
                }
            }
        }
        snapshots.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(snapshots)
    }

    /// Compute the trend across all recorded snapshots, if there are at least two.
    pub fn trend(&self) -> Result<Option<Trend>> {
        let history = self.load_history()?;
        Ok(compute_trend(&history))
    }
}

/// Compute a [`Trend`] from an ordered snapshot list (needs at least two).
pub fn compute_trend(history: &[Snapshot]) -> Option<Trend> {
    if history.len() < 2 {
        return None;
    }
    let first = history.first().unwrap().clone();
    let latest = history.last().unwrap().clone();
    let score_change = latest.security_score as i64 - first.security_score as i64;
    let findings_fixed = first.total_findings.saturating_sub(latest.total_findings);
    let findings_added = latest.total_findings.saturating_sub(first.total_findings);
    Some(Trend {
        first,
        latest,
        score_change,
        findings_fixed,
        findings_added,
        snapshot_count: history.len(),
    })
}

fn sanitize(slug: &str) -> String {
    slug.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(id: &str, score: u32, total: usize) -> Snapshot {
        Snapshot {
            id: id.to_string(),
            timestamp: format!("t-{id}"),
            label: None,
            security_score: score,
            total_findings: total,
            critical: 0,
            high: 0,
            warning: 0,
            info: 0,
            files: 10,
            lines_of_code: 100,
        }
    }

    #[test]
    fn trend_needs_two_snapshots() {
        assert!(compute_trend(&[]).is_none());
        assert!(compute_trend(&[snap("1", 78, 30)]).is_none());
    }

    #[test]
    fn trend_reports_improvement_and_fixes() {
        let history = vec![snap("1", 78, 30), snap("2", 88, 12), snap("3", 94, 7)];
        let t = compute_trend(&history).unwrap();
        assert_eq!(t.score_change, 16); // 94 - 78
        assert_eq!(t.findings_fixed, 23); // 30 - 7
        assert_eq!(t.findings_added, 0);
        assert_eq!(t.snapshot_count, 3);
    }

    #[test]
    fn trend_reports_regression() {
        let history = vec![snap("1", 90, 5), snap("2", 70, 15)];
        let t = compute_trend(&history).unwrap();
        assert_eq!(t.score_change, -20);
        assert_eq!(t.findings_fixed, 0);
        assert_eq!(t.findings_added, 10);
    }

    #[test]
    fn record_and_reload_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = IntelStore::new(dir.path());
        store.record(&snap("100", 78, 30), Some("demo")).unwrap();
        store.record(&snap("200", 94, 7), Some("demo")).unwrap();

        let history = store.load_history().unwrap();
        assert_eq!(history.len(), 2);
        // Sorted oldest-first.
        assert_eq!(history[0].id, "100");
        assert_eq!(history[1].security_score, 94);

        let index = store.load_index().unwrap();
        assert_eq!(index.name.as_deref(), Some("demo"));
        assert_eq!(index.latest_score, Some(94));
        assert_eq!(index.best_score, Some(94));
        assert_eq!(index.snapshot_count, 2);

        let trend = store.trend().unwrap().unwrap();
        assert_eq!(trend.score_change, 16);
        assert_eq!(trend.findings_fixed, 23);
    }
}
