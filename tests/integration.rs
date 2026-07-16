//! End-to-end tests: scan the fixture projects and assert on the findings.

use std::path::{Path, PathBuf};

use killer::analyzer::{Analyzer, Category, Severity};
use killer::config::Config;
use killer::report::Report;
use killer::scanner;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(name)
}

fn analyze(dir: &Path) -> (killer::scanner::ScanResult, Vec<killer::analyzer::Finding>) {
    let config = Config::load(dir).expect("config loads");
    let scan = scanner::scan(dir, &config);
    let findings = Analyzer::with_default_rules(&config).analyze(&scan);
    (scan, findings)
}

#[test]
fn scanner_collects_files_and_languages() {
    let (scan, _) = analyze(&fixture("vulnerable_project"));
    assert!(scan.stats.files >= 2, "should find the fixture files");
    assert!(scan.stats.lines_of_code > 0);
    assert!(scan.stats.languages.contains(&"JavaScript".to_string()));
    assert!(scan.stats.languages.contains(&"Python".to_string()));
}

#[test]
fn vulnerable_project_triggers_security_rules() {
    let (_, findings) = analyze(&fixture("vulnerable_project"));

    // At least one hardcoded secret (JS API key / AWS key).
    assert!(
        findings.iter().any(|f| f.rule == "hardcoded-secret"),
        "expected a hardcoded-secret finding"
    );

    // At least one dangerous command (os.system / subprocess / eval).
    assert!(
        findings.iter().any(|f| f.rule == "dangerous-command"),
        "expected a dangerous-command finding"
    );

    // Security findings should be present and high-severity.
    assert!(findings
        .iter()
        .any(|f| f.category == Category::Security && f.severity <= Severity::High));
}

#[test]
fn vulnerable_project_tracks_todo_and_fixme() {
    let (_, findings) = analyze(&fixture("vulnerable_project"));
    assert!(
        findings.iter().any(|f| f.rule == "todo-tracker"),
        "expected TODO/FIXME markers to be tracked"
    );
}

#[test]
fn clean_project_has_no_blocking_issues() {
    let dir = fixture("clean_project");
    let (scan, findings) = analyze(&dir);
    let report = Report::new("clean".into(), scan.stats, findings);
    assert!(
        !report.has_blocking_issues(),
        "clean project should have no critical/high issues, got: {:#?}",
        report.findings
    );
    assert_eq!(report.score(), 100, "clean project should score 100");
}

#[test]
fn report_renders_and_scores() {
    let (scan, findings) = analyze(&fixture("vulnerable_project"));
    let report = Report::new("vulnerable".into(), scan.stats, findings);

    // Score is reduced by the findings but stays within bounds.
    assert!(report.score() <= 100);
    assert!(report.has_blocking_issues());

    // The rendered report contains the header and a score line.
    let text = report.render_terminal();
    assert!(text.contains("KILLER REPORT"));
    assert!(text.contains("Score:"));
}

#[test]
fn respects_config_rule_toggle() {
    // With secret detection disabled, no hardcoded-secret findings appear.
    let dir = fixture("vulnerable_project");
    let mut config = Config::default();
    config.rules.secret_detection = false;

    let scan = scanner::scan(&dir, &config);
    let findings = Analyzer::with_default_rules(&config).analyze(&scan);

    assert!(
        !findings.iter().any(|f| f.rule == "hardcoded-secret"),
        "disabling secret_detection should remove those findings"
    );
    // Other rules still fire.
    assert!(findings.iter().any(|f| f.rule == "dangerous-command"));
}
