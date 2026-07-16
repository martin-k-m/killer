//! Command-line interface definition (clap).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Killer — a fast, extensible code quality and security analysis engine.
#[derive(Debug, Parser)]
#[command(
    name = "killer",
    version,
    about = "A fast, extensible code quality and security analysis engine.",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan a project directory and print an analysis report.
    Scan {
        /// Path to the project to scan (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Suppress the report body and print only the summary line.
        #[arg(long)]
        quiet: bool,

        /// Exit with a non-zero status if any critical/high issues are found.
        #[arg(long)]
        fail_on_issues: bool,

        /// Do not record a snapshot in the project intelligence history.
        #[arg(long)]
        no_record: bool,
    },

    /// Run `.klr` attack scripts against a target and report vulnerabilities.
    Test {
        /// A `.klr` file or a directory of them. Defaults to the `[klr]
        /// directory` from config, or the current directory.
        path: Option<PathBuf>,

        /// Run a built-in suite instead of files (e.g. `--suite web`).
        #[arg(long)]
        suite: Option<String>,

        /// Base URL that relative attack targets resolve against.
        #[arg(long)]
        url: Option<String>,

        /// Also run any static `.klr` rules against this project directory.
        #[arg(long, default_value = ".")]
        project: PathBuf,

        /// Number of worker threads for parallel execution (0/absent = auto).
        #[arg(long, num_args = 0..=1, default_missing_value = "0")]
        parallel: Option<usize>,

        /// Output format: `terminal` (default) or `json`.
        #[arg(long, default_value = "terminal")]
        format: String,

        /// Do not write results to `.killer/results/`.
        #[arg(long)]
        no_save: bool,

        /// Exit non-zero if any vulnerability is found.
        #[arg(long)]
        fail_on_issues: bool,
    },

    /// Render a report from the latest saved test results.
    Report {
        /// Project directory (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Write a self-contained HTML report instead of terminal output.
        #[arg(long)]
        html: bool,

        /// Output path for the HTML report.
        #[arg(long, default_value = "killer-report.html")]
        out: PathBuf,
    },

    /// Explain a security issue id, e.g. `killer explain KLR-SQLI`.
    Explain {
        /// The issue id to explain.
        issue_id: String,
    },

    /// Show the recorded security-score history and trend for a project.
    History {
        /// Project directory (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Review the lines changed in the working tree (or a diff range).
    Review {
        /// Project directory (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Review only staged changes.
        #[arg(long)]
        staged: bool,

        /// Diff against this base ref (e.g. `origin/main`).
        #[arg(long)]
        base: Option<String>,

        /// Exit non-zero if any blocking (critical/high) issue is found.
        #[arg(long)]
        fail_on_issues: bool,
    },

    /// Run the full CI gate: scan + `.klr` tests + review of the diff.
    Ci {
        /// Project directory (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Diff base ref for the review step (e.g. `origin/main`).
        #[arg(long)]
        base: Option<String>,
    },

    /// Manage GitHub integration (generate a CI workflow).
    Github {
        #[command(subcommand)]
        action: GithubAction,
    },

    /// Create a default `.killer.toml` configuration file.
    Init {
        /// Directory to write the config into (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Overwrite an existing config file.
        #[arg(long)]
        force: bool,
    },

    /// Print version and build information.
    Version,
}

/// Actions for `killer github`.
#[derive(Debug, Subcommand)]
pub enum GithubAction {
    /// Write a GitHub Actions workflow that runs the Killer gate.
    Enable {
        /// Repository root (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Overwrite an existing workflow file.
        #[arg(long)]
        force: bool,
    },
}
