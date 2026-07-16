//! Command-line interface definition (clap).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Killer — a Rust security platform: scan code, run `.klr` attacks, and gate CI.
#[derive(Debug, Parser)]
#[command(
    name = "killer",
    version,
    about = "A Rust security platform — scan code, run .klr attacks, review diffs, and gate CI.",
    long_about = "Killer analyzes a project for vulnerabilities, runs adversarial .klr tests \
against a live service, tracks a security score over time, reviews git diffs, and \
provides a single CI gate.",
    after_help = "EXAMPLES:\n  \
killer scan .                         Static analysis with a 0-100 score\n  \
killer test --suite web --url URL     Run a built-in attack suite\n  \
killer review --base origin/main      Review the lines a change touched\n  \
killer ci                             Full gate for CI (scan + rules + review)\n\n\
Docs: https://github.com/martin-k-m/killer/tree/main/docs",
    propagate_version = true
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

    /// Generate adversarial inputs and (optionally) fire them at a target.
    ///
    /// Surfaces the same fuzz generators the `.klr` `mutate` construct uses.
    /// Without `--url` it just prints the inputs it would send.
    Fuzz {
        /// List the available generators and exit.
        #[arg(long)]
        list: bool,

        /// The request field to mutate (fuzz values are sent as this key).
        #[arg(long, default_value = "input")]
        field: String,

        /// Comma-separated generator names (default: all of them).
        #[arg(long)]
        generators: Option<String>,

        /// Absolute or relative target URL. Relative targets resolve against
        /// the configured `base_url`. Without this, inputs are only printed.
        #[arg(long)]
        url: Option<String>,

        /// HTTP method to use when a target is set.
        #[arg(long, default_value = "POST")]
        method: String,

        /// Project directory used to resolve config/`base_url` (default: `.`).
        #[arg(long, default_value = ".")]
        project: PathBuf,

        /// Exit non-zero if any input triggers a fault or an unreachable target.
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

    /// Build a structural graph of the project (files, imports, dependencies).
    Graph {
        /// Project directory to graph (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Emit the graph as JSON instead of a terminal summary.
        #[arg(long)]
        json: bool,
    },

    /// Benchmark scan performance over a project.
    Benchmark {
        /// Project directory to benchmark (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Number of scan iterations to time.
        #[arg(long, default_value = "5")]
        runs: usize,
    },

    /// Watch source files and re-scan whenever they change.
    Watch {
        /// Project directory to watch (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Seconds between checks for changes.
        #[arg(long, default_value = "2")]
        interval: u64,
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

        /// Also scaffold a `security-tests/` directory with a starter `.klr`
        /// file so you can run `killer test` right away.
        #[arg(long)]
        scaffold: bool,
    },

    /// Diagnose a project's Killer setup and environment.
    Doctor {
        /// Project directory (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Repair what can be fixed automatically (e.g. create a config).
        #[arg(long)]
        fix: bool,
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
