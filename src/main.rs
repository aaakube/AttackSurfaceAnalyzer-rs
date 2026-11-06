mod collectors;
mod diff;
mod model;
mod procmon;
mod query;
mod report;
mod rules;
mod store;
mod web;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use collectors::{Collector, Sink};
use model::{Kind, Severity};
use report::ReportWriter;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;
use store::Store;

/// Attack Surface Analyzer for Windows: snapshot a system before and after a change
/// (installing software, applying config) and report what it did to the attack surface.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// SQLite database holding all runs.
    #[arg(long, global = true, env = "ASA_DB", default_value = "asa.db")]
    db: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Take a snapshot of the system.
    Collect(CollectArgs),
    /// Compare two runs and report changes.
    Diff(DiffArgs),
    /// Manage stored runs.
    #[command(subcommand)]
    Runs(RunsCommand),
    /// Validate and inspect rule files.
    #[command(subcommand)]
    Rules(RulesCommand),
    /// Import Process Monitor captures to see which process made each change.
    #[command(subcommand)]
    Procmon(ProcmonCommand),
    /// Browse runs and comparisons in a local web UI.
    Serve {
        /// Address to listen on. Keep it on loopback: the UI has no authentication.
        #[arg(long, default_value = "127.0.0.1:8740")]
        listen: String,
        /// Rules file (YAML). Defaults to the built-in rules.
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Open the UI in the default browser.
        #[arg(long)]
        open: bool,
    },
}

#[derive(Args)]
struct CollectArgs {
    /// Identifier for this run. Defaults to a timestamp.
    #[arg(long)]
    run_id: Option<String>,
    /// Collectors to run (comma-separated).
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "files,services,firewall,com,registry,users,certificates,ports,wifi"
    )]
    collectors: Vec<CollectorName>,
    /// Directories the file collector walks (repeatable). Defaults to the system drive.
    #[arg(long = "path", value_name = "DIR")]
    paths: Vec<PathBuf>,
    /// Directories to skip (repeatable), in addition to the default exclusions.
    #[arg(long, value_name = "DIR")]
    exclude: Vec<PathBuf>,
    /// Do not apply the default exclusions (System Volume Information, $Recycle.Bin, ...).
    #[arg(long)]
    no_default_excludes: bool,
    /// Hash file contents (BLAKE3). Slower, but catches same-size, same-mtime edits.
    #[arg(long)]
    hash: bool,
    /// Skip owner/DACL collection.
    #[arg(long)]
    no_acls: bool,
    /// Skip Authenticode verification (files, service and COM server binaries).
    #[arg(long)]
    no_signatures: bool,
    /// Worker threads.
    #[arg(long, default_value_t = default_threads())]
    threads: usize,
    /// Print each non-fatal warning (access denied, ...).
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum CollectorName {
    Files,
    Services,
    Firewall,
    Com,
    Registry,
    Users,
    Certificates,
    Ports,
    Wifi,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Table,
    Json,
    /// One JSON object per line; best for very large diffs.
    Jsonl,
    Sarif,
}

#[derive(Args)]
struct DiffArgs {
    /// Run to compare from (the "before" state).
    base: String,
    /// Run to compare to (the "after" state).
    compare: String,
    /// Rules file (YAML). Defaults to the built-in rules.
    #[arg(long)]
    rules: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "table")]
    format: Format,
    /// Write the report to a file instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Leave out changes below this severity.
    #[arg(long, default_value = "info")]
    min_severity: Severity,
    /// Table format: list at most this many changes, most severe first (0 = all).
    #[arg(long, default_value_t = 200)]
    limit: usize,
    /// JSON formats: include full before/after objects for modified items, not just diffs.
    #[arg(long)]
    objects: bool,
    /// Exit with status 1 if any change is at or above this severity (for CI).
    #[arg(long)]
    fail_on: Option<Severity>,
}

#[derive(Subcommand)]
enum RunsCommand {
    /// List stored runs.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Delete a run and all its objects.
    Delete { id: String },
    /// Dump a run's objects as JSON lines.
    Export {
        id: String,
        #[arg(long)]
        kind: Option<Kind>,
    },
}

#[derive(Subcommand)]
enum ProcmonCommand {
    /// Import a capture saved from Procmon as CSV (File > Save > Comma-Separated Values).
    /// Only events that modify files or the registry are kept.
    Import {
        file: PathBuf,
        /// Name for the capture. Defaults to the file name.
        #[arg(long)]
        name: Option<String>,
    },
    /// List imported captures.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Delete an imported capture.
    Delete { name: String },
}

#[derive(Subcommand)]
enum RulesCommand {
    /// Parse and lint a rules file (the built-in rules if no file is given).
    Check { file: Option<PathBuf> },
    /// Print the built-in rules, as a starting point for your own.
    Default,
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

/// Kinds each collector produces; used to only diff what both runs collected.
pub(crate) fn kinds_of(collector: &str) -> &'static [Kind] {
    match collector {
        "files" => &[Kind::File],
        "services" => &[Kind::Service, Kind::Driver],
        "firewall" => &[Kind::Firewall],
        "com" => &[Kind::Com],
        "registry" => &[Kind::Registry],
        "users" => &[Kind::User, Kind::Group],
        "certificates" => &[Kind::Certificate],
        "ports" => &[Kind::Port],
        "wifi" => &[Kind::Wifi],
        _ => &[],
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Collect(args) => collect(&cli.db, args),
        Command::Diff(args) => diff(&cli.db, args),
        Command::Runs(cmd) => runs(&cli.db, cmd),
        Command::Rules(cmd) => rules_cmd(cmd),
        Command::Procmon(cmd) => procmon_cmd(&cli.db, cmd),
        Command::Serve {
            listen,
            rules,
            open,
        } => {
            web::serve(cli.db, rules, &listen, open)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn collect(db: &Path, args: CollectArgs) -> Result<ExitCode> {
    if !cfg!(windows) {
        eprintln!(
            "warning: asa targets Windows; on {} owners, ACLs and signatures are not collected",
            std::env::consts::OS
        );
    }
    let mut exclude = args.exclude.clone();
    if !args.no_default_excludes {
        exclude.extend(collectors::files::default_excludes());
    }
    let paths = if args.paths.is_empty() {
        collectors::files::default_roots()
    } else {
        args.paths.clone()
    };
    let threads = args.threads.max(1);
    let signatures = !args.no_signatures;
    let mut selected: Vec<Box<dyn Collector>> = Vec::new();
    for name in &args.collectors {
        match name {
            CollectorName::Files => selected.push(Box::new(collectors::files::FilesCollector {
                roots: paths.clone(),
                exclude: exclude.clone(),
                hash: args.hash,
                acls: !args.no_acls,
                signatures,
                threads,
            })),
            #[cfg(windows)]
            CollectorName::Services => {
                selected.push(Box::new(collectors::services::ServicesCollector {
                    reg: collectors::registry::WinRegistry,
                    signatures,
                    threads,
                }))
            }
            #[cfg(windows)]
            CollectorName::Firewall => {
                selected.push(Box::new(collectors::firewall::FirewallCollector {
                    reg: collectors::registry::WinRegistry,
                }))
            }
            #[cfg(windows)]
            CollectorName::Com => selected.push(Box::new(collectors::com::ComCollector {
                reg: collectors::registry::WinRegistry,
                signatures,
                threads,
            })),
            #[cfg(windows)]
            CollectorName::Registry => {
                selected.push(Box::new(collectors::registry::RegistryCollector {
                    reg: collectors::registry::WinRegistry,
                    locations: Vec::new(),
                }))
            }
            #[cfg(windows)]
            CollectorName::Users => {
                selected.push(Box::new(collectors::accounts::AccountsCollector))
            }
            #[cfg(windows)]
            CollectorName::Certificates => {
                selected.push(Box::new(collectors::certs::CertsCollector))
            }
            #[cfg(windows)]
            CollectorName::Ports => selected.push(Box::new(collectors::ports::PortsCollector {
                signatures,
                threads,
            })),
            // Reads profile files, so it runs anywhere (useful against a mounted image).
            CollectorName::Wifi => selected.push(Box::new(collectors::wifi::WifiCollector {
                root: collectors::wifi::default_root(),
            })),
            #[cfg(not(windows))]
            other => eprintln!(
                "skipping the {} collector: it reads the Windows registry",
                other
                    .to_possible_value()
                    .map(|v| v.get_name().to_string())
                    .unwrap_or_default()
            ),
        }
    }
    if selected.is_empty() {
        bail!("no collector can run on this platform");
    }

    let id = args
        .run_id
        .unwrap_or_else(|| chrono::Local::now().format("%Y%m%d-%H%M%S").to_string());
    let mut store = Store::open(db)?;
    store.begin_run(&id)?;
    eprintln!("collecting run '{id}' into {}", db.display());

    let started = Instant::now();
    let (tx, rx) = crossbeam_channel::bounded(10_000);
    let sink = Sink::new(tx, args.verbose);
    let (results, warnings, ingested) = std::thread::scope(|s| {
        let selected = &selected;
        let collectors = s.spawn(move || {
            let results: Vec<(&'static str, Result<()>, f64)> = std::thread::scope(|s2| {
                let handles: Vec<_> = selected
                    .iter()
                    .map(|c| {
                        let sink = &sink;
                        s2.spawn(move || {
                            let t = Instant::now();
                            let r = c.collect(sink);
                            (c.name(), r, t.elapsed().as_secs_f64())
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("collector panicked"))
                    .collect()
            });
            // Dropping the sink closes the channel and ends ingestion.
            (results, sink.warnings())
        });
        let ingested = store.ingest(&id, rx.iter());
        let (results, warnings) = collectors.join().expect("collector thread panicked");
        (results, warnings, ingested)
    });
    let (inserted, duplicates) = ingested.context("writing objects to the database")?;

    let mut succeeded = Vec::new();
    let mut failed = std::collections::BTreeMap::new();
    for (name, result, secs) in &results {
        match result {
            Ok(()) => {
                eprintln!("  {name:<9} done in {secs:.1}s");
                succeeded.push(name.to_string());
            }
            Err(err) => {
                eprintln!("  {name:<9} FAILED: {err:#}");
                failed.insert(name.to_string(), format!("{err:#}"));
            }
        }
    }
    store.finish_run(&id, &succeeded, &failed, warnings)?;
    eprintln!(
        "stored {inserted} objects in {:.1}s ({warnings} warnings{})",
        started.elapsed().as_secs_f64(),
        if duplicates > 0 {
            format!(", {duplicates} duplicates skipped")
        } else {
            String::new()
        }
    );
    if warnings > 0 && !args.verbose {
        eprintln!("  (re-run with -v to see warnings; an elevated prompt reduces them)");
    }
    Ok(if succeeded.is_empty() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

fn diff(db: &Path, args: DiffArgs) -> Result<ExitCode> {
    let rules = rules::RuleSet::load(args.rules.as_deref())?;
    let store = Store::open(db)?;
    let (base, compare) = (store.run(&args.base)?, store.run(&args.compare)?);
    let common = store::common_kinds(&base, &compare);
    for n in store::coverage_notices(&base, &compare) {
        eprintln!(
            "{}: {}",
            if n.level == "info" { "note" } else { "warning" },
            n.text
        );
    }

    let out: Box<dyn Write> = match &args.output {
        Some(path) => Box::new(BufWriter::new(
            std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?,
        )),
        None => Box::new(BufWriter::new(std::io::stdout().lock())),
    };
    let ctx = report::Context {
        base: &base.id,
        compare: &compare.id,
        rules: &rules,
        min_severity: args.min_severity,
        objects: args.objects,
    };
    let mut writer: Box<dyn ReportWriter> = match args.format {
        Format::Table => Box::new(report::TableWriter::new(out, &ctx, args.limit)),
        Format::Json => Box::new(report::JsonWriter::new(out, &ctx)?),
        Format::Jsonl => Box::new(report::JsonlWriter::new(out, &ctx)),
        Format::Sarif => Box::new(report::SarifWriter::new(out, &ctx)?),
    };

    let mut stats = report::Stats::default();
    store.diff_each(&base.id, &compare.id, |raw| {
        if !common.contains(&raw.kind) {
            return Ok(());
        }
        let change = diff::analyze(raw, &rules);
        stats.record(&change);
        if change.severity >= args.min_severity {
            stats.reported += 1;
            writer.change(&change)?;
        }
        Ok(())
    })?;
    writer.finish(&stats)?;
    if let Some(path) = &args.output {
        eprintln!(
            "wrote {} of {} changes to {}",
            stats.reported,
            stats.total,
            path.display()
        );
    }

    let failed = args
        .fail_on
        .is_some_and(|t| stats.max_severity.is_some_and(|m| m >= t));
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn runs(db: &Path, cmd: RunsCommand) -> Result<ExitCode> {
    let mut store = Store::open(db)?;
    match cmd {
        RunsCommand::List { json } => {
            let runs = store.runs()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&runs)?);
            } else if runs.is_empty() {
                println!("no runs yet; create one with `asa collect`");
            } else {
                println!(
                    "{:<24} {:<21} {:>10}  COLLECTORS",
                    "ID", "CREATED", "OBJECTS"
                );
                for r in runs {
                    let status = if r.complete { "" } else { " (incomplete)" };
                    println!(
                        "{:<24} {:<21} {:>10}  {}{status}",
                        r.id,
                        r.created,
                        r.objects,
                        r.collectors.join(",")
                    );
                }
            }
        }
        RunsCommand::Delete { id } => {
            if !store.delete_run(&id)? {
                bail!("no run with id '{id}'");
            }
            eprintln!("deleted run '{id}'");
        }
        RunsCommand::Export { id, kind } => {
            let mut out = BufWriter::new(std::io::stdout().lock());
            store.for_each_object(&id, kind, |kind, identity, data| {
                writeln!(
                    out,
                    r#"{{"kind":"{kind}","identity":{},"data":{data}}}"#,
                    serde_json::to_string(identity)?
                )?;
                Ok(())
            })?;
            out.flush()?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn procmon_cmd(db: &Path, cmd: ProcmonCommand) -> Result<ExitCode> {
    let store = Store::open(db)?;
    match cmd {
        ProcmonCommand::Import { file, name } => {
            let name = name.unwrap_or_else(|| {
                file.file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "capture".into())
            });
            let t = Instant::now();
            let (rows, kept) = procmon::import(&store, &file, &name)?;
            eprintln!(
                "imported capture '{name}': {kept} distinct changes from {rows} events in {:.1}s",
                t.elapsed().as_secs_f64()
            );
            eprintln!(
                "  open a comparison in `asa serve` and filter with: modified_by = <process>"
            );
        }
        ProcmonCommand::List { json } => {
            let caps = procmon::captures(&store)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&caps)?);
            } else if caps.is_empty() {
                println!("no captures yet; import one with `asa procmon import capture.csv`");
            } else {
                println!(
                    "{:<24} {:<21} {:>10} {:>12}  SOURCE",
                    "NAME", "IMPORTED", "CHANGES", "EVENTS"
                );
                for c in caps {
                    println!(
                        "{:<24} {:<21} {:>10} {:>12}  {}",
                        c.name, c.imported, c.events, c.rows, c.source
                    );
                }
            }
        }
        ProcmonCommand::Delete { name } => {
            if !procmon::delete(&store, &name)? {
                bail!("no capture named '{name}'");
            }
            eprintln!("deleted capture '{name}'");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn rules_cmd(cmd: RulesCommand) -> Result<ExitCode> {
    match cmd {
        RulesCommand::Default => {
            print!("{}", rules::DEFAULT_RULES);
            Ok(ExitCode::SUCCESS)
        }
        RulesCommand::Check { file } => {
            let rules = rules::RuleSet::load(file.as_deref())?;
            let warnings = rules.lint(&collectors::known_fields());
            for w in &warnings {
                eprintln!("warning: {w}");
            }
            println!(
                "{} rules OK, {} warning(s)",
                rules.rules.len(),
                warnings.len()
            );
            Ok(if warnings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_runs_every_collector_by_default() {
        let cli = Cli::try_parse_from(["asa", "collect"]).unwrap();
        let Command::Collect(args) = cli.command else {
            panic!("expected collect")
        };
        assert_eq!(
            args.collectors.len(),
            CollectorName::value_variants().len(),
            "the --collectors default must list every collector"
        );
        for c in CollectorName::value_variants() {
            let name = c.to_possible_value().unwrap().get_name().to_string();
            assert!(
                !kinds_of(&name).is_empty(),
                "collector {name} has no kinds_of mapping"
            );
        }
    }
}
