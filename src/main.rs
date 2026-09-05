//! frostagent: deny-by-default capability linter for AI agent setups.

mod caps;
mod discover;
mod lock;
mod model;
mod policy;
mod probe;
mod proxy;
mod report;
mod rules;
mod taint;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "frostagent: what may your agent's tools do? A one-screen policy says; the check fails on anything else.

USAGE
  frostagent [scan] [dir] [options]     lint MCP servers, hooks, permissions and skills
  frostagent probe [dir] [options]      also start every server and inspect its tools
  frostagent lock  [dir] [options]      probe and approve the tools as they are now (writes frostagent.lock)
  frostagent init  [dir]                write a starter frostagent.policy from what is found
  frostagent summary [--policy FILE]    read the policy back in plain English
  frostagent rules [--markdown]         list every rule with its default severity
  frostagent clients [dir] [--user]     list every config file frostagent looks for and which exist here
  frostagent explain <rule>             what a rule means and how to fix or allow it
  frostagent baseline [dir] [options]   record today's findings so only new ones are reported
  frostagent proxy <server> [dir] [--enforce] [--log FILE]
                                        stand between the host and a stdio server; check tools, drift and results live

OPTIONS
  --user               also read per-user config: ~/.claude.json, ~/.claude, Claude Desktop, Cursor
  --policy FILE        policy file (default: frostagent.policy in dir)
  --lock FILE          lockfile (default: frostagent.lock in dir)
  --format FMT         text (default), json, sarif, github
  --timeout SECONDS    per-server probe timeout (default 20)
  --only NAME          probe only this server (repeatable)
  --fail-on LEVEL      exit 1 on fail (default) or warn
  --exit-zero          always exit 0
  --baseline FILE      hide findings recorded in this file (default: frostagent.baseline.json if present)
  --color MODE         auto (default), always, never; NO_COLOR is honored
  --no-source          skip reading the source of local servers (and of npx packages in the npm cache)
  --yes, -y            probe and lock: start the listed servers without asking
  --enforce            proxy only: drop drifted or poisoned tools, refuse calls to them, flag injected results
  --log FILE           proxy only: append one JSON line per event to FILE
  --verbose            show allowed findings and every probed tool

Nothing is uploaded. Probing runs the servers exactly as your agent would, with their configured env:
it executes other people's code on your machine, so it lists them and asks first unless you pass --yes.
";

struct Args {
    cmd: String,
    dir: PathBuf,
    user: bool,
    policy: Option<PathBuf>,
    lock: Option<PathBuf>,
    format: String,
    timeout: u64,
    only: Vec<String>,
    fail_on: String,
    exit_zero: bool,
    verbose: bool,
    baseline: Option<PathBuf>,
    color: String,
    no_source: bool,
    markdown: bool,
    rest: Vec<String>,
    enforce: bool,
    log: Option<PathBuf>,
    yes: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        cmd: "scan".into(),
        dir: std::env::current_dir().map_err(|e| e.to_string())?,
        user: false,
        policy: None,
        lock: None,
        format: "text".into(),
        timeout: 20,
        only: vec![],
        fail_on: "fail".into(),
        exit_zero: false,
        verbose: false,
        baseline: None,
        color: "auto".into(),
        markdown: false,
        no_source: false,
        rest: vec![],
        enforce: false,
        log: None,
        yes: false,
    };
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let mut positional: Vec<String> = Vec::new();
    while i < raw.len() {
        let s = raw[i].as_str();
        let take = |name: &str| -> Result<String, String> {
            raw.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match s {
            "-h" | "--help" | "help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "-V" | "--version" | "version" => {
                println!("frostagent {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--user" | "-u" => a.user = true,
            "--policy" => {
                a.policy = Some(PathBuf::from(take("--policy")?));
                i += 1;
            }
            "--lock" => {
                a.lock = Some(PathBuf::from(take("--lock")?));
                i += 1;
            }
            "--format" | "-f" => {
                a.format = take("--format")?;
                i += 1;
            }
            "--timeout" => {
                a.timeout = take("--timeout")?
                    .parse()
                    .map_err(|_| "--timeout needs a number of seconds".to_string())?;
                i += 1;
            }
            "--only" => {
                a.only.push(take("--only")?);
                i += 1;
            }
            "--fail-on" => {
                a.fail_on = take("--fail-on")?;
                i += 1;
            }
            "--exit-zero" => a.exit_zero = true,
            "--verbose" | "-v" => a.verbose = true,
            "--markdown" => a.markdown = true,
            "--no-source" => a.no_source = true,
            "--enforce" => a.enforce = true,
            "--yes" | "-y" => a.yes = true,
            "--log" => {
                a.log = Some(PathBuf::from(take("--log")?));
                i += 1;
            }
            "--baseline" => {
                a.baseline = Some(PathBuf::from(take("--baseline")?));
                i += 1;
            }
            "--color" => {
                a.color = take("--color")?;
                i += 1;
            }
            _ if s.starts_with('-') => return Err(format!("unknown option `{s}`\n\n{USAGE}")),
            _ => positional.push(s.to_string()),
        }
        i += 1;
    }
    if let Some(first) = positional.first() {
        if matches!(
            first.as_str(),
            "scan"
                | "probe"
                | "lock"
                | "init"
                | "summary"
                | "rules"
                | "explain"
                | "baseline"
                | "proxy"
                | "clients"
        ) {
            a.cmd = positional.remove(0);
        }
    }
    if a.cmd == "explain" {
        a.rest = positional;
        return Ok(a);
    }
    if a.cmd == "proxy" {
        if positional.is_empty() {
            return Err("proxy: which server? `frostagent proxy <server-name> [dir]`".into());
        }
        a.rest = vec![positional.remove(0)];
    }
    if let Some(d) = positional.first() {
        a.dir = PathBuf::from(d);
        if !a.dir.is_dir() {
            return Err(format!("`{d}` is not a directory"));
        }
        a.dir = a.dir.canonicalize().map_err(|e| e.to_string())?;
    }
    if !matches!(a.format.as_str(), "text" | "json" | "sarif" | "github") {
        return Err(format!("unknown format `{}`", a.format));
    }
    Ok(a)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn load_policy(args: &Args) -> Result<(policy::Policy, Option<String>), String> {
    let path = args
        .policy
        .clone()
        .unwrap_or_else(|| args.dir.join("frostagent.policy"));
    if !path.exists() {
        if args.policy.is_some() {
            return Err(format!("policy file `{}` not found", path.display()));
        }
        return Ok((policy::Policy::default(), None));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut p = policy::Policy::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    p.path = Some(model::shorten_home(&path));
    Ok((p, Some(model::shorten_home(&path))))
}

fn run(args: &Args) -> Result<ExitCode, String> {
    match args.cmd.as_str() {
        "rules" => {
            if args.markdown {
                print!("{}", rules::rules_markdown());
            } else {
                for r in rules::RULES {
                    println!("{:<4}  {:<24} {}", r.severity.label(), r.id, r.about);
                }
            }
            return Ok(ExitCode::SUCCESS);
        }
        "explain" => {
            let Some(id) = args.rest.first() else {
                return Err("explain: which rule? run `frostagent rules` for the list".into());
            };
            let Some(r) = rules::rule(id) else {
                return Err(format!(
                    "unknown rule `{id}`; run `frostagent rules` for the list"
                ));
            };
            println!("{}  ({} by default)\n", r.id, r.severity.label());
            println!("What it means\n  {}.\n", r.about);
            println!("How to fix it\n  {}\n", r.fix);
            println!("How to allow it, once you have decided it is fine\n  server \"<name>\" may {}          -- or skill / hook / permission / tool\n  everything may {}\n", r.id, r.id);
            if r.severity != rules::Severity::Fail {
                println!("How to make it a failure\n  forbid {}\n", r.id);
            }
            return Ok(ExitCode::SUCCESS);
        }
        "summary" => {
            let (p, path) = load_policy(args)?;
            if path.is_none() {
                println!("No policy file. Everything found is reported at its default severity.");
            } else {
                print!("{}", policy::summary(&p));
            }
            return Ok(ExitCode::SUCCESS);
        }
        _ => {}
    }
    if args.cmd == "clients" {
        let files = discover::candidate_files(&discover::Options {
            user: args.user,
            project: args.dir.clone(),
        });
        let found = files.iter().filter(|(_, _, e)| *e).count();
        println!(
            "{found} of {} known config locations exist{}:",
            files.len(),
            if args.user {
                ""
            } else {
                " (add --user for per-user files)"
            }
        );
        for (client, path, exists) in &files {
            println!(
                "  {}  {:<20} {}",
                if *exists { "found  " } else { "missing" },
                client,
                model::shorten_home(path)
            );
        }
        println!("\nA client you use that is not listed is worth an issue: https://github.com/keithadler/frostagent/issues/new?template=client.yml");
        return Ok(ExitCode::SUCCESS);
    }

    let setup = discover::discover(&discover::Options {
        user: args.user,
        project: args.dir.clone(),
    });

    if args.cmd == "proxy" {
        let name = &args.rest[0];
        let Some(server) = proxy::find_server(&setup, name) else {
            let known: Vec<&str> = setup.servers.iter().map(|s| s.name.as_str()).collect();
            return Err(format!(
                "no server named `{name}` in {}{}; known: {}",
                model::shorten_home(&args.dir),
                if args.user {
                    " or the user config"
                } else {
                    " (add --user for per-user config)"
                },
                if known.is_empty() {
                    "none".to_string()
                } else {
                    known.join(", ")
                }
            ));
        };
        let (pol, _) = load_policy(args)?;
        let lock_path = args
            .lock
            .clone()
            .unwrap_or_else(|| args.dir.join(lock::FILE));
        let code = proxy::run(
            server,
            proxy::Options {
                enforce: args.enforce,
                log: args.log.clone(),
                lock_path,
                policy: pol,
            },
        )?;
        return Ok(if code == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        });
    }

    if args.cmd == "init" {
        return init(args, &setup);
    }

    let mut findings: Vec<rules::Finding> = Vec::new();
    for s in &setup.servers {
        rules::check_server(s, &mut findings);
    }
    for h in &setup.hooks {
        rules::check_hook(h, &args.dir, &mut findings);
    }
    for p in &setup.permissions {
        rules::check_permission(p, &mut findings);
    }
    for s in &setup.skills {
        rules::check_skill(s, &mut findings);
    }
    // Source-level capabilities for servers whose code is on this machine.
    let mut capabilities: Vec<(String, caps::Capabilities)> = Vec::new();
    if !args.no_source {
        for s in &setup.servers {
            if let Some(root) = caps::locate(s) {
                let c = caps::extract(&root);
                if c.files > 0 {
                    caps::findings(s, &c, &mut findings);
                    let flows = taint::analyze(&root);
                    if !flows.is_empty() {
                        taint::findings(s, &flows, &mut findings);
                    }
                    capabilities.push((s.name.clone(), c));
                }
            }
        }
    }
    for e in &setup.errors {
        findings.push(rules::Finding {
            rule: "config-error",
            severity: rules::Severity::Warn,
            kind: "config",
            subject: e.split(':').next().unwrap_or("").to_string(),
            message: e.clone(),
            source: None,
            allowed_by: None,
        });
    }

    let (pol, pol_path) = load_policy(args)?;
    let lock_path = args
        .lock
        .clone()
        .unwrap_or_else(|| args.dir.join(lock::FILE));

    let mut probes: Vec<model::Probe> = Vec::new();
    if args.cmd == "probe" || args.cmd == "lock" {
        let to_run: Vec<&model::Server> = setup
            .servers
            .iter()
            .filter(|s| args.only.is_empty() || args.only.iter().any(|o| policy::glob(o, &s.name)))
            .collect();
        if !args.yes && !to_run.is_empty() {
            eprintln!("frostagent will start {} server{} with the env from your config. That runs other people's code on this machine:", to_run.len(), if to_run.len() == 1 { "" } else { "s" });
            for s in &to_run {
                eprintln!(
                    "  {:<24} {}",
                    s.name,
                    s.url.clone().unwrap_or_else(|| s.command_line())
                );
            }
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                eprint!("Continue? [y/N] ");
                let mut line = String::new();
                let _ = std::io::stdin().read_line(&mut line);
                if !matches!(line.trim(), "y" | "Y" | "yes") {
                    return Err("stopped before starting any server. Pass --yes to skip this question, or --only NAME to pick servers.".into());
                }
            } else {
                return Err("not a terminal; pass --yes to confirm starting these servers, or --only NAME to pick some.".into());
            }
        }
        let timeout = Duration::from_secs(args.timeout);
        let mut tools: Vec<model::Tool> = Vec::new();
        for s in &setup.servers {
            if !args.only.is_empty() && !args.only.iter().any(|o| policy::glob(o, &s.name)) {
                continue;
            }
            if args.format == "text" {
                eprint!("probing {} ... ", s.name);
            }
            let p = probe::probe(s, timeout);
            if args.format == "text" {
                match &p.error {
                    None => eprintln!(
                        "{} tool{} in {} ms",
                        p.tools.len(),
                        if p.tools.len() == 1 { "" } else { "s" },
                        p.millis
                    ),
                    Some(e) => eprintln!("failed: {e}"),
                }
            }
            if let Some(e) = &p.error {
                // A remote server that wants a sign-in the agent host performs interactively (OAuth) is not a fault in the config.
                let auth = e.contains("authentication rejected");
                findings.push(rules::Finding {
                    rule: if auth { "server-auth" } else { "probe-failed" },
                    severity: if auth { rules::Severity::Info } else { rules::Severity::Warn },
                    kind: "server",
                    subject: s.name.clone(),
                    message: if auth && !e.contains("OAuth sign-in required") { format!("{e}. Its tools were not inspected; export FROSTAGENT_AUTH_<NAME> with a token from a client you have signed in with, or rely on `frostagent proxy` at runtime.") } else { e.clone() },
                    source: Some(s.source.clone()),
                    allowed_by: None,
                });
            }
            tools.extend(p.tools.iter().cloned());
            rules::check_probe_text(&p, &mut findings);
            if !p.side_effects.is_empty() {
                let shown: Vec<&str> = p.side_effects.iter().take(6).map(String::as_str).collect();
                findings.push(rules::Finding {
                    rule: "probe-side-effect",
                    severity: rules::Severity::Warn,
                    kind: "server",
                    subject: s.name.clone(),
                    message: format!(
                        "created {}{} while starting, before any tool was called.",
                        shown.join(", "),
                        if p.side_effects.len() > 6 {
                            format!(" and {} more", p.side_effects.len() - 6)
                        } else {
                            String::new()
                        }
                    ),
                    source: Some(s.source.clone()),
                    allowed_by: None,
                });
            }
            probes.push(p);
        }
        rules::check_tools(&tools, &mut findings);
        let launches: BTreeMap<String, String> = setup
            .servers
            .iter()
            .map(|s| {
                (
                    s.name.clone(),
                    s.url.clone().unwrap_or_else(|| s.command_line()),
                )
            })
            .collect();
        if args.cmd == "lock" {
            let mut lk = lock::Lock::load(&lock_path)?.unwrap_or_default();
            lk.record(&probes, &launches);
            lk.save(&lock_path)?;
            eprintln!(
                "locked {} server{} into {}",
                probes.iter().filter(|p| p.ok).count(),
                if probes.iter().filter(|p| p.ok).count() == 1 {
                    ""
                } else {
                    "s"
                },
                model::shorten_home(&lock_path)
            );
        } else {
            match lock::Lock::load(&lock_path)? {
                Some(lk) => lk.compare(&probes, pol.require_lock(), &mut findings),
                None => {
                    if !probes.is_empty() {
                        findings.push(rules::Finding { rule: "server-unlocked", severity: if pol.require_lock() { rules::Severity::Fail } else { rules::Severity::Info }, kind: "server", subject: "*".into(), message: format!("no {} yet; run `frostagent lock` to approve every server's tools as they are now, and future runs will flag any change.", lock::FILE), source: None, allowed_by: None });
                    }
                }
            }
        }
    }

    let (mut active, mut allowed) = pol.apply(findings);
    let baseline_path = args
        .baseline
        .clone()
        .unwrap_or_else(|| args.dir.join("frostagent.baseline.json"));
    if args.cmd == "baseline" {
        let keys: Vec<String> = active.iter().map(finding_key).collect();
        let doc = serde_json::json!({"version": 1, "tool": "frostagent", "findings": keys, "note": "Findings recorded here are hidden by later runs. Delete entries as you fix them."});
        std::fs::write(
            &baseline_path,
            serde_json::to_string_pretty(&doc).unwrap() + "\n",
        )
        .map_err(|e| e.to_string())?;
        eprintln!(
            "recorded {} finding{} in {}",
            keys.len(),
            if keys.len() == 1 { "" } else { "s" },
            model::shorten_home(&baseline_path)
        );
        return Ok(ExitCode::SUCCESS);
    }
    if baseline_path.exists() {
        let text = std::fs::read_to_string(&baseline_path).map_err(|e| e.to_string())?;
        let doc: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", baseline_path.display()))?;
        let known: std::collections::HashSet<String> = doc["findings"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|k| k.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let (kept, hidden): (Vec<_>, Vec<_>) = active
            .into_iter()
            .partition(|f| !known.contains(&finding_key(f)));
        active = kept;
        for mut f in hidden {
            f.allowed_by = Some(format!("baseline {}", model::shorten_home(&baseline_path)));
            allowed.push(f);
        }
    }
    let color = match args.color.as_str() {
        "always" => true,
        "never" => false,
        _ => {
            std::env::var_os("NO_COLOR").is_none()
                && std::io::IsTerminal::is_terminal(&std::io::stdout())
        }
    };
    let rep = report::Report {
        color,
        policy_name: &pol.name,
        policy_path: pol_path.as_deref(),
        setup: &setup,
        findings: &active,
        allowed: &allowed,
        probes: &probes,
        capabilities: &capabilities,
        verbose: args.verbose,
    };
    let out = match args.format.as_str() {
        "json" => report::json_out(&rep),
        "sarif" => report::sarif(&rep),
        "github" => report::github(&rep),
        _ => report::text(&rep),
    };
    print!("{out}");
    let (fail, warn, _) = report::counts(&active);
    let bad = fail > 0 || (args.fail_on == "warn" && warn > 0);
    Ok(if bad && !args.exit_zero {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

/// Stable identity of a finding for the baseline: rule, kind, subject and source file.
fn finding_key(f: &rules::Finding) -> String {
    let src = f
        .source
        .as_ref()
        .map(|s| model::shorten_home(&s.file))
        .unwrap_or_default();
    model::fingerprint(&[f.rule, f.kind, &f.subject, &src])[..24].to_string()
}

fn init(args: &Args, setup: &model::Setup) -> Result<ExitCode, String> {
    let path = args
        .policy
        .clone()
        .unwrap_or_else(|| args.dir.join("frostagent.policy"));
    if path.exists() {
        return Err(format!(
            "{} already exists; edit it instead",
            model::shorten_home(&path)
        ));
    }
    let name = args
        .dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "project".into());
    let mut out = String::new();
    out.push_str(&format!("policy \"{name}\"\n"));
    out.push_str("-- Everything frostagent finds is reported until a line here allows it.\n");
    out.push_str("-- Lines: <server|skill|hook|permission|tool> \"<name>\" may <rule> [in \"<file>\"] [until YYYY-MM-DD]\n");
    out.push_str("--        trust <kind> \"<name>\"      forbid <rule>      require lock\n");
    out.push_str("-- Run `frostagent rules` for the rule list and `frostagent summary` to read this back.\n\n");
    if !setup.servers.is_empty() {
        out.push_str("-- Servers found:\n");
        for s in &setup.servers {
            out.push_str(&format!(
                "--   {:<20} {}\n",
                s.name,
                s.url.clone().unwrap_or_else(|| s.command_line())
            ));
        }
        out.push('\n');
    }
    if !setup.skills.is_empty() {
        out.push_str("-- Skills found:\n");
        for s in &setup.skills {
            out.push_str(&format!("--   {}\n", s.name));
        }
        out.push('\n');
    }
    out.push_str("-- Examples (remove the leading -- to enable):\n");
    out.push_str("-- server \"*\" may plaintext-secret in \"~/.claude.json\"   -- per-user file, not committed\n");
    out.push_str("-- forbid exec-surface\n");
    out.push_str("-- require lock\n");
    std::fs::write(&path, out).map_err(|e| e.to_string())?;
    println!("wrote {}", model::shorten_home(&path));
    let _ = Path::new("");
    Ok(ExitCode::SUCCESS)
}
