//! Output: text, json, sarif, github.

use crate::model::{Probe, Setup};
use crate::rules::{Finding, Severity, RULES};
use serde_json::json;

pub struct Report<'a> {
    pub color: bool,
    pub policy_name: &'a str,
    pub policy_path: Option<&'a str>,
    pub setup: &'a Setup,
    pub findings: &'a [Finding],
    pub allowed: &'a [Finding],
    pub probes: &'a [Probe],
    pub capabilities: &'a [(String, crate::caps::Capabilities)],
    pub verbose: bool,
}

pub fn counts(f: &[Finding]) -> (usize, usize, usize) {
    let fail = f.iter().filter(|x| x.severity == Severity::Fail).count();
    let warn = f.iter().filter(|x| x.severity == Severity::Warn).count();
    let info = f.iter().filter(|x| x.severity == Severity::Info).count();
    (fail, warn, info)
}

fn wrap(text: &str, indent: usize, width: usize) -> String {
    let mut out = String::new();
    let mut line = String::new();
    let pad = " ".repeat(indent);
    for word in text.split_whitespace() {
        if line.len() + word.len() + 1 > width && !line.is_empty() {
            out.push_str(&pad);
            out.push_str(&line);
            out.push('\n');
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push_str(&pad);
        out.push_str(&line);
        out.push('\n');
    }
    out
}

struct Paint(bool);
impl Paint {
    fn sev(&self, s: Severity, t: &str) -> String {
        if !self.0 {
            return t.to_string();
        }
        match s {
            Severity::Fail => format!("\x1b[1;31m{t}\x1b[0m"),
            Severity::Warn => format!("\x1b[1;33m{t}\x1b[0m"),
            Severity::Info => format!("\x1b[2m{t}\x1b[0m"),
        }
    }
    fn bold(&self, t: &str) -> String {
        if self.0 {
            format!("\x1b[1m{t}\x1b[0m")
        } else {
            t.to_string()
        }
    }
    fn dim(&self, t: &str) -> String {
        if self.0 {
            format!("\x1b[2m{t}\x1b[0m")
        } else {
            t.to_string()
        }
    }
    fn cyan(&self, t: &str) -> String {
        if self.0 {
            format!("\x1b[36m{t}\x1b[0m")
        } else {
            t.to_string()
        }
    }
    fn green(&self, t: &str) -> String {
        if self.0 {
            format!("\x1b[32m{t}\x1b[0m")
        } else {
            t.to_string()
        }
    }
}

pub fn text(r: &Report) -> String {
    let c = Paint(r.color);
    let mut out = String::new();
    let pol = match r.policy_path {
        Some(p) => format!("policy \"{}\" ({p})", r.policy_name),
        None => "no policy file (everything is reported; run `frostagent init` to write one)"
            .to_string(),
    };
    out.push_str(&format!(
        "{} {} — {pol}\n",
        c.bold("frostagent"),
        env!("CARGO_PKG_VERSION")
    ));
    let s = r.setup;
    out.push_str(&format!(
        "scanned {} file{}: {} server{}, {} hook{}, {} permission rule{}, {} skill{}{}\n",
        s.files.len(),
        pl(s.files.len()),
        s.servers.len(),
        pl(s.servers.len()),
        s.hooks.len(),
        pl(s.hooks.len()),
        s.permissions.len(),
        pl(s.permissions.len()),
        s.skills.len(),
        pl(s.skills.len()),
        if r.probes.is_empty() {
            String::new()
        } else {
            format!(
                "; probed {} server{} ({} tool{})",
                r.probes.len(),
                pl(r.probes.len()),
                r.probes.iter().map(|p| p.tools.len()).sum::<usize>(),
                pl(r.probes.iter().map(|p| p.tools.len()).sum::<usize>())
            )
        }
    ));
    for e in &s.errors {
        out.push_str(&format!("WARN  config-error       {e}\n"));
    }
    out.push('\n');
    let mut sorted: Vec<&Finding> = r.findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.kind.cmp(b.kind))
            .then(a.subject.cmp(&b.subject))
            .then(a.rule.cmp(b.rule))
    });
    let hidden_info = if r.verbose {
        0
    } else {
        sorted
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count()
    };
    for f in &sorted {
        if f.severity == Severity::Info && !r.verbose {
            continue;
        }
        let where_ = f
            .source
            .as_ref()
            .map(|s| format!("   {}", c.dim(&s.display())))
            .unwrap_or_default();
        out.push_str(&format!(
            "{}  {} {} {}{}\n",
            c.sev(f.severity, f.severity.label()),
            c.bold(&format!("{:<19}", f.rule)),
            f.kind,
            c.cyan(&format!("\"{}\"", f.subject)),
            where_
        ));
        out.push_str(&wrap(&f.message, 6, 100));
    }
    if r.verbose && !r.allowed.is_empty() {
        out.push_str("\nallowed by policy or baseline:\n");
        for f in r.allowed {
            out.push_str(&format!(
                "  {}    {:<19} {} \"{}\"   ← {}\n",
                c.green("ok"),
                f.rule,
                f.kind,
                f.subject,
                c.dim(&f.allowed_by.clone().unwrap_or_default())
            ));
        }
    }
    if r.verbose {
        for (name, c) in r.capabilities {
            out.push_str(&format!(
                "\nsource {} : {} file{} at {}\n",
                name,
                c.files,
                if c.files == 1 { "" } else { "s" },
                c.root.clone().unwrap_or_default()
            ));
            for (label, set) in [
                ("exec", &c.exec),
                ("eval", &c.eval),
                ("fs write", &c.fs_write),
                ("network", &c.network),
                ("hosts", &c.hosts),
                ("env", &c.env),
                ("credentials", &c.credential_paths),
            ] {
                if !set.is_empty() {
                    out.push_str(&format!(
                        "  {:<12} {}\n",
                        label,
                        set.iter().take(12).cloned().collect::<Vec<_>>().join(", ")
                    ));
                }
            }
        }
        for p in r.probes {
            out.push_str(&format!(
                "\nprobe {} : {}{}\n",
                p.server,
                if p.ok { "ok" } else { "failed" },
                p.error
                    .as_ref()
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default()
            ));
            if let Some(info) = &p.server_info {
                out.push_str(&format!(
                    "  server {} {} protocol {}\n",
                    info.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                    info.get("version").and_then(|v| v.as_str()).unwrap_or(""),
                    p.protocol_version.clone().unwrap_or_default()
                ));
            }
            for t in &p.tools {
                out.push_str(&format!(
                    "  {:<32} {}\n",
                    t.name,
                    t.description
                        .chars()
                        .take(80)
                        .collect::<String>()
                        .replace('\n', " ")
                ));
            }
        }
    }
    let (fail, warn, info) = counts(r.findings);
    let summary = format!(
        "{fail} fail, {warn} warn, {info} info{}, {} allowed",
        if hidden_info > 0 {
            " (hidden; --verbose shows them)"
        } else {
            ""
        },
        r.allowed.len()
    );
    out.push_str(&format!(
        "\n{}\n",
        if fail > 0 {
            c.sev(Severity::Fail, &summary)
        } else if warn > 0 {
            c.sev(Severity::Warn, &summary)
        } else {
            c.green(&summary)
        }
    ));
    out
}

fn pl(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

pub fn json_out(r: &Report) -> String {
    let (fail, warn, info) = counts(r.findings);
    let v = json!({
        "tool": "frostagent",
        "version": env!("CARGO_PKG_VERSION"),
        "policy": {"name": r.policy_name, "path": r.policy_path},
        "summary": {"fail": fail, "warn": warn, "info": info, "allowed": r.allowed.len()},
        "setup": {
            "files": r.setup.files.iter().map(|p| crate::model::shorten_home(p)).collect::<Vec<_>>(),
            "errors": r.setup.errors,
            "servers": r.setup.servers.iter().map(|s| json!({"name": s.name, "client": s.client, "transport": s.transport, "launch": s.url.clone().unwrap_or_else(|| s.command_line()), "source": s.source.display()})).collect::<Vec<_>>(),
            "hooks": r.setup.hooks.iter().map(|h| json!({"name": h.name(), "command": h.command, "source": h.source.display()})).collect::<Vec<_>>(),
            "permissions": r.setup.permissions.iter().map(|p| json!({"rule": p.rule, "list": p.list, "source": p.source.display()})).collect::<Vec<_>>(),
            "skills": r.setup.skills.iter().map(|s| json!({"name": s.name, "dir": crate::model::shorten_home(&s.dir), "allowed_tools": s.allowed_tools})).collect::<Vec<_>>(),
        },
        "capabilities": r.capabilities.iter().map(|(n, c)| json!({"server": n, "root": c.root, "files": c.files, "exec": c.exec, "eval": c.eval, "fs_write": c.fs_write, "network": c.network, "hosts": c.hosts, "env": c.env, "credential_paths": c.credential_paths})).collect::<Vec<_>>(),
        "findings": r.findings,
        "allowed": r.allowed,
        "probes": r.probes.iter().map(|p| json!({"server": p.server, "ok": p.ok, "error": p.error, "server_info": p.server_info, "protocol": p.protocol_version, "millis": p.millis,
            "instructions": p.instructions,
            "tools": p.tools.iter().map(|t| json!({"name": t.name, "description": t.description, "annotations": t.annotations, "fingerprint": t.fingerprint()})).collect::<Vec<_>>(),
            "prompts": p.prompts.iter().map(|t| json!({"name": t.name, "description": t.description, "fingerprint": t.fingerprint()})).collect::<Vec<_>>(),
            "resources": p.resources.iter().map(|r| json!({"uri": r.uri, "name": r.name, "description": r.description})).collect::<Vec<_>>()})).collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&v).unwrap()
}

pub fn sarif(r: &Report) -> String {
    let rules: Vec<_> = RULES.iter().map(|x| json!({"id": x.id, "shortDescription": {"text": x.about}, "defaultConfiguration": {"level": level(x.severity)}})).collect();
    let results: Vec<_> = r.findings.iter().map(|f| {
        let mut res = json!({"ruleId": f.rule, "level": level(f.severity), "message": {"text": format!("{} \"{}\": {}", f.kind, f.subject, f.message)}});
        if let Some(s) = &f.source {
            res["locations"] = json!([{"physicalLocation": {"artifactLocation": {"uri": s.file.display().to_string()}, "region": {"startLine": 1}}}]);
        }
        res
    }).collect();
    let v = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "frostagent", "version": env!("CARGO_PKG_VERSION"), "informationUri": "https://github.com/keithadler/frostagent", "rules": rules}}, "results": results}]
    });
    serde_json::to_string_pretty(&v).unwrap()
}

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Fail => "error",
        Severity::Warn => "warning",
        Severity::Info => "note",
    }
}

pub fn github(r: &Report) -> String {
    let mut out = String::new();
    for f in r.findings {
        let kind = match f.severity {
            Severity::Fail => "error",
            Severity::Warn => "warning",
            Severity::Info => "notice",
        };
        let file = f
            .source
            .as_ref()
            .map(|s| format!("file={},line=1,", s.file.display()))
            .unwrap_or_default();
        let msg = f.message.replace('%', "%25").replace('\n', "%0A");
        out.push_str(&format!(
            "::{kind} {file}title={} {} \"{}\"::{msg}\n",
            f.rule, f.kind, f.subject
        ));
    }
    let (fail, warn, info) = counts(r.findings);
    out.push_str(&format!(
        "frostagent: {fail} fail, {warn} warn, {info} info, {} allowed by policy\n",
        r.allowed.len()
    ));
    out
}
