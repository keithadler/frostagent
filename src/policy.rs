//! The policy file: one sentence per line, in the frost dialect.
//!
//! ```text
//! policy "compmgr"
//! server "meshy" may unpinned-package             -- upstream has no tags yet, issue #4
//! server "*" may plaintext-secret in "~/.claude.json"
//! skill "framer" may skill-network until 2026-12-31
//! trust server "unity"                            -- built here, reviewed in its own repo
//! forbid exec-surface                             -- treat free-text code parameters as failures
//! require lock                                    -- servers without a lock entry fail
//! ```
//!
//! Subjects: server, skill, hook, permission, tool, or `everything`. Names may
//! use `*` as a wildcard. `in "<file>"` limits a waiver to one config file.
//! Comments start with `--` or `#`.

use crate::rules::{rule, Finding, Severity};
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Server,
    Skill,
    Hook,
    Permission,
    Tool,
    Everything,
}

impl Kind {
    fn matches(&self, finding_kind: &str) -> bool {
        match self {
            Kind::Everything => true,
            Kind::Server => finding_kind == "server",
            Kind::Skill => finding_kind == "skill",
            Kind::Hook => finding_kind == "hook",
            Kind::Permission => finding_kind == "permission",
            Kind::Tool => finding_kind == "tool",
        }
    }
    fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "server" | "servers" => Kind::Server,
            "skill" | "skills" => Kind::Skill,
            "hook" | "hooks" => Kind::Hook,
            "permission" | "permissions" => Kind::Permission,
            "tool" | "tools" => Kind::Tool,
            "everything" | "all" | "anything" => Kind::Everything,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Line {
    /// `<kind> "<name>" may <rule> [in "<file>"] [until YYYY-MM-DD]`
    May {
        kind: Kind,
        name: String,
        rule: String,
        file: Option<String>,
        until: Option<(i32, u32, u32)>,
        text: String,
    },
    /// `trust <kind> "<name>"`
    Trust {
        kind: Kind,
        name: String,
        text: String,
    },
    /// `forbid <rule>`
    Forbid { rule: String, text: String },
    /// `require lock`
    RequireLock,
}

#[derive(Debug, Default, Clone)]
pub struct Policy {
    pub name: String,
    pub lines: Vec<Line>,
    pub path: Option<String>,
}

#[derive(Debug)]
pub struct PolicyError {
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

fn tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in line.chars() {
        match c {
            '"' => {
                in_q = !in_q;
                if !in_q {
                    out.push(std::mem::take(&mut cur));
                    cur.push('\u{0}'); // mark as quoted-empty guard
                    cur.clear();
                }
            }
            c if c.is_whitespace() && !in_q => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn strip_comment(line: &str) -> &str {
    // Comments start with `--` or `#` outside quotes.
    let mut in_q = false;
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => in_q = !in_q,
            b'#' if !in_q => return &line[..i],
            b'-' if !in_q && i + 1 < b.len() && b[i + 1] == b'-' => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

fn parse_date(s: &str) -> Option<(i32, u32, u32)> {
    let mut it = s.split('-');
    let y = it.next()?.parse().ok()?;
    let m = it.next()?.parse().ok()?;
    let d = it.next()?.parse().ok()?;
    if it.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

/// Today's civil date from the system clock (UTC).
pub fn today() -> (i32, u32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((if m <= 2 { y + 1 } else { y }) as i32, m, d)
}

impl Policy {
    pub fn parse(text: &str) -> Result<Policy, PolicyError> {
        let mut p = Policy::default();
        for (i, raw) in text.lines().enumerate() {
            let n = i + 1;
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            let t = tokens(line);
            let low: Vec<String> = t.iter().map(|s| s.to_ascii_lowercase()).collect();
            let err = |msg: String| PolicyError { line: n, msg };
            match low[0].as_str() {
                "policy" => {
                    p.name = t.get(1).cloned().ok_or_else(|| err("expected a name after `policy`".into()))?;
                }
                "trust" => {
                    let kind = Kind::parse(low.get(1).map(String::as_str).unwrap_or("")).ok_or_else(|| err("expected `trust server|skill|hook|permission|tool \"name\"`".into()))?;
                    let name = if kind == Kind::Everything { "*".to_string() } else { t.get(2).cloned().ok_or_else(|| err("expected a quoted name".into()))? };
                    p.lines.push(Line::Trust { kind, name, text: line.to_string() });
                }
                "forbid" => {
                    let r = low.get(1).cloned().ok_or_else(|| err("expected a rule after `forbid`".into()))?;
                    if rule(&r).is_none() {
                        return Err(err(format!("unknown rule `{r}`; run `frostagent rules` for the list")));
                    }
                    p.lines.push(Line::Forbid { rule: r, text: line.to_string() });
                }
                "require" => {
                    if low.get(1).map(String::as_str) == Some("lock") || low.get(1).map(String::as_str) == Some("lockfile") {
                        p.lines.push(Line::RequireLock);
                    } else {
                        return Err(err("only `require lock` is understood".into()));
                    }
                }
                k if Kind::parse(k).is_some() => {
                    let kind = Kind::parse(k).unwrap();
                    let mut idx = 1;
                    let name = if kind == Kind::Everything {
                        "*".to_string()
                    } else {
                        let nm = t.get(1).cloned().ok_or_else(|| err(format!("expected a quoted name after `{k}`")))?;
                        idx = 2;
                        nm
                    };
                    if low.get(idx).map(String::as_str) != Some("may") {
                        return Err(err(format!("expected `may <rule>` after the {k} name")));
                    }
                    let r = low.get(idx + 1).cloned().ok_or_else(|| err("expected a rule after `may`".into()))?;
                    if rule(&r).is_none() {
                        return Err(err(format!("unknown rule `{r}`; run `frostagent rules` for the list")));
                    }
                    let mut file = None;
                    let mut until = None;
                    let mut j = idx + 2;
                    while j < t.len() {
                        match low[j].as_str() {
                            "in" => {
                                file = Some(t.get(j + 1).cloned().ok_or_else(|| err("expected a quoted file after `in`".into()))?);
                                j += 2;
                            }
                            "until" => {
                                let d = t.get(j + 1).ok_or_else(|| err("expected a date after `until`".into()))?;
                                until = Some(parse_date(d).ok_or_else(|| err(format!("bad date `{d}`; use YYYY-MM-DD")))?);
                                j += 2;
                            }
                            other => return Err(err(format!("unexpected `{other}`"))),
                        }
                    }
                    p.lines.push(Line::May { kind, name, rule: r, file, until, text: line.to_string() });
                }
                other => return Err(err(format!("cannot read `{other}`; lines start with policy, trust, forbid, require, server, skill, hook, permission, tool or everything"))),
            }
        }
        Ok(p)
    }

    pub fn require_lock(&self) -> bool {
        self.lines.iter().any(|l| matches!(l, Line::RequireLock))
    }

    /// Apply the policy: drop trusted subjects, waive matching findings, escalate forbidden rules.
    /// Returns (active findings, allowed findings).
    pub fn apply(&self, findings: Vec<Finding>) -> (Vec<Finding>, Vec<Finding>) {
        let now = today();
        let mut active = Vec::new();
        let mut allowed = Vec::new();
        let mut expired_noted = std::collections::BTreeSet::new();
        'outer: for mut fd in findings {
            for l in &self.lines {
                if let Line::Trust { kind, name, .. } = l {
                    if kind.matches(fd.kind) && glob(name, &subject_base(&fd)) {
                        continue 'outer;
                    }
                }
            }
            for l in &self.lines {
                if let Line::May {
                    kind,
                    name,
                    rule: r,
                    file,
                    until,
                    text,
                } = l
                {
                    if r != fd.rule || !kind.matches(fd.kind) || !glob(name, &subject_base(&fd)) {
                        continue;
                    }
                    if let Some(fg) = file {
                        let src = fd
                            .source
                            .as_ref()
                            .map(|s| crate::model::shorten_home(&s.file))
                            .unwrap_or_default();
                        if !glob(fg, &src)
                            && !glob(
                                fg,
                                &src.replace('~', &std::env::var("HOME").unwrap_or_default()),
                            )
                        {
                            continue;
                        }
                    }
                    if let Some(u) = until {
                        if *u < now {
                            if expired_noted.insert(text.clone()) {
                                active.push(Finding { rule: "policy-expired", severity: Severity::Warn, kind: "policy", subject: text.clone(), message: format!("this exception expired on {:04}-{:02}-{:02}; the finding it covered is active again.", u.0, u.1, u.2), source: None, allowed_by: None });
                            }
                            continue;
                        }
                    }
                    fd.allowed_by = Some(text.clone());
                    allowed.push(fd);
                    continue 'outer;
                }
            }
            for l in &self.lines {
                if let Line::Forbid { rule: r, .. } = l {
                    if r == fd.rule {
                        fd.severity = Severity::Fail;
                    }
                }
            }
            active.push(fd);
        }
        (active, allowed)
    }
}

/// The name a policy line addresses: for tools `server/tool`, for hooks `event:matcher`, otherwise the subject.
fn subject_base(f: &Finding) -> String {
    f.subject.clone()
}

/// Case-insensitive glob with `*` only.
pub fn glob(pattern: &str, text: &str) -> bool {
    fn rec(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => rec(&p[1..], t) || (!t.is_empty() && rec(p, &t[1..])),
            (Some(pc), Some(tc)) if pc.eq_ignore_ascii_case(tc) => rec(&p[1..], &t[1..]),
            _ => false,
        }
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

/// Plain-English reading of a policy.
pub fn summary(p: &Policy) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Policy \"{}\".\n",
        if p.name.is_empty() {
            "unnamed"
        } else {
            &p.name
        }
    ));
    out.push_str("Everything is a finding until a line here says otherwise.\n");
    for l in &p.lines {
        match l {
            Line::Trust { kind, name, .. } => out.push_str(&format!(
                "- {} \"{}\" is trusted: nothing about it is reported.\n",
                kind_word(kind),
                name
            )),
            Line::May {
                kind,
                name,
                rule: r,
                file,
                until,
                ..
            } => {
                let about = rule(r).map(|x| x.about).unwrap_or("");
                out.push_str(&format!(
                    "- {} \"{}\" may {}{}{}: {about}.\n",
                    kind_word(kind),
                    name,
                    r,
                    file.as_ref()
                        .map(|f| format!(" in {f}"))
                        .unwrap_or_default(),
                    until
                        .map(|(y, m, d)| format!(" until {y:04}-{m:02}-{d:02}"))
                        .unwrap_or_default()
                ));
            }
            Line::Forbid { rule: r, .. } => out.push_str(&format!(
                "- {r} is a failure, not a warning: {}.\n",
                rule(r).map(|x| x.about).unwrap_or("")
            )),
            Line::RequireLock => {
                out.push_str("- every probed server must have a lockfile entry.\n")
            }
        }
    }
    if p.lines.is_empty() {
        out.push_str("(no exceptions)\n");
    }
    out
}

fn kind_word(k: &Kind) -> &'static str {
    match k {
        Kind::Server => "server",
        Kind::Skill => "skill",
        Kind::Hook => "hook",
        Kind::Permission => "permission",
        Kind::Tool => "tool",
        Kind::Everything => "everything",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lines() {
        let p = Policy::parse("policy \"x\"\nserver \"meshy\" may unpinned-package -- why\n# c\ntrust server \"unity\"\nforbid exec-surface\nskill \"*\" may skill-links in \"~/.claude/*\" until 2030-01-02\nrequire lock\n").unwrap();
        assert_eq!(p.name, "x");
        assert_eq!(p.lines.len(), 5);
        assert!(p.require_lock());
        assert!(Policy::parse("server \"a\" may nonsense").is_err());
        assert!(Policy::parse("wat").is_err());
        assert!(Policy::parse("server \"a\" may unpinned-package until 2030-13-01").is_err());
    }

    #[test]
    fn glob_works() {
        assert!(glob("*", "anything"));
        assert!(glob("mesh*", "Meshy"));
        assert!(glob("*/read_file", "a/read_file"));
        assert!(!glob("a", "b"));
        assert!(glob("~/.claude.json", "~/.claude.json"));
    }

    #[test]
    fn apply_policy() {
        let mk = |rule: &'static str, kind: &'static str, subj: &str| Finding {
            rule,
            severity: Severity::Warn,
            kind,
            subject: subj.into(),
            message: String::new(),
            source: None,
            allowed_by: None,
        };
        let p = Policy::parse("server \"meshy\" may unpinned-package\ntrust server \"unity\"\nforbid exec-surface\nserver \"old\" may plain-http until 2000-01-01").unwrap();
        let (active, allowed) = p.apply(vec![
            mk("unpinned-package", "server", "meshy"),
            mk("unpinned-package", "server", "other"),
            mk("plain-http", "server", "unity"),
            mk("exec-surface", "tool", "x/run"),
            mk("plain-http", "server", "old"),
        ]);
        assert_eq!(allowed.len(), 1);
        assert_eq!(active.len(), 4); // other, exec (escalated), old (expired), policy-expired
        assert!(active
            .iter()
            .any(|f| f.rule == "exec-surface" && f.severity == Severity::Fail));
        assert!(active.iter().any(|f| f.rule == "policy-expired"));
        let (y, _, _) = today();
        assert!(y >= 2026);
    }
}
