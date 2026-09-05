//! `frostagent.lock`: the approved fingerprint of every tool a server exposes.

use crate::model::{Probe, Tool};
use crate::rules::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LockedServer {
    /// Command line or URL at lock time, for the reader's benefit.
    pub launch: String,
    pub locked_at: String,
    /// tool name -> fingerprint
    pub tools: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Lock {
    pub version: u32,
    pub servers: BTreeMap<String, LockedServer>,
}

pub const FILE: &str = "frostagent.lock";

impl Lock {
    pub fn load(path: &std::path::Path) -> Result<Option<Lock>, String> {
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, text + "\n").map_err(|e| e.to_string())
    }

    /// Record the tools of every successful probe, replacing earlier entries for those servers.
    pub fn record(&mut self, probes: &[Probe], launches: &BTreeMap<String, String>) {
        self.version = 1;
        let (y, m, d) = crate::policy::today();
        for p in probes.iter().filter(|p| p.ok) {
            let mut tools = BTreeMap::new();
            for t in &p.tools {
                tools.insert(t.name.clone(), t.fingerprint());
            }
            self.servers.insert(
                p.server.clone(),
                LockedServer {
                    launch: launches.get(&p.server).cloned().unwrap_or_default(),
                    locked_at: format!("{y:04}-{m:02}-{d:02}"),
                    tools,
                },
            );
        }
    }

    /// Compare probes against the lock.
    pub fn compare(&self, probes: &[Probe], require: bool, out: &mut Vec<Finding>) {
        for p in probes.iter().filter(|p| p.ok) {
            let Some(locked) = self.servers.get(&p.server) else {
                out.push(Finding {
                    rule: "server-unlocked",
                    severity: if require { Severity::Fail } else { Severity::Info },
                    kind: "server",
                    subject: p.server.clone(),
                    message: format!("no lockfile entry; run `frostagent lock` to approve its {} tool{} as they are now.", p.tools.len(), if p.tools.len() == 1 { "" } else { "s" }),
                    source: None,
                    allowed_by: None,
                });
                continue;
            };
            let mut seen = std::collections::BTreeSet::new();
            for t in &p.tools {
                seen.insert(t.name.clone());
                match locked.tools.get(&t.name) {
                    None => out.push(tool_finding("tool-added", Severity::Warn, t, "is not in the lockfile. Review it, then `frostagent lock` to approve.")),
                    Some(fp) if *fp != t.fingerprint() => out.push(tool_finding("tool-drift", Severity::Fail, t, &format!("changed since it was locked on {}. Its description or schema is different; read it again before approving with `frostagent lock`.", locked.locked_at))),
                    _ => {}
                }
            }
            for name in locked.tools.keys() {
                if !seen.contains(name) {
                    out.push(Finding {
                        rule: "tool-removed",
                        severity: Severity::Info,
                        kind: "tool",
                        subject: format!("{}/{}", p.server, name),
                        message: "was locked but the server no longer exposes it.".into(),
                        source: None,
                        allowed_by: None,
                    });
                }
            }
        }
    }
}

fn tool_finding(rule: &'static str, severity: Severity, t: &Tool, msg: &str) -> Finding {
    Finding {
        rule,
        severity,
        kind: "tool",
        subject: format!("{}/{}", t.server, t.name),
        message: msg.to_string(),
        source: None,
        allowed_by: None,
    }
}
