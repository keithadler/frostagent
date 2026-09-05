//! Normalized view of an agent setup: servers, hooks, permissions, skills.

use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Where a thing was declared.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Source {
    pub file: PathBuf,
    /// JSON pointer or section name inside the file, for messages.
    pub location: String,
    /// True when the file lives under the user's home rather than the project.
    pub user_level: bool,
}

impl Source {
    pub fn display(&self) -> String {
        let f = shorten_home(&self.file);
        if self.location.is_empty() {
            f
        } else {
            format!("{f} ({})", self.location)
        }
    }
}

pub fn shorten_home(p: &std::path::Path) -> String {
    let s = p.display().to_string();
    if let Ok(home) = std::env::var("HOME") {
        if let Some(rest) = s.strip_prefix(&home) {
            return format!("~{rest}");
        }
    }
    s
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Stdio,
    Http,
    Sse,
    Unknown,
}

/// An MCP server declaration.
#[derive(Debug, Clone, Serialize)]
pub struct Server {
    pub name: String,
    pub source: Source,
    pub transport: Transport,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub url: Option<String>,
    pub headers: BTreeMap<String, String>,
    /// Which client owns this declaration: claude-code, claude-desktop, cursor, vscode, plugin.
    pub client: String,
}

impl Server {
    /// Command line as one string, for display and matching.
    pub fn command_line(&self) -> String {
        let mut parts = Vec::new();
        if let Some(c) = &self.command {
            parts.push(c.clone());
        }
        parts.extend(self.args.iter().cloned());
        parts.join(" ")
    }
}

/// A shell hook run automatically by the agent host.
#[derive(Debug, Clone, Serialize)]
pub struct Hook {
    pub event: String,
    pub matcher: String,
    pub command: String,
    pub source: Source,
}

impl Hook {
    pub fn name(&self) -> String {
        if self.matcher.is_empty() {
            self.event.clone()
        } else {
            format!("{}:{}", self.event, self.matcher)
        }
    }
}

/// One permission rule from an allow or deny list.
#[derive(Debug, Clone, Serialize)]
pub struct Permission {
    pub rule: String,
    /// "allow", "deny" or "ask".
    pub list: String,
    pub source: Source,
}

/// A skill or plugin skill: SKILL.md plus whatever sits beside it.
#[derive(Debug, Clone, Serialize)]
pub struct Skill {
    pub name: String,
    pub dir: PathBuf,
    pub source: Source,
    pub description: String,
    pub allowed_tools: Vec<String>,
    /// SKILL.md body without the frontmatter.
    pub body: String,
    /// Other files in the skill directory (relative paths) with their text when readable.
    pub files: Vec<(String, String)>,
}

/// Everything discovered.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Setup {
    pub servers: Vec<Server>,
    pub hooks: Vec<Hook>,
    pub permissions: Vec<Permission>,
    pub skills: Vec<Skill>,
    /// Files that were looked at, for the report.
    pub files: Vec<PathBuf>,
    /// Files that exist but could not be parsed.
    pub errors: Vec<String>,
}

/// One tool as reported by a live server.
#[derive(Debug, Clone, Serialize)]
pub struct Tool {
    pub server: String,
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub annotations: serde_json::Value,
    pub title: Option<String>,
}

impl Tool {
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.name.as_bytes());
        h.update([0]);
        h.update(self.description.as_bytes());
        h.update([0]);
        h.update(self.input_schema.to_string().as_bytes());
        h.update([0]);
        h.update(self.annotations.to_string().as_bytes());
        let d = h.finalize();
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn annotation_bool(&self, key: &str) -> Option<bool> {
        self.annotations.get(key).and_then(|v| v.as_bool())
    }
}

/// Result of probing one server.
#[derive(Debug, Clone, Serialize)]
pub struct Probe {
    pub server: String,
    pub ok: bool,
    pub error: Option<String>,
    pub server_info: Option<serde_json::Value>,
    pub protocol_version: Option<String>,
    pub tools: Vec<Tool>,
    /// Bytes the server wrote to stderr during the probe (truncated).
    pub stderr: String,
    pub millis: u128,
}
