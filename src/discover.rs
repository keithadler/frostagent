//! Find agent configuration on disk and normalize it.
//!
//! Project level (relative to the scanned directory):
//!   .mcp.json                         Claude Code project servers
//!   .claude/settings.json             hooks, permissions
//!   .claude/settings.local.json       hooks, permissions
//!   .claude/skills/*/SKILL.md         skills
//!   .cursor/mcp.json  .vscode/mcp.json  .windsurf/mcp.json  .gemini/settings.json
//! User level (with --user):
//!   ~/.claude.json                    global mcpServers and per-project mcpServers
//!   ~/.claude/settings.json           hooks, permissions
//!   ~/.claude/skills/*/SKILL.md
//!   ~/.claude/plugins/marketplaces/** plugin .mcp.json, hooks, skills
//!   ~/Library/Application Support/Claude/claude_desktop_config.json
//!   ~/.cursor/mcp.json

use crate::model::*;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub struct Options {
    pub user: bool,
    /// Project directory being scanned (absolute).
    pub project: PathBuf,
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn read_json(p: &Path, setup: &mut Setup) -> Option<Value> {
    let text = std::fs::read_to_string(p).ok()?;
    setup.files.push(p.to_path_buf());
    match serde_json::from_str::<Value>(&strip_json_comments(&text)) {
        Ok(v) => Some(v),
        Err(e) => {
            setup.errors.push(format!("{}: {e}", shorten_home(p)));
            None
        }
    }
}

/// VS Code and Cursor allow // and /* */ comments in their JSON.
fn strip_json_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c as char);
            if c == b'\\' && i + 1 < b.len() {
                out.push(b[i + 1] as char);
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
        } else if c == b'"' {
            in_str = true;
            out.push('"');
            i += 1;
        } else if c == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else {
            // Re-encode the byte as part of a UTF-8 sequence.
            let ch_len = utf8_len(c);
            out.push_str(std::str::from_utf8(&b[i..(i + ch_len).min(b.len())]).unwrap_or(""));
            i += ch_len;
        }
    }
    out
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

fn str_map(v: Option<&Value>) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Some(Value::Object(o)) = v {
        for (k, v) in o {
            let s = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            m.insert(k.clone(), s);
        }
    }
    m
}

fn str_vec(v: Option<&Value>) -> Vec<String> {
    v.and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .map(|x| {
                    x.as_str()
                        .map(String::from)
                        .unwrap_or_else(|| x.to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse an `mcpServers` object.
pub fn servers_from(
    obj: &Value,
    source_file: &Path,
    location: &str,
    user_level: bool,
    client: &str,
    out: &mut Vec<Server>,
) {
    let Some(map) = obj.as_object() else { return };
    for (name, v) in map {
        let ty = v
            .get("type")
            .and_then(|t| t.as_str())
            .map(|s| s.to_ascii_lowercase());
        let url = v
            .get("url")
            .or_else(|| v.get("serverUrl"))
            .and_then(|u| u.as_str())
            .map(String::from);
        let command = v.get("command").and_then(|c| c.as_str()).map(String::from);
        let transport = match ty.as_deref() {
            Some("stdio") => Transport::Stdio,
            Some("http") | Some("streamable-http") | Some("streamable_http") => Transport::Http,
            Some("sse") => Transport::Sse,
            _ if command.is_some() => Transport::Stdio,
            _ if url.is_some() => Transport::Http,
            _ => Transport::Unknown,
        };
        out.push(Server {
            name: name.clone(),
            source: Source {
                file: source_file.to_path_buf(),
                location: format!("{location}mcpServers.{name}"),
                user_level,
            },
            transport,
            command,
            args: str_vec(v.get("args")),
            env: str_map(v.get("env")),
            url,
            headers: str_map(v.get("headers")),
            client: client.to_string(),
        });
    }
}

/// Parse Claude Code `hooks` and `permissions` from a settings object.
fn settings_from(v: &Value, file: &Path, user_level: bool, setup: &mut Setup) {
    if let Some(hooks) = v.get("hooks").and_then(|h| h.as_object()) {
        for (event, groups) in hooks {
            let Some(groups) = groups.as_array() else {
                continue;
            };
            for g in groups {
                let matcher = g
                    .get("matcher")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                let Some(list) = g.get("hooks").and_then(|h| h.as_array()) else {
                    continue;
                };
                for h in list {
                    let ty = h.get("type").and_then(|t| t.as_str()).unwrap_or("command");
                    let command = match ty {
                        "command" => h
                            .get("command")
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string(),
                        "prompt" => format!(
                            "prompt: {}",
                            h.get("prompt").and_then(|c| c.as_str()).unwrap_or("")
                        ),
                        other => format!("{other}: {}", h),
                    };
                    setup.hooks.push(Hook {
                        event: event.clone(),
                        matcher: matcher.clone(),
                        command,
                        source: Source {
                            file: file.to_path_buf(),
                            location: format!("hooks.{event}"),
                            user_level,
                        },
                    });
                }
            }
        }
    }
    if let Some(p) = v.get("permissions").and_then(|p| p.as_object()) {
        for list in ["allow", "deny", "ask"] {
            for rule in str_vec(p.get(list)) {
                setup.permissions.push(Permission {
                    rule,
                    list: list.to_string(),
                    source: Source {
                        file: file.to_path_buf(),
                        location: format!("permissions.{list}"),
                        user_level,
                    },
                });
            }
        }
        if let Some(mode) = p.get("defaultMode").and_then(|m| m.as_str()) {
            setup.permissions.push(Permission {
                rule: format!("defaultMode={mode}"),
                list: "mode".into(),
                source: Source {
                    file: file.to_path_buf(),
                    location: "permissions.defaultMode".into(),
                    user_level,
                },
            });
        }
    }
    if let Some(ms) = v.get("mcpServers") {
        servers_from(ms, file, "", user_level, "claude-code", &mut setup.servers);
    }
}

/// Parse a skill directory.
pub fn skill_from(dir: &Path, user_level: bool) -> Option<Skill> {
    let md = dir.join("SKILL.md");
    let text = std::fs::read_to_string(&md).ok()?;
    let (front, body) = split_frontmatter(&text);
    let mut name = dir
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut description = String::new();
    let mut allowed_tools = Vec::new();
    for line in front.lines() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("name:") {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            if !v.is_empty() {
                name = v.to_string();
            }
        } else if let Some(v) = l.strip_prefix("description:") {
            description = v
                .trim()
                .trim_matches('"')
                .trim_matches('>')
                .trim()
                .to_string();
        } else if let Some(v) = l.strip_prefix("allowed-tools:") {
            let v = v.trim();
            allowed_tools = if v.starts_with('[') {
                v.trim_matches(['[', ']'])
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            } else {
                v.split(',')
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            };
        }
    }
    // Multi-line description (block scalar) gets its continuation lines.
    if description.is_empty() || description == ">-" {
        let mut collecting = false;
        let mut parts = Vec::new();
        for line in front.lines() {
            if line.trim_start().starts_with("description:") {
                collecting = true;
                continue;
            }
            if collecting {
                if line.starts_with(' ') || line.starts_with('\t') {
                    parts.push(line.trim().to_string());
                } else {
                    break;
                }
            }
        }
        description = parts.join(" ");
    }
    let mut files = Vec::new();
    collect_files(dir, dir, &mut files, 0);
    Some(Skill {
        name,
        dir: dir.to_path_buf(),
        source: Source {
            file: md,
            location: String::new(),
            user_level,
        },
        description,
        allowed_tools,
        body: body.to_string(),
        files,
    })
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(String, String)>, depth: usize) {
    if depth > 4 || out.len() > 200 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name()
                .map(|n| n == "node_modules" || n == ".git")
                .unwrap_or(false)
            {
                continue;
            }
            collect_files(root, &p, out, depth + 1);
        } else if p.file_name().map(|n| n != "SKILL.md").unwrap_or(true) {
            let rel = p.strip_prefix(root).unwrap_or(&p).display().to_string();
            let text = match std::fs::metadata(&p) {
                Ok(m) if m.len() <= 512 * 1024 => std::fs::read_to_string(&p).unwrap_or_default(),
                _ => String::new(),
            };
            out.push((rel, text));
        }
    }
}

pub fn split_frontmatter(text: &str) -> (&str, &str) {
    let t = text.trim_start_matches('\u{feff}');
    if let Some(rest) = t.strip_prefix("---") {
        if let Some(end) = rest.find("\n---") {
            let front = &rest[..end];
            let body = &rest[end + 4..];
            return (front, body);
        }
    }
    ("", t)
}

fn skills_in(dir: &Path, user_level: bool, setup: &mut Setup) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() && p.join("SKILL.md").exists() {
            setup.files.push(p.join("SKILL.md"));
            if let Some(s) = skill_from(&p, user_level) {
                setup.skills.push(s);
            }
        } else if p.file_name().map(|n| n == "SKILL.md").unwrap_or(false) {
            // A bare SKILL.md directly in the skills dir.
            if let Some(parent) = p.parent() {
                if let Some(s) = skill_from(parent, user_level) {
                    setup.skills.push(s);
                }
            }
        }
    }
}

/// Plugin directories: each may hold .mcp.json, hooks/hooks.json, skills/, commands/.
fn plugin_dir(dir: &Path, user_level: bool, setup: &mut Setup) {
    let mcp = dir.join(".mcp.json");
    if mcp.exists() {
        if let Some(v) = read_json(&mcp, setup) {
            let obj = v.get("mcpServers").unwrap_or(&v);
            servers_from(obj, &mcp, "", user_level, "plugin", &mut setup.servers);
        }
    }
    let hooks = dir.join("hooks").join("hooks.json");
    if hooks.exists() {
        if let Some(v) = read_json(&hooks, setup) {
            let wrapped = if v.get("hooks").is_some() {
                v
            } else {
                serde_json::json!({ "hooks": v })
            };
            settings_from(&wrapped, &hooks, user_level, setup);
        }
    }
    let skills = dir.join("skills");
    if skills.is_dir() {
        skills_in(&skills, user_level, setup);
    }
}

fn walk_plugins(root: &Path, user_level: bool, setup: &mut Setup, depth: usize) {
    if depth > 5 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_dir()
            || p.file_name()
                .map(|n| n == "node_modules" || n == ".git")
                .unwrap_or(false)
        {
            continue;
        }
        let is_plugin = p.join(".claude-plugin").join("plugin.json").exists()
            || p.join("plugin.json").exists()
            || p.join(".mcp.json").exists()
            || p.join("hooks").join("hooks.json").exists();
        if is_plugin {
            plugin_dir(&p, user_level, setup);
        }
        walk_plugins(&p, user_level, setup, depth + 1);
    }
}

/// Discover everything for the given options.
pub fn discover(opts: &Options) -> Setup {
    let mut setup = Setup::default();
    let proj = &opts.project;

    // Project level.
    let mcp = proj.join(".mcp.json");
    if mcp.exists() {
        if let Some(v) = read_json(&mcp, &mut setup) {
            let obj = v.get("mcpServers").unwrap_or(&v);
            servers_from(obj, &mcp, "", false, "claude-code", &mut setup.servers);
        }
    }
    for name in ["settings.json", "settings.local.json"] {
        let p = proj.join(".claude").join(name);
        if p.exists() {
            if let Some(v) = read_json(&p, &mut setup) {
                settings_from(&v, &p, false, &mut setup);
            }
        }
    }
    skills_in(&proj.join(".claude").join("skills"), false, &mut setup);
    for (rel, client) in [
        (".cursor/mcp.json", "cursor"),
        (".vscode/mcp.json", "vscode"),
        (".windsurf/mcp.json", "windsurf"),
        (".gemini/settings.json", "gemini"),
    ] {
        let p = proj.join(rel);
        if p.exists() {
            if let Some(v) = read_json(&p, &mut setup) {
                let obj = v
                    .get("mcpServers")
                    .or_else(|| v.get("servers"))
                    .unwrap_or(&v);
                servers_from(obj, &p, "", false, client, &mut setup.servers);
            }
        }
    }
    // Plugins vendored in the project.
    let proj_plugins = proj.join(".claude").join("plugins");
    if proj_plugins.is_dir() {
        walk_plugins(&proj_plugins, false, &mut setup, 0);
    }

    if opts.user {
        if let Some(home) = home() {
            let cj = home.join(".claude.json");
            if cj.exists() {
                if let Some(v) = read_json(&cj, &mut setup) {
                    if let Some(ms) = v.get("mcpServers") {
                        servers_from(ms, &cj, "", true, "claude-code", &mut setup.servers);
                    }
                    if let Some(projects) = v.get("projects").and_then(|p| p.as_object()) {
                        let here = proj.display().to_string();
                        for (path, pv) in projects {
                            if path != &here {
                                continue;
                            }
                            if let Some(ms) = pv.get("mcpServers") {
                                servers_from(
                                    ms,
                                    &cj,
                                    &format!("projects[{}].", shorten_home(Path::new(path))),
                                    true,
                                    "claude-code",
                                    &mut setup.servers,
                                );
                            }
                        }
                    }
                }
            }
            let us = home.join(".claude").join("settings.json");
            if us.exists() {
                if let Some(v) = read_json(&us, &mut setup) {
                    settings_from(&v, &us, true, &mut setup);
                }
            }
            skills_in(&home.join(".claude").join("skills"), true, &mut setup);
            let plugins = home.join(".claude").join("plugins");
            if plugins.is_dir() {
                walk_plugins(&plugins.join("marketplaces"), true, &mut setup, 0);
                walk_plugins(&plugins.join("cache"), true, &mut setup, 0);
            }
            let desktop =
                home.join("Library/Application Support/Claude/claude_desktop_config.json");
            if desktop.exists() {
                if let Some(v) = read_json(&desktop, &mut setup) {
                    if let Some(ms) = v.get("mcpServers") {
                        servers_from(ms, &desktop, "", true, "claude-desktop", &mut setup.servers);
                    }
                }
            }
            let cursor = home.join(".cursor").join("mcp.json");
            if cursor.exists() {
                if let Some(v) = read_json(&cursor, &mut setup) {
                    let obj = v.get("mcpServers").unwrap_or(&v);
                    servers_from(obj, &cursor, "", true, "cursor", &mut setup.servers);
                }
            }
        }
    }
    // The same plugin skill often exists in both the marketplace clone and the install cache.
    let mut seen = std::collections::HashSet::new();
    setup
        .skills
        .retain(|s| seen.insert((s.name.clone(), s.description.clone(), s.body.clone())));
    let mut seen_srv = std::collections::HashSet::new();
    setup.servers.retain(|s| {
        seen_srv.insert((
            s.name.clone(),
            s.command_line(),
            s.url.clone(),
            s.client.clone(),
        ))
    });
    setup
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_stripped() {
        let s = strip_json_comments("{ // hi\n \"a\": \"x//y\", /* c */ \"b\": 1 }");
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["a"], "x//y");
        assert_eq!(v["b"], 1);
    }

    #[test]
    fn frontmatter() {
        let (f, b) = split_frontmatter("---\nname: x\n---\nbody");
        assert_eq!(f.trim(), "name: x");
        assert_eq!(b.trim(), "body");
        let (f, b) = split_frontmatter("no front");
        assert_eq!(f, "");
        assert_eq!(b, "no front");
    }

    #[test]
    fn servers_parse() {
        let v: Value = serde_json::json!({
            "a": {"command": "npx", "args": ["-y", "pkg"], "env": {"K": "v"}},
            "b": {"type": "http", "url": "https://x/mcp", "headers": {"Authorization": "Bearer t"}},
            "c": {"type": "sse", "url": "http://x/sse"}
        });
        let mut out = Vec::new();
        servers_from(
            &v,
            Path::new("/p/.mcp.json"),
            "",
            false,
            "claude-code",
            &mut out,
        );
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].transport, Transport::Stdio);
        assert_eq!(out[0].command_line(), "npx -y pkg");
        assert_eq!(out[1].transport, Transport::Http);
        assert_eq!(out[2].transport, Transport::Sse);
    }
}
