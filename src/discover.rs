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
        if !v.is_object() {
            continue;
        }
        let ty = v
            .get("type")
            .and_then(|t| t.as_str())
            .map(|s| s.to_ascii_lowercase());
        let url = v
            .get("url")
            .or_else(|| v.get("serverUrl"))
            .or_else(|| v.get("httpUrl"))
            .and_then(|u| u.as_str())
            .map(String::from);
        // Zed nests the launch under "command": {"path", "args", "env"}; OpenCode gives "command" as an array.
        let (command, extra_args, zed_env) = match v.get("command") {
            Some(Value::String(c)) => (Some(c.clone()), Vec::new(), None),
            Some(Value::Array(a)) => {
                let all: Vec<String> = a
                    .iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect();
                (
                    all.first().cloned(),
                    all.iter().skip(1).cloned().collect(),
                    None,
                )
            }
            Some(Value::Object(o)) => (
                o.get("path").and_then(|c| c.as_str()).map(String::from),
                str_vec(o.get("args")),
                Some(str_map(o.get("env"))),
            ),
            _ => (None, Vec::new(), None),
        };
        let transport = match ty.as_deref() {
            Some("stdio") | Some("local") => Transport::Stdio,
            Some("http") | Some("streamable-http") | Some("streamable_http") | Some("remote") => {
                Transport::Http
            }
            Some("sse") => Transport::Sse,
            _ if command.is_some() => Transport::Stdio,
            _ if url.is_some() => Transport::Http,
            _ => Transport::Unknown,
        };
        let mut args = str_vec(v.get("args"));
        if args.is_empty() {
            args = extra_args;
        }
        let mut env = zed_env.unwrap_or_else(|| str_map(v.get("env")));
        if env.is_empty() {
            env = str_map(v.get("environment"));
        }
        out.push(Server {
            name: name.clone(),
            source: Source {
                file: source_file.to_path_buf(),
                location: format!("{location}{name}"),
                user_level,
            },
            transport,
            command,
            args,
            env,
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
        servers_from(
            ms,
            file,
            "mcpServers.",
            user_level,
            "claude-code",
            &mut setup.servers,
        );
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
            servers_from(
                obj,
                &mcp,
                "mcpServers.",
                user_level,
                "plugin",
                &mut setup.servers,
            );
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

/// Read a JSON file that holds servers under one of the known keys.
fn json_servers_file(p: &Path, client: &str, user_level: bool, setup: &mut Setup) {
    let Some(v) = read_json(p, setup) else { return };
    // Zed: "context_servers"; VS Code: "servers"; OpenCode: "mcp"; Amp: "amp.mcpServers"; most others: "mcpServers".
    for (key, prefix) in [
        ("mcpServers", "mcpServers."),
        ("servers", "servers."),
        ("context_servers", "context_servers."),
        ("mcp", "mcp."),
        ("amp.mcpServers", "amp.mcpServers."),
    ] {
        if let Some(obj) = v.get(key) {
            if obj.is_object() {
                servers_from(obj, p, prefix, user_level, client, &mut setup.servers);
            }
        }
    }
    if v.get("hooks").is_some() || v.get("permissions").is_some() {
        settings_from(&v, p, user_level, setup);
    }
}

/// Codex keeps servers in TOML: `[mcp_servers.<name>]` tables with command, args, env, url.
fn toml_servers_file(p: &Path, user_level: bool, setup: &mut Setup) {
    let Ok(text) = std::fs::read_to_string(p) else {
        return;
    };
    setup.files.push(p.to_path_buf());
    match toml_subset::parse(&text) {
        Ok(v) => {
            if let Some(ms) = v.get("mcp_servers") {
                servers_from(
                    ms,
                    p,
                    "mcp_servers.",
                    user_level,
                    "codex",
                    &mut setup.servers,
                );
            }
        }
        Err(e) => setup.errors.push(format!("{}: {e}", shorten_home(p))),
    }
}

/// Just enough TOML for agent configs: tables, dotted table headers, strings,
/// numbers, booleans, arrays, inline tables. Produces serde_json values.
pub mod toml_subset {
    use serde_json::{json, Map, Value};

    pub fn parse(text: &str) -> Result<Value, String> {
        let mut root = Map::new();
        let mut path: Vec<String> = Vec::new();
        let mut lines = text.lines().enumerate().peekable();
        while let Some((n, raw)) = lines.next() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(h) = line.strip_prefix("[[") {
                // arrays of tables: treat as a table keyed by index
                let name = h.trim_end_matches(']').trim();
                path = split_key(name);
                continue;
            }
            if let Some(h) = line.strip_prefix('[') {
                let name = h.trim_end_matches(']').trim();
                path = split_key(name);
                ensure_table(&mut root, &path);
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| format!("line {}: expected `key = value`", n + 1))?;
            let mut value_text = v.trim().to_string();
            // Multi-line arrays and inline tables.
            while (value_text.starts_with('[') && !balanced(&value_text, '[', ']'))
                || (value_text.starts_with('{') && !balanced(&value_text, '{', '}'))
                || value_text.starts_with("\"\"\"") && value_text.matches("\"\"\"").count() < 2
            {
                let Some((_, next)) = lines.next() else { break };
                value_text.push('\n');
                value_text.push_str(strip_comment(next).trim());
            }
            let value =
                parse_value(value_text.trim()).map_err(|e| format!("line {}: {e}", n + 1))?;
            let mut full = path.clone();
            full.extend(split_key(k.trim()));
            insert(&mut root, &full, value);
        }
        Ok(Value::Object(root))
    }

    fn balanced(s: &str, open: char, close: char) -> bool {
        let mut depth = 0i32;
        let mut in_str = false;
        for c in s.chars() {
            if c == '"' {
                in_str = !in_str;
            } else if !in_str {
                if c == open {
                    depth += 1;
                } else if c == close {
                    depth -= 1;
                }
            }
        }
        depth <= 0
    }

    fn strip_comment(s: &str) -> &str {
        let mut in_str = false;
        for (i, c) in s.char_indices() {
            if c == '"' {
                in_str = !in_str;
            } else if c == '#' && !in_str {
                return &s[..i];
            }
        }
        s
    }

    fn split_key(k: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut in_q = false;
        for c in k.chars() {
            match c {
                '"' | '\'' => in_q = !in_q,
                '.' if !in_q => out.push(std::mem::take(&mut cur)),
                c if c.is_whitespace() && !in_q => {}
                c => cur.push(c),
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    }

    fn ensure_table(root: &mut Map<String, Value>, path: &[String]) {
        let mut cur = root;
        for k in path {
            let e = cur.entry(k.clone()).or_insert_with(|| json!({}));
            if !e.is_object() {
                *e = json!({});
            }
            cur = e.as_object_mut().unwrap();
        }
    }

    fn insert(root: &mut Map<String, Value>, path: &[String], v: Value) {
        if path.is_empty() {
            return;
        }
        ensure_table(root, &path[..path.len() - 1]);
        let mut cur = root;
        for k in &path[..path.len() - 1] {
            cur = cur.get_mut(k).unwrap().as_object_mut().unwrap();
        }
        cur.insert(path[path.len() - 1].clone(), v);
    }

    pub fn parse_value(s: &str) -> Result<Value, String> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("\"\"\"") {
            return Ok(Value::String(
                rest.trim_end_matches("\"\"\"")
                    .trim_start_matches('\n')
                    .to_string(),
            ));
        }
        if s.starts_with('"') {
            return parse_basic_string(s).map(Value::String);
        }
        if s.starts_with('\'') {
            return Ok(Value::String(s.trim_matches('\'').to_string()));
        }
        if s == "true" || s == "false" {
            return Ok(Value::Bool(s == "true"));
        }
        if s.starts_with('[') {
            let inner = s
                .strip_prefix('[')
                .and_then(|x| x.strip_suffix(']'))
                .ok_or("unterminated array")?;
            return Ok(Value::Array(
                split_top(inner)?
                    .into_iter()
                    .map(|e| parse_value(&e))
                    .collect::<Result<Vec<_>, _>>()?,
            ));
        }
        if s.starts_with('{') {
            let inner = s
                .strip_prefix('{')
                .and_then(|x| x.strip_suffix('}'))
                .ok_or("unterminated inline table")?;
            let mut m = Map::new();
            for pair in split_top(inner)? {
                let (k, v) = pair
                    .split_once('=')
                    .ok_or("inline table needs key = value")?;
                let key = split_key(k.trim()).pop().unwrap_or_default();
                m.insert(key, parse_value(v)?);
            }
            return Ok(Value::Object(m));
        }
        if let Ok(n) = s.replace('_', "").parse::<i64>() {
            return Ok(json!(n));
        }
        if let Ok(x) = s.parse::<f64>() {
            return Ok(json!(x));
        }
        Ok(Value::String(s.to_string()))
    }

    fn parse_basic_string(s: &str) -> Result<String, String> {
        let mut out = String::new();
        let mut chars = s[1..].chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => return Ok(out),
                '\\' => match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('r') => out.push('\r'),
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('u') => {
                        let hex: String = chars.by_ref().take(4).collect();
                        if let Some(ch) =
                            u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                        {
                            out.push(ch);
                        }
                    }
                    Some(o) => {
                        out.push('\\');
                        out.push(o);
                    }
                    None => break,
                },
                c => out.push(c),
            }
        }
        Err("unterminated string".into())
    }

    /// Split on top-level commas, respecting strings, brackets and braces.
    fn split_top(s: &str) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut depth = 0i32;
        let mut in_str = false;
        let mut prev = ' ';
        for c in s.chars() {
            if c == '"' && prev != '\\' {
                in_str = !in_str;
            }
            if !in_str {
                match c {
                    '[' | '{' => depth += 1,
                    ']' | '}' => depth -= 1,
                    ',' if depth == 0 => {
                        let t = cur.trim().to_string();
                        if !t.is_empty() {
                            out.push(t);
                        }
                        cur.clear();
                        prev = c;
                        continue;
                    }
                    _ => {}
                }
            }
            cur.push(c);
            prev = c;
        }
        let t = cur.trim().to_string();
        if !t.is_empty() {
            out.push(t);
        }
        Ok(out)
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
            servers_from(
                obj,
                &mcp,
                "mcpServers.",
                false,
                "claude-code",
                &mut setup.servers,
            );
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
        (".zed/settings.json", "zed"),
        ("opencode.json", "opencode"),
        (".opencode/opencode.json", "opencode"),
        (".roo/mcp.json", "roo"),
        (".kiro/settings/mcp.json", "kiro"),
        ("amp.json", "amp"),
    ] {
        let p = proj.join(rel);
        if p.exists() {
            json_servers_file(&p, client, false, &mut setup);
        }
    }
    let codex_proj = proj.join(".codex").join("config.toml");
    if codex_proj.exists() {
        toml_servers_file(&codex_proj, false, &mut setup);
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
                        servers_from(
                            ms,
                            &cj,
                            "mcpServers.",
                            true,
                            "claude-code",
                            &mut setup.servers,
                        );
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
                                    &format!(
                                        "projects[{}].mcpServers.",
                                        shorten_home(Path::new(path))
                                    ),
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
                        servers_from(
                            ms,
                            &desktop,
                            "mcpServers.",
                            true,
                            "claude-desktop",
                            &mut setup.servers,
                        );
                    }
                }
            }
            for (rel, client) in [
                (".cursor/mcp.json", "cursor"),
                (".gemini/settings.json", "gemini"),
                (".codeium/windsurf/mcp_config.json", "windsurf"),
                (".config/zed/settings.json", "zed"),
                (".config/opencode/opencode.json", "opencode"),
                (".config/amp/settings.json", "amp"),
                (".kiro/settings/mcp.json", "kiro"),
                ("Library/Application Support/Code/User/mcp.json", "vscode"),
                ("Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", "cline"),
                ("Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json", "roo"),
                (".config/Code/User/mcp.json", "vscode"),
                (".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json", "cline"),
            ] {
                let p = home.join(rel);
                if p.exists() {
                    json_servers_file(&p, client, true, &mut setup);
                }
            }
            let codex = home.join(".codex").join("config.toml");
            if codex.exists() {
                toml_servers_file(&codex, true, &mut setup);
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
    fn toml_codex() {
        let t = r#"
model = "o3"   # comment
[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_TOKEN = "${GITHUB_TOKEN}", DEBUG = "1" }

[mcp_servers.remote]
url = "https://mcp.vendor.io/mcp"
headers = { Authorization = "Bearer abc" }
[mcp_servers.multi]
command = "uvx"
args = [
  "mcp-server-fetch",
]
"#;
        let v = toml_subset::parse(t).unwrap();
        let mut out = Vec::new();
        servers_from(
            &v["mcp_servers"],
            Path::new("/h/.codex/config.toml"),
            "mcp_servers.",
            true,
            "codex",
            &mut out,
        );
        assert_eq!(out.len(), 3);
        assert_eq!(
            out[0].command_line(),
            "npx -y @modelcontextprotocol/server-github"
        );
        assert_eq!(
            out[0].env.get("GITHUB_TOKEN").map(String::as_str),
            Some("${GITHUB_TOKEN}")
        );
        assert_eq!(out[1].url.as_deref(), Some("https://mcp.vendor.io/mcp"));
        assert_eq!(out[2].args, vec!["mcp-server-fetch"]);
        assert!(toml_subset::parse("bad line without equals").is_err());
    }

    #[test]
    fn zed_and_opencode_shapes() {
        let zed: Value = serde_json::json!({"fs": {"command": {"path": "node", "args": ["server.js"], "env": {"K": "v"}}}});
        let mut out = Vec::new();
        servers_from(
            &zed,
            Path::new("/h/.config/zed/settings.json"),
            "context_servers.",
            true,
            "zed",
            &mut out,
        );
        assert_eq!(out[0].command_line(), "node server.js");
        assert_eq!(out[0].env.get("K").map(String::as_str), Some("v"));
        let oc: Value = serde_json::json!({"fs": {"type": "local", "command": ["bun", "x", "my-mcp"], "environment": {"A": "b"}}, "r": {"type": "remote", "url": "https://x/mcp"}});
        let mut out = Vec::new();
        servers_from(
            &oc,
            Path::new("/p/opencode.json"),
            "mcp.",
            false,
            "opencode",
            &mut out,
        );
        assert_eq!(out[0].command_line(), "bun x my-mcp");
        assert_eq!(out[0].transport, Transport::Stdio);
        assert_eq!(out[1].transport, Transport::Http);
    }

    #[test]
    fn comment_stripper_never_panics() {
        let mut seed: u64 = 0x9E3779B97F4A7C15;
        for _ in 0..3000 {
            let mut s = String::new();
            for _ in 0..(seed % 40) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let c = match seed % 12 {
                    0 => '"',
                    1 => '/',
                    2 => '*',
                    3 => '\\',
                    4 => '\n',
                    5 => 'é',
                    6 => '😀',
                    _ => (b'a' + (seed % 26) as u8) as char,
                };
                s.push(c);
            }
            let _ = strip_json_comments(&s);
            let _ = toml_subset::parse(&s);
            let _ = split_frontmatter(&s);
        }
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
