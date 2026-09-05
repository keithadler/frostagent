//! Argument-to-sink tracing inside tool handlers of local servers.
//!
//! For every tool handler found in the server's source, the parameters the
//! model controls are followed, one assignment hop at a time, into calls that
//! spawn processes, evaluate code, touch the filesystem, run SQL or open
//! network connections. A tainted value in a string-built shell command or an
//! eval is command injection by construction; in a spawn, a path, a query or a
//! URL it is the surface the tool exists to offer, and is reported so the
//! policy can say so. Heuristic, file-local, and deliberately conservative
//! about what counts as a handler.

use crate::model::{Server, Source};
use crate::rules::{Finding, Severity};
use regex::Regex;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::OnceLock;

fn re(s: &'static str) -> &'static Regex {
    static CACHE: OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<&'static str, &'static Regex>>,
    > = OnceLock::new();
    let m = CACHE.get_or_init(Default::default);
    let mut g = m.lock().unwrap();
    if let Some(r) = g.get(s) {
        return r;
    }
    let r: &'static Regex = Box::leak(Box::new(Regex::new(s).expect("regex")));
    g.insert(s, r);
    r
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SinkKind {
    Shell,
    Spawn,
    Eval,
    Fs,
    Sql,
    Network,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Flow {
    pub tool: String,
    pub file: String,
    pub param: String,
    pub sink: String,
    pub kind: String,
}

/// One tool handler: its name, parameters and body text.
struct Handler {
    tool: String,
    params: Vec<String>,
    body: String,
}

/// Text of a balanced region starting at `open_idx` (which must be `(` or `{`).
fn balanced(text: &str, open_idx: usize) -> Option<&str> {
    let b = text.as_bytes();
    let open = b[open_idx];
    let close = match open {
        b'(' => b')',
        b'{' => b'}',
        b'[' => b']',
        _ => return None,
    };
    let mut depth = 0i32;
    let mut i = open_idx;
    let mut in_str: Option<u8> = None;
    while i < b.len() {
        let c = b[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else if c == b'"' || c == b'\'' || c == b'`' {
            in_str = Some(c);
        } else if c == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        } else if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return text.get(open_idx..=i);
            }
        }
        i += 1;
    }
    None
}

fn idents(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    for c in re(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::\s*[A-Za-z_$][A-Za-z0-9_$]*)?\s*(?:=[^,}]*)?")
        .captures_iter(pattern)
    {
        let name = c.get(1).unwrap().as_str();
        if !matches!(
            name,
            "async"
                | "function"
                | "string"
                | "number"
                | "boolean"
                | "any"
                | "true"
                | "false"
                | "null"
                | "undefined"
                | "Record"
                | "Array"
                | "Promise"
                | "void"
                | "object"
                | "const"
                | "let"
                | "var"
                | "type"
                | "typeof"
        ) {
            out.push(name.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Parameters and body of the handler arrow function inside a call's argument
/// list: the `=>` that sits at the top level of the call, not one nested in
/// the handler body or in the schema. `({a, b}) =>`, `(args) =>`, `args =>`.
fn arrow_params(call_args: &str) -> Option<(Vec<String>, String)> {
    let b = call_args.as_bytes();
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    let mut arrow: Option<usize> = None;
    let mut i = 0;
    while i + 1 < b.len() {
        let c = b[i];
        if let Some(q) = in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q {
                in_str = None;
            }
        } else {
            match c {
                b'"' | b'\'' | b'`' => in_str = Some(c),
                b'(' | b'{' | b'[' => depth += 1,
                b')' | b'}' | b']' => depth -= 1,
                b'=' if b[i + 1] == b'>' && depth == 1 => {
                    arrow = Some(i);
                    break;
                }
                _ => {}
            }
        }
        i += 1;
    }
    let arrow = arrow?;
    let before = call_args[..arrow].trim_end();
    let params: Vec<String> = if before.ends_with(')') {
        // Find the matching '(' for the trailing ')'.
        let mut d = 0i32;
        let mut open = None;
        for (j, ch) in before.char_indices().rev() {
            match ch {
                ')' => d += 1,
                '(' => {
                    d -= 1;
                    if d == 0 {
                        open = Some(j);
                        break;
                    }
                }
                _ => {}
            }
        }
        let inner = &before[open? + 1..before.len() - 1];
        if inner.trim_start().starts_with('{') {
            idents(
                inner
                    .trim()
                    .trim_start_matches('{')
                    .trim_end_matches('}')
                    .split(':')
                    .next()
                    .unwrap_or(""),
            )
            .into_iter()
            .chain(idents(inner))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
        } else {
            idents(inner.split(':').next().unwrap_or(inner))
        }
    } else {
        let name = before
            .rsplit(|c: char| !c.is_alphanumeric() && c != '_' && c != '$')
            .next()?;
        vec![name.to_string()]
    };
    let after = &call_args[arrow + 2..];
    let body_start = after.find('{')?;
    let body = balanced(after, body_start)?.to_string();
    Some((params, body))
}

/// The last top-level argument of a call, if it is a bare identifier: a handler passed by name.
fn last_identifier_arg(call_args: &str) -> Option<String> {
    let inner = call_args.strip_prefix('(')?.strip_suffix(')')?;
    let mut depth = 0i32;
    let mut in_str: Option<char> = None;
    let mut last_comma = None;
    for (i, ch) in inner.char_indices() {
        if let Some(q) = in_str {
            if ch == q {
                in_str = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => in_str = Some(ch),
            '(' | '{' | '[' => depth += 1,
            ')' | '}' | ']' => depth -= 1,
            ',' if depth == 0 => last_comma = Some(i),
            _ => {}
        }
    }
    let tail = inner[last_comma? + 1..].trim();
    if re(r"^[A-Za-z_$][A-Za-z0-9_$]*$").is_match(tail) {
        Some(tail.to_string())
    } else {
        None
    }
}

/// Resolve a handler passed by name: `async function name(params) {...}` or `const name = async (params) => {...}`.
fn named_handler(text: &str, call_args: &str) -> Option<(Vec<String>, String)> {
    let name = last_identifier_arg(call_args)?;
    let esc = regex::escape(&name);
    if let Some(m) = Regex::new(&format!(r"(?:async\s+)?function\s+{esc}\s*\("))
        .ok()?
        .find(text)
    {
        let sig = balanced(text, m.end() - 1)?;
        let params = idents(sig.trim_matches(['(', ')']).split(':').next().unwrap_or(""));
        let params = if sig.contains('{') {
            idents(sig)
        } else {
            params
        };
        let after = &text[m.end() - 1 + sig.len()..];
        let body = balanced(after, after.find('{')?)?.to_string();
        return Some((params, body));
    }
    if let Some(m) = Regex::new(&format!(r"(?:const|let|var)\s+{esc}\s*(?::[^=]+)?="))
        .ok()?
        .find(text)
    {
        let rest = &text[m.end()..];
        // Feed the arrow function as if it were a call's argument list.
        let end = rest.find("=>")? + 2;
        let body_open = rest[end..].find('{')? + end;
        let body = balanced(rest, body_open)?;
        let synthetic = format!("({}{})", &rest[..body_open], body);
        return arrow_params(&synthetic);
    }
    None
}

fn js_handlers(text: &str, rel: &str) -> Vec<Handler> {
    let mut out = Vec::new();
    // High-level API: server.tool("name", ...) / registerTool("name", ...) / addTool({ name, execute })
    for m in re(r"\.(?:tool|registerTool)\s*\(").find_iter(text) {
        let Some(args) = balanced(text, m.end() - 1) else {
            continue;
        };
        let name = re(r#"^\(\s*["'`]([^"'`]+)["'`]"#)
            .captures(args)
            .map(|c| c[1].to_string())
            .unwrap_or_else(|| "?".into());
        if let Some((params, body)) = arrow_params(args) {
            out.push(Handler {
                tool: name,
                params,
                body,
            });
        } else if let Some((params, body)) = named_handler(text, args) {
            out.push(Handler {
                tool: name,
                params,
                body,
            });
        }
    }
    // Low-level API: setRequestHandler(CallToolRequestSchema, async (request) => {...})
    for m in
        re(r"setRequestHandler\s*\(\s*(?:[A-Za-z_$][\w$]*\.)*CallToolRequestSchema").find_iter(text)
    {
        let Some(open) = text[m.start()..].find('(').map(|j| m.start() + j) else {
            continue;
        };
        let Some(args) = balanced(text, open) else {
            continue;
        };
        if let Some((mut params, body)) = arrow_params(args) {
            // Anything destructured from the arguments object is a source too.
            for c in re(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:request\.params\.arguments|args|arguments|params|input)\b").captures_iter(&body) {
                params.extend(idents(&c[1]));
            }
            params.push("request.params.arguments".into());
            params.push("args".into());
            out.push(Handler {
                tool: format!("* ({rel})"),
                params,
                body,
            });
        }
    }
    out
}

fn py_block(text: &str, def_start: usize) -> String {
    // The body is the indented block after the def line.
    let rest = &text[def_start..];
    let mut lines = rest.lines();
    let Some(first) = lines.next() else {
        return String::new();
    };
    let base_indent = first.len() - first.trim_start().len();
    let mut body = String::new();
    body.push_str(first);
    body.push('\n');
    for l in lines {
        if l.trim().is_empty() {
            body.push('\n');
            continue;
        }
        let ind = l.len() - l.trim_start().len();
        if ind <= base_indent {
            break;
        }
        body.push_str(l);
        body.push('\n');
    }
    body
}

fn py_handlers(text: &str, rel: &str) -> Vec<Handler> {
    let mut out = Vec::new();
    for m in re(r"(?m)^\s*@[A-Za-z_][A-Za-z0-9_.]*\.tool\s*(?:\([^)]*\))?\s*\n((?:\s*@[^\n]*\n)*)\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(").captures_iter(text) {
        let name = m[2].to_string();
        let def_pos = m.get(0).unwrap().end() - 1;
        let Some(sig) = balanced(text, def_pos) else { continue };
        let params: Vec<String> = sig
            .trim_matches(['(', ')'])
            .split(',')
            .map(|p| p.split(':').next().unwrap_or("").split('=').next().unwrap_or("").trim().trim_start_matches('*').to_string())
            .filter(|p| !p.is_empty() && p != "self" && p != "ctx" && p != "context")
            .collect();
        let line_start = text[..m.get(0).unwrap().start()].len();
        let def_line_start = text[line_start..].find("def ").map(|i| line_start + i).unwrap_or(line_start);
        let line_begin = text[..def_line_start].rfind('\n').map(|i| i + 1).unwrap_or(0);
        out.push(Handler { tool: name, params, body: py_block(text, line_begin) });
    }
    // Low-level: @server.call_tool() async def handler(name, arguments)
    for m in re(r"(?m)^\s*@[A-Za-z_][A-Za-z0-9_.]*\.call_tool\s*\([^)]*\)\s*\n\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)").captures_iter(text) {
        let sig = &m[2];
        let mut params: Vec<String> = sig.split(',').map(|p| p.split(':').next().unwrap_or("").trim().to_string()).filter(|p| !p.is_empty()).collect();
        let line_begin = text[..m.get(0).unwrap().start()].len();
        let def_pos = text[line_begin..].find("def ").map(|i| line_begin + i).unwrap_or(line_begin);
        let line_start = text[..def_pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let body = py_block(text, line_start);
        for c in re(r#"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:arguments|args|params)(?:\.get\(|\[)\s*["']"#).captures_iter(&body) {
            params.push(c[1].to_string());
        }
        out.push(Handler { tool: format!("* ({rel})"), params, body });
    }
    out
}

const JS_SINKS: &[(&str, SinkKind)] = &[
    (r"\b(?:child_process\.)?exec(?:Sync)?\s*\(", SinkKind::Shell),
    (
        r"\b(?:child_process\.)?(?:spawn|spawnSync|execFile|execFileSync|fork)\s*\(",
        SinkKind::Spawn,
    ),
    (
        r"\bDeno\.(?:run|Command)\s*\(|\bBun\.(?:spawn|\$)\s*\(",
        SinkKind::Spawn,
    ),
    (
        r"\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.runIn[A-Za-z]*\s*\(",
        SinkKind::Eval,
    ),
    (
        r"\b(?:fs|fsp|promises)\.(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rmdir|rename|renameSync|mkdir|mkdirSync|readdir|readdirSync|stat|statSync|createReadStream|createWriteStream|access|copyFile|realpath)\s*\(",
        SinkKind::Fs,
    ),
    (
        r"\b(?:readFile|writeFile|appendFile|unlink|readdir|stat|rm|mkdir|rename)(?:Sync)?\s*\(",
        SinkKind::Fs,
    ),
    (
        r"\b(?:db|database|conn|connection|client|pool|stmt|statement|cursor|knex|sql|pg|sqlite|mysql|prisma|sequelize|drizzle)[A-Za-z0-9_]*\.(?:query|execute|run|all|get|prepare|exec|raw)\s*\(",
        SinkKind::Sql,
    ),
    (
        r"\bfetch\s*\(|\baxios(?:\.[a-z]+)?\s*\(|\bgot\s*\(|\bhttps?\.(?:request|get)\s*\(|new\s+WebSocket\s*\(",
        SinkKind::Network,
    ),
];

const PY_SINKS: &[(&str, SinkKind)] = &[
    (
        r"\bos\.system\s*\(|\bos\.popen\s*\(|\bsubprocess\.[A-Za-z_]+\s*\([^)]*shell\s*=\s*True|\bcommands\.getoutput\s*\(",
        SinkKind::Shell,
    ),
    (
        r"\bsubprocess\.[A-Za-z_]+\s*\(|\bos\.exec[a-z]*\s*\(|\bos\.spawn[a-z]*\s*\(|\basyncio\.create_subprocess_[a-z]+\s*\(",
        SinkKind::Spawn,
    ),
    (
        r"(?:^|[^.\w])(?:eval|exec|compile|__import__)\s*\(|\bimportlib\.import_module\s*\(|\bpickle\.loads?\s*\(",
        SinkKind::Eval,
    ),
    (
        r"(?:^|[^.\w])open\s*\(|\bPath\s*\(|\bos\.(?:remove|unlink|rmdir|rename|makedirs|mkdir|listdir|walk|chmod|stat)\s*\(|\bshutil\.[a-z_]+\s*\(|\.(?:read_text|write_text|read_bytes|write_bytes|unlink|rmdir|mkdir|iterdir|glob)\s*\(",
        SinkKind::Fs,
    ),
    (
        r"\.(?:execute|executemany|executescript|query|raw|run)\s*\(",
        SinkKind::Sql,
    ),
    (
        r"\brequests\.[a-z]+\s*\(|\bhttpx\.[A-Za-z]+\s*\(|\burlopen\s*\(|\burllib\.request\.[a-z]+\s*\(|\baiohttp\.[A-Za-z]+\s*\(|\bsocket\.[a-z_]+\s*\(",
        SinkKind::Network,
    ),
];

fn word_in(text: &str, word: &str) -> bool {
    let escaped = regex::escape(word);
    Regex::new(&format!(
        r"(?:^|[^A-Za-z0-9_$.]){escaped}(?:[^A-Za-z0-9_$]|$)|\.{escaped}\b"
    ))
    .map(|r| r.is_match(text))
    .unwrap_or(false)
}

/// Follow assignments: every name assigned from an expression mentioning a tainted name becomes
/// tainted, remembering which parameter it came from.
fn propagate(body: &str, params: &[String]) -> Vec<(String, String)> {
    let mut tainted: Vec<(String, String)> =
        params.iter().map(|p| (p.clone(), p.clone())).collect();
    for _ in 0..3 {
        let mut added = false;
        for c in re(r"(?m)(?:^|[;{\n]\s*)(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::\s*[^=\n]+)?=\s*([^=;\n][^;\n]*)").captures_iter(body) {
            let name = c[1].to_string();
            let expr = &c[2];
            if tainted.iter().any(|(n, _)| n == &name) {
                continue;
            }
            if let Some((_, origin)) = tainted.iter().find(|(t, _)| word_in(expr, t)) {
                let origin = origin.clone();
                tainted.push((name, origin));
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    tainted
}

fn flows_in(h: &Handler, file: &str, js: bool) -> Vec<Flow> {
    let mut out = Vec::new();
    let tainted = propagate(&h.body, &h.params);
    if tainted.is_empty() {
        return out;
    }
    let sinks = if js { JS_SINKS } else { PY_SINKS };
    let mut seen_calls: BTreeSet<usize> = BTreeSet::new();
    for (pat, kind) in sinks {
        for m in re(pat).find_iter(&h.body) {
            // Argument text of the call; one finding per call site even if several patterns match it.
            let Some(open) = h.body[m.start()..].find('(').map(|i| m.start() + i) else {
                continue;
            };
            if !seen_calls.insert(open) {
                continue;
            }
            let Some(args_text) = balanced(&h.body, open) else {
                continue;
            };
            if let Some((_, origin)) = tainted.iter().find(|(t, _)| word_in(args_text, t)) {
                let sink = m.as_str().trim().trim_end_matches('(').trim().to_string();
                let kind_s = format!("{kind:?}").to_ascii_lowercase();
                if !out
                    .iter()
                    .any(|f: &Flow| f.tool == h.tool && f.sink == sink && f.param == *origin)
                {
                    out.push(Flow {
                        tool: h.tool.clone(),
                        file: file.to_string(),
                        param: origin.clone(),
                        sink,
                        kind: kind_s,
                    });
                }
            }
        }
    }
    out
}

fn source_files(root: &Path, out: &mut Vec<std::path::PathBuf>, depth: usize) {
    if depth > 6 || out.len() > 1500 {
        return;
    }
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if p.is_dir() {
            if matches!(
                name.as_str(),
                "node_modules"
                    | ".git"
                    | ".venv"
                    | "venv"
                    | "__pycache__"
                    | "test"
                    | "tests"
                    | "__tests__"
                    | "docs"
                    | "examples"
                    | ".next"
                    | "coverage"
            ) {
                continue;
            }
            source_files(&p, out, depth + 1);
        } else if re(r"\.(js|mjs|cjs|ts|mts|py)$").is_match(&name)
            && !name.ends_with(".d.ts")
            && !name.contains(".test.")
            && !name.contains(".spec.")
        {
            out.push(p);
        }
    }
}

/// Analyze the code at `root`. Prefers source over compiled output when both exist.
pub fn analyze(root: &Path) -> Vec<Flow> {
    let scan_root = if root.is_file() {
        root.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root.to_path_buf())
    } else {
        root.to_path_buf()
    };
    let mut files = Vec::new();
    source_files(&scan_root, &mut files, 0);
    if files.is_empty() && root.is_file() {
        files.push(root.to_path_buf());
    }
    // If TypeScript sources exist, skip their compiled .js twins.
    let has_ts = files.iter().any(|f| {
        f.extension()
            .map(|e| e == "ts" || e == "mts")
            .unwrap_or(false)
    });
    let mut flows = Vec::new();
    for f in files {
        let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
        if has_ts && matches!(ext, "js" | "mjs" | "cjs") {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&f) else {
            continue;
        };
        if meta.len() > 2 * 1024 * 1024 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        let rel = f
            .strip_prefix(&scan_root)
            .unwrap_or(&f)
            .display()
            .to_string();
        let js = ext != "py";
        let handlers = if js {
            js_handlers(&text, &rel)
        } else {
            py_handlers(&text, &rel)
        };
        for h in handlers {
            flows.extend(flows_in(&h, &rel, js));
        }
    }
    flows
}

/// Findings from flows.
pub fn findings(s: &Server, flows: &[Flow], out: &mut Vec<Finding>) {
    let src: Option<Source> = Some(s.source.clone());
    let mut by_kind: std::collections::BTreeMap<&str, Vec<&Flow>> = Default::default();
    for f in flows {
        by_kind.entry(f.kind.as_str()).or_default().push(f);
    }
    for (kind, fl) in by_kind {
        let (rule, sev): (&'static str, Severity) = match kind {
            "shell" => ("tool-arg-shell", Severity::Fail),
            "eval" => ("tool-arg-eval", Severity::Fail),
            "spawn" => ("tool-arg-exec", Severity::Warn),
            "sql" => ("tool-arg-sql", Severity::Info),
            "fs" => ("tool-arg-fs", Severity::Info),
            _ => ("tool-arg-network", Severity::Info),
        };
        let mut shown: Vec<String> = fl
            .iter()
            .take(6)
            .map(|f| format!("{}: `{}` → {} ({})", f.tool, f.param, f.sink, f.file))
            .collect();
        if fl.len() > 6 {
            shown.push(format!("and {} more", fl.len() - 6));
        }
        let msg = match kind {
            "shell" => format!("a tool argument is interpolated into a shell command string; whatever influences the model can run commands. {}", shown.join("; ")),
            "eval" => format!("a tool argument reaches code evaluation. {}", shown.join("; ")),
            "spawn" => format!("a tool argument is passed to a spawned process. {}", shown.join("; ")),
            "sql" => format!("a tool argument reaches a database query. {}", shown.join("; ")),
            "fs" => format!("a tool argument selects a filesystem path. {}", shown.join("; ")),
            _ => format!("a tool argument selects a network destination. {}", shown.join("; ")),
        };
        out.push(Finding {
            rule,
            severity: sev,
            kind: "server",
            subject: s.name.clone(),
            message: msg,
            source: src.clone(),
            allowed_by: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_high_level() {
        let src = r#"
const server = new McpServer({ name: "x" });
server.tool("run", { cmd: z.string() }, async ({ cmd }) => {
  const full = `ls ${cmd}`;
  const out = execSync(full);
  return { content: [{ type: "text", text: out.toString() }] };
});
server.registerTool("read", { inputSchema: { path: z.string() } }, async (args) => {
  const data = await fs.readFile(args.path, "utf8");
  return { content: [] };
});
server.tool("safe", {}, async () => { execSync("ls"); return {}; });
server.registerTool("nested", { inputSchema: { p: z.string() } }, async ({ p }) => {
  const items = [1, 2].map((n) => n + 1);
  const valid = await validatePath(p);
  const data = await fs.readFile(valid, "utf8");
  return { content: [] };
});
"#;
        let hs = js_handlers(src, "index.ts");
        assert_eq!(hs.len(), 4);
        assert_eq!(hs[0].tool, "run");
        assert!(hs[0].params.contains(&"cmd".to_string()));
        let flows: Vec<Flow> = hs
            .iter()
            .flat_map(|h| flows_in(h, "index.ts", true))
            .collect();
        assert!(
            flows
                .iter()
                .any(|f| f.tool == "run" && f.kind == "shell" && f.param == "cmd"),
            "{flows:?}"
        );
        assert!(
            flows
                .iter()
                .any(|f| f.tool == "read" && f.kind == "fs" && f.param == "args"),
            "{flows:?}"
        );
        assert!(!flows.iter().any(|f| f.tool == "safe"), "{flows:?}");
        assert!(
            flows
                .iter()
                .any(|f| f.tool == "nested" && f.kind == "fs" && f.param == "p"),
            "{flows:?}"
        );
    }

    #[test]
    fn js_named_handler() {
        let src = r#"
async function readTextFileHandler({ path, head }) {
  const valid = await validatePath(path);
  return { content: [{ type: "text", text: await fs.readFile(valid, "utf8") }] };
}
const runHandler = async ({ cmd }) => {
  return execSync(`run ${cmd}`).toString();
};
server.registerTool("read_text_file", { description: "Read", inputSchema: S.shape }, readTextFileHandler);
server.registerTool("run", { description: "Run" }, runHandler);
"#;
        let hs = js_handlers(src, "index.js");
        assert_eq!(
            hs.len(),
            2,
            "{:?}",
            hs.iter().map(|h| (&h.tool, &h.params)).collect::<Vec<_>>()
        );
        let flows: Vec<Flow> = hs
            .iter()
            .flat_map(|h| flows_in(h, "index.js", true))
            .collect();
        assert!(
            flows
                .iter()
                .any(|f| f.tool == "read_text_file" && f.kind == "fs" && f.param == "path"),
            "{flows:?}"
        );
        assert!(
            flows
                .iter()
                .any(|f| f.tool == "run" && f.kind == "shell" && f.param == "cmd"),
            "{flows:?}"
        );
    }

    #[test]
    fn js_low_level() {
        let src = r#"
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  switch (name) {
    case "exec": {
      const { command } = args;
      const result = spawnSync("sh", ["-c", command]);
      return { content: [] };
    }
  }
});
"#;
        let hs = js_handlers(src, "index.ts");
        assert_eq!(hs.len(), 1);
        let flows = flows_in(&hs[0], "index.ts", true);
        assert!(
            flows
                .iter()
                .any(|f| f.kind == "spawn" && f.param == "command"),
            "{flows:?}"
        );
    }

    #[test]
    fn python_fastmcp() {
        let src = r#"
mcp = FastMCP("demo")

@mcp.tool()
def shell(command: str) -> str:
    """Run it."""
    return subprocess.check_output(command, shell=True).decode()

@mcp.tool(name="read")
async def read_file(path: str, ctx: Context) -> str:
    p = Path(path)
    return p.read_text()

@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b
"#;
        let hs = py_handlers(src, "server.py");
        assert_eq!(
            hs.len(),
            3,
            "{:?}",
            hs.iter().map(|h| &h.tool).collect::<Vec<_>>()
        );
        let flows: Vec<Flow> = hs
            .iter()
            .flat_map(|h| flows_in(h, "server.py", false))
            .collect();
        assert!(
            flows
                .iter()
                .any(|f| f.tool == "shell" && f.kind == "shell" && f.param == "command"),
            "{flows:?}"
        );
        assert!(
            flows
                .iter()
                .any(|f| f.tool == "read_file" && f.kind == "fs"),
            "{flows:?}"
        );
        assert!(!flows.iter().any(|f| f.tool == "add"), "{flows:?}");
    }

    #[test]
    fn python_low_level() {
        let src = r#"
@server.call_tool()
async def handle(name: str, arguments: dict) -> list:
    if name == "query":
        sql = arguments.get("sql")
        cur.execute(sql)
    return []
"#;
        let hs = py_handlers(src, "server.py");
        assert_eq!(hs.len(), 1);
        let flows = flows_in(&hs[0], "server.py", false);
        assert!(
            flows.iter().any(|f| f.kind == "sql" && f.param == "sql"),
            "{flows:?}"
        );
    }

    #[test]
    fn balanced_regions() {
        assert_eq!(balanced("f(a, (b), 'c)')", 1), Some("(a, (b), 'c)')"));
        assert_eq!(balanced("{ x: { y } } tail", 0), Some("{ x: { y } }"));
        assert_eq!(balanced("(unterminated", 0), None);
    }
}
