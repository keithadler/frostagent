//! Start each server the way the agent host would, ask it for its tools, stop it.

use crate::model::{Probe, Prompt, Resource, Server, Tool, Transport};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const PROTOCOLS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
/// A server that streams more than this during a probe is not answering a list request.
const MAX_STREAM_BYTES: u64 = 64 * 1024 * 1024;
/// Largest single HTTP body accepted.
const MAX_HTTP_BYTES: u64 = 32 * 1024 * 1024;

/// Expand `${VAR}` and `$VAR` from the parent environment, as the hosts do.
pub fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < b.len() {
        if b[i] == '$' && i + 1 < b.len() {
            if b[i + 1] == '{' {
                if let Some(end) = b[i + 2..].iter().position(|c| *c == '}') {
                    let spec: String = b[i + 2..i + 2 + end].iter().collect();
                    let (name, default) = match spec.split_once(":-") {
                        Some((n, d)) => (n.to_string(), Some(d.to_string())),
                        None => (spec.clone(), None),
                    };
                    out.push_str(&std::env::var(&name).ok().or(default).unwrap_or_default());
                    i += 3 + end;
                    continue;
                }
            } else if b[i + 1].is_ascii_alphabetic() || b[i + 1] == '_' {
                let mut j = i + 1;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == '_') {
                    j += 1;
                }
                let name: String = b[i + 1..j].iter().collect();
                out.push_str(&std::env::var(&name).unwrap_or_default());
                i = j;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn tools_from(list: &Value, server: &str) -> Vec<Tool> {
    let mut out = Vec::new();
    if let Some(arr) = list.get("tools").and_then(|t| t.as_array()) {
        for t in arr {
            out.push(Tool {
                server: server.to_string(),
                name: t
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string(),
                description: t
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string(),
                input_schema: t.get("inputSchema").cloned().unwrap_or(Value::Null),
                annotations: t.get("annotations").cloned().unwrap_or(json!({})),
                title: t.get("title").and_then(|d| d.as_str()).map(String::from),
            });
        }
    }
    out
}

fn prompts_from(list: &Value, server: &str) -> Vec<Prompt> {
    list.get("prompts")
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .map(|p| Prompt {
                    server: server.to_string(),
                    name: p
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string(),
                    description: p
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                        .to_string(),
                    arguments: p.get("arguments").cloned().unwrap_or(Value::Null),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn resources_from(list: &Value, server: &str) -> Vec<Resource> {
    let mut out = Vec::new();
    for key in ["resources", "resourceTemplates"] {
        if let Some(a) = list.get(key).and_then(|r| r.as_array()) {
            for r in a {
                out.push(Resource {
                    server: server.to_string(),
                    uri: r
                        .get("uri")
                        .or_else(|| r.get("uriTemplate"))
                        .and_then(|u| u.as_str())
                        .unwrap_or("")
                        .to_string(),
                    name: r
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string(),
                    description: r
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                        .to_string(),
                });
            }
        }
    }
    out
}

/// Which list methods the server says it supports.
fn advertised(result: &Value) -> (bool, bool) {
    let caps = &result["capabilities"];
    (
        caps.get("prompts").is_some(),
        caps.get("resources").is_some(),
    )
}

fn init_request(id: u64, protocol: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "initialize", "params": {
        "protocolVersion": protocol,
        "capabilities": {},
        "clientInfo": {"name": "frostagent", "version": env!("CARGO_PKG_VERSION")}
    }})
}

/// Probe a server, whatever its transport.
pub fn probe(s: &Server, timeout: Duration) -> Probe {
    let start = Instant::now();
    let mut p = Probe {
        server: s.name.clone(),
        ok: false,
        error: None,
        server_info: None,
        protocol_version: None,
        instructions: None,
        tools: Vec::new(),
        prompts: Vec::new(),
        resources: Vec::new(),
        stderr: String::new(),
        side_effects: Vec::new(),
        millis: 0,
    };
    let before = home_snapshot();
    let r = match s.transport {
        Transport::Stdio => probe_stdio(s, timeout, &mut p),
        Transport::Http => probe_http(s, timeout, &mut p),
        Transport::Sse => probe_sse(s, timeout, &mut p),
        Transport::Unknown => Err("no command and no url".to_string()),
    };
    match r {
        Ok(()) => p.ok = true,
        Err(e) => p.error = Some(e),
    }
    if s.transport == Transport::Stdio {
        let after = home_snapshot();
        p.side_effects = after.difference(&before).cloned().collect();
    }
    p.millis = start.elapsed().as_millis();
    p
}

/// Names of the entries directly under the home directory and its common
/// config folders. Cheap, and enough to notice a server that writes a config,
/// cache or telemetry id the moment it starts.
fn home_snapshot() -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) else {
        return out;
    };
    let home = std::path::PathBuf::from(home);
    for (dir, prefix) in [
        (home.clone(), "~/"),
        (home.join(".config"), "~/.config/"),
        (home.join(".cache"), "~/.cache/"),
        (home.join(".local/share"), "~/.local/share/"),
        (
            home.join("Library/Application Support"),
            "~/Library/Application Support/",
        ),
        (home.join("Library/Caches"), "~/Library/Caches/"),
        (home.join("Library/Preferences"), "~/Library/Preferences/"),
        (home.join("Library/LaunchAgents"), "~/Library/LaunchAgents/"),
    ] {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                out.insert(format!("{prefix}{}", e.file_name().to_string_lossy()));
            }
        }
    }
    out
}

fn probe_stdio(s: &Server, timeout: Duration, p: &mut Probe) -> Result<(), String> {
    let cmd = s.command.clone().ok_or("no command")?;
    let mut c = Command::new(expand_env(&cmd));
    c.args(s.args.iter().map(|a| expand_env(a)));
    for (k, v) in &s.env {
        c.env(k, expand_env(v));
    }
    c.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c
        .spawn()
        .map_err(|e| format!("could not start `{}`: {e}", s.command_line()))?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let stderr = child.stderr.take().ok_or("no stderr")?;

    let (tx, rx) = mpsc::channel::<Result<String, String>>();
    std::thread::spawn(move || {
        let mut r = BufReader::new(std::io::Read::take(stdout, MAX_STREAM_BYTES));
        loop {
            let mut line = String::new();
            match r.read_line(&mut line) {
                Ok(0) => {
                    let _ = tx.send(Err("server closed stdout".into()));
                    break;
                }
                Ok(_) => {
                    if tx.send(Ok(line)).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e.to_string()));
                    break;
                }
            }
        }
    });
    let (etx, erx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut r = BufReader::new(stderr);
        let mut line = String::new();
        while let Ok(n) = r.read_line(&mut line) {
            if n == 0 {
                break;
            }
            if etx.send(std::mem::take(&mut line)).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + timeout;
    let mut next_id = 1u64;
    let result = (|| -> Result<(), String> {
        // Initialize, falling back through protocol versions on error.
        let mut init: Option<Value> = None;
        for proto in PROTOCOLS {
            let id = next_id;
            next_id += 1;
            send(&mut stdin, &init_request(id, proto))?;
            let resp = wait_for(&rx, id, deadline)?;
            if resp.get("error").is_none() {
                init = Some(resp);
                break;
            }
            let msg = resp["error"]["message"]
                .as_str()
                .unwrap_or("")
                .to_ascii_lowercase();
            if !msg.contains("protocol") && !msg.contains("version") {
                return Err(format!("initialize failed: {}", resp["error"]));
            }
        }
        let init = init.ok_or("server rejected every protocol version we know")?;
        let result = &init["result"];
        p.protocol_version = result
            .get("protocolVersion")
            .and_then(|v| v.as_str())
            .map(String::from);
        p.server_info = result.get("serverInfo").cloned();
        p.instructions = result
            .get("instructions")
            .and_then(|v| v.as_str())
            .map(String::from);
        let (has_prompts, has_resources) = advertised(result);
        send(
            &mut stdin,
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )?;
        let mut list = |method: &str, p: &mut Probe| -> Result<(), String> {
            let mut cursor: Option<String> = None;
            let mut pages = 0;
            loop {
                let id = next_id;
                next_id += 1;
                let params = match &cursor {
                    Some(c) => json!({"cursor": c}),
                    None => json!({}),
                };
                send(
                    &mut stdin,
                    &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
                )?;
                let resp = wait_for(&rx, id, deadline)?;
                if let Some(e) = resp.get("error") {
                    if method == "tools/list" {
                        return Err(format!("tools/list failed: {e}"));
                    }
                    return Ok(()); // optional lists may be refused
                }
                match method {
                    "tools/list" => p.tools.extend(tools_from(&resp["result"], &s.name)),
                    "prompts/list" => p.prompts.extend(prompts_from(&resp["result"], &s.name)),
                    _ => p.resources.extend(resources_from(&resp["result"], &s.name)),
                }
                cursor = resp["result"]
                    .get("nextCursor")
                    .and_then(|c| c.as_str())
                    .map(String::from);
                pages += 1;
                if cursor.is_none() || pages > 50 {
                    break;
                }
            }
            Ok(())
        };
        list("tools/list", p)?;
        if has_prompts {
            list("prompts/list", p)?;
        }
        if has_resources {
            list("resources/list", p)?;
            list("resources/templates/list", p)?;
        }
        Ok(())
    })();
    let _ = child.kill();
    let _ = child.wait();
    let mut err_text = String::new();
    while let Ok(l) = erx.try_recv() {
        err_text.push_str(&l);
        if err_text.len() > 4000 {
            break;
        }
    }
    p.stderr = err_text.chars().take(4000).collect();
    result.map_err(|e| {
        if p.stderr.trim().is_empty() {
            e
        } else {
            format!(
                "{e}; stderr: {}",
                p.stderr.trim().lines().last().unwrap_or("")
            )
        }
    })
}

fn send(stdin: &mut std::process::ChildStdin, v: &Value) -> Result<(), String> {
    let mut s = v.to_string();
    s.push('\n');
    stdin
        .write_all(s.as_bytes())
        .map_err(|e| format!("write failed: {e}"))?;
    stdin.flush().map_err(|e| e.to_string())
}

fn wait_for(
    rx: &mpsc::Receiver<Result<String, String>>,
    id: u64,
    deadline: Instant,
) -> Result<Value, String> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("timed out waiting for the server".into());
        }
        match rx.recv_timeout(deadline - now) {
            Ok(Ok(line)) => {
                let t = line.trim();
                if t.is_empty() {
                    continue;
                }
                // Servers sometimes log to stdout; skip anything that is not our response.
                let Ok(v) = serde_json::from_str::<Value>(t) else {
                    continue;
                };
                if v.get("id").and_then(|i| i.as_u64()) == Some(id) {
                    return Ok(v);
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err("timed out waiting for the server".into())
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err("server exited".into()),
        }
    }
}

/// Streamable HTTP: POST JSON-RPC, answers come back as JSON or as an SSE stream.
fn probe_http(s: &Server, timeout: Duration, p: &mut Probe) -> Result<(), String> {
    let url = s.url.clone().ok_or("no url")?;
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let mut session: Option<String> = None;
    let post = |agent: &ureq::Agent,
                session: &Option<String>,
                body: &Value,
                proto: Option<&str>|
     -> Result<(u16, Option<String>, String), String> {
        let mut req = agent
            .post(&url)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json, text/event-stream");
        for (k, v) in &s.headers {
            req = req.set(k, &expand_env(v));
        }
        if let Some(tok) = auth_override(&s.name) {
            req = req.set("Authorization", &tok);
        }
        if let Some(sid) = session {
            req = req.set("Mcp-Session-Id", sid);
        }
        if let Some(pv) = proto {
            req = req.set("MCP-Protocol-Version", pv);
        }
        match req.send_string(&body.to_string()) {
            Ok(resp) => {
                let sid = resp
                    .header("Mcp-Session-Id")
                    .or_else(|| resp.header("mcp-session-id"))
                    .map(String::from);
                let status = resp.status();
                let ct = resp.header("Content-Type").unwrap_or("").to_string();
                let mut text = String::new();
                std::io::Read::read_to_string(
                    &mut std::io::Read::take(resp.into_reader(), MAX_HTTP_BYTES),
                    &mut text,
                )
                .map_err(|e| e.to_string())?;
                let text = if ct.contains("text/event-stream") {
                    sse_data(&text)
                } else {
                    text
                };
                Ok((status, sid, text))
            }
            Err(ureq::Error::Status(code, resp)) => {
                let challenge = resp
                    .header("WWW-Authenticate")
                    .or_else(|| resp.header("www-authenticate"))
                    .map(String::from);
                let text = resp.into_string().unwrap_or_default();
                Err(match code {
                    401 | 403 => {
                        let mut msg = format!(
                            "HTTP {code}: authentication rejected{}",
                            if s.headers.is_empty() && auth_override(&s.name).is_none() {
                                " (no Authorization header configured)"
                            } else {
                                ""
                            }
                        );
                        if let Some(meta) = oauth_metadata(agent, &url, challenge.as_deref()) {
                            msg.push_str(&format!("; {meta}"));
                        }
                        msg
                    }
                    _ => format!(
                        "HTTP {code}: {}",
                        text.chars().take(200).collect::<String>()
                    ),
                })
            }
            Err(e) => Err(format!("request failed: {e}")),
        }
    };
    let mut init: Option<Value> = None;
    let mut proto_used = None;
    for proto in PROTOCOLS {
        let (_, sid, text) = post(&agent, &session, &init_request(1, proto), None)?;
        if sid.is_some() {
            session = sid;
        }
        let v: Value = serde_json::from_str(text.trim()).map_err(|e| {
            format!(
                "initialize returned something that is not JSON-RPC: {e}: {}",
                text.chars().take(120).collect::<String>()
            )
        })?;
        if v.get("error").is_none() {
            init = Some(v);
            proto_used = Some(*proto);
            break;
        }
    }
    let init = init.ok_or("server rejected every protocol version we know")?;
    let result = &init["result"];
    p.protocol_version = result
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .map(String::from);
    p.server_info = result.get("serverInfo").cloned();
    p.instructions = result
        .get("instructions")
        .and_then(|v| v.as_str())
        .map(String::from);
    let (has_prompts, has_resources) = advertised(result);
    let proto = p.protocol_version.clone().or(proto_used.map(String::from));
    let _ = post(
        &agent,
        &session,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        proto.as_deref(),
    );
    let mut id = 2;
    let mut list = |method: &str, p: &mut Probe| -> Result<(), String> {
        let mut cursor: Option<String> = None;
        let mut pages = 0;
        loop {
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            let (_, _, text) = post(
                &agent,
                &session,
                &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
                proto.as_deref(),
            )?;
            id += 1;
            let v: Value = serde_json::from_str(text.trim())
                .map_err(|e| format!("{method} returned non-JSON: {e}"))?;
            if let Some(e) = v.get("error") {
                if method == "tools/list" {
                    return Err(format!("tools/list failed: {e}"));
                }
                return Ok(());
            }
            match method {
                "tools/list" => p.tools.extend(tools_from(&v["result"], &s.name)),
                "prompts/list" => p.prompts.extend(prompts_from(&v["result"], &s.name)),
                _ => p.resources.extend(resources_from(&v["result"], &s.name)),
            }
            cursor = v["result"]
                .get("nextCursor")
                .and_then(|c| c.as_str())
                .map(String::from);
            pages += 1;
            if cursor.is_none() || pages > 50 {
                break;
            }
        }
        Ok(())
    };
    list("tools/list", p)?;
    if has_prompts {
        list("prompts/list", p)?;
    }
    if has_resources {
        list("resources/list", p)?;
        list("resources/templates/list", p)?;
    }
    Ok(())
}

/// Legacy HTTP+SSE transport (2024-11-05): GET the SSE stream, receive an
/// `endpoint` event naming where to POST, POST JSON-RPC there, read responses
/// off the stream.
fn probe_sse(s: &Server, timeout: Duration, p: &mut Probe) -> Result<(), String> {
    use std::io::Read;
    let url = s.url.clone().ok_or("no url")?;
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .build();
    let mut req = agent.get(&url).set("Accept", "text/event-stream");
    for (k, v) in &s.headers {
        req = req.set(k, &expand_env(v));
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => {
            return Err(match code {
                401 | 403 => format!(
                    "HTTP {code}: authentication rejected{}",
                    if s.headers.is_empty() {
                        " (no Authorization header configured)"
                    } else {
                        ""
                    }
                ),
                _ => format!("HTTP {code} opening the SSE stream"),
            })
        }
        Err(e) => return Err(format!("could not open SSE stream: {e}")),
    };
    let reader = resp.into_reader();
    // Stream events to a channel from a thread; the body never ends on its own.
    let (tx, rx) = mpsc::channel::<(String, String)>();
    std::thread::spawn(move || {
        let mut r = std::io::BufReader::new(reader);
        let mut event = String::new();
        let mut data = String::new();
        let mut line = String::new();
        loop {
            line.clear();
            let mut byte = [0u8; 1];
            // read_line on a chunked stream
            let mut got = false;
            loop {
                match r.read(&mut byte) {
                    Ok(0) => break,
                    Ok(_) => {
                        got = true;
                        if byte[0] == b'\n' {
                            break;
                        }
                        line.push(byte[0] as char);
                    }
                    Err(_) => break,
                }
            }
            if !got {
                break;
            }
            let l = line.trim_end_matches('\r');
            if let Some(e) = l.strip_prefix("event:") {
                event = e.trim().to_string();
            } else if let Some(d) = l.strip_prefix("data:") {
                data.push_str(d.trim_start());
            } else if l.is_empty() {
                if !data.is_empty()
                    && tx
                        .send((std::mem::take(&mut event), std::mem::take(&mut data)))
                        .is_err()
                {
                    break;
                }
                event.clear();
            }
        }
    });
    let deadline = Instant::now() + timeout;
    let endpoint = loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("timed out waiting for the SSE endpoint event".into());
        }
        match rx.recv_timeout(deadline - now) {
            Ok((ev, d)) if ev == "endpoint" => break d,
            Ok(_) => continue,
            Err(_) => return Err("SSE stream closed before sending an endpoint".into()),
        }
    };
    // Endpoint may be relative to the SSE url.
    let post_url = if endpoint.starts_with("http") {
        endpoint
    } else {
        let base = url.split('?').next().unwrap_or(&url);
        let origin_end = base
            .find("://")
            .map(|i| i + 3)
            .and_then(|i| base[i..].find('/').map(|j| i + j))
            .unwrap_or(base.len());
        if endpoint.starts_with('/') {
            format!("{}{}", &base[..origin_end], endpoint)
        } else {
            format!("{}/{}", base.trim_end_matches('/'), endpoint)
        }
    };
    let post = |body: &Value| -> Result<(), String> {
        let mut req = agent
            .post(&post_url)
            .set("Content-Type", "application/json");
        for (k, v) in &s.headers {
            req = req.set(k, &expand_env(v));
        }
        if let Some(tok) = auth_override(&s.name) {
            req = req.set("Authorization", &tok);
        }
        match req.send_string(&body.to_string()) {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(code, _)) => Err(format!("HTTP {code} posting to {post_url}")),
            Err(e) => Err(format!("post failed: {e}")),
        }
    };
    let wait = |rx: &mpsc::Receiver<(String, String)>, id: u64| -> Result<Value, String> {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err("timed out waiting for the server".into());
            }
            match rx.recv_timeout(deadline - now) {
                Ok((_, d)) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&d) {
                        if v.get("id").and_then(|i| i.as_u64()) == Some(id) {
                            return Ok(v);
                        }
                    }
                }
                Err(_) => return Err("SSE stream closed".into()),
            }
        }
    };
    let mut id = 1u64;
    let mut init = None;
    for proto in PROTOCOLS {
        post(&init_request(id, proto))?;
        let v = wait(&rx, id)?;
        id += 1;
        if v.get("error").is_none() {
            init = Some(v);
            break;
        }
    }
    let init = init.ok_or("server rejected every protocol version we know")?;
    let result = &init["result"];
    p.protocol_version = result
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .map(String::from);
    p.server_info = result.get("serverInfo").cloned();
    p.instructions = result
        .get("instructions")
        .and_then(|v| v.as_str())
        .map(String::from);
    let (has_prompts, has_resources) = advertised(result);
    post(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
    let mut list = |method: &str, p: &mut Probe| -> Result<(), String> {
        let mut cursor: Option<String> = None;
        let mut pages = 0;
        loop {
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            post(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
            let v = wait(&rx, id)?;
            id += 1;
            if let Some(e) = v.get("error") {
                if method == "tools/list" {
                    return Err(format!("tools/list failed: {e}"));
                }
                return Ok(());
            }
            match method {
                "tools/list" => p.tools.extend(tools_from(&v["result"], &s.name)),
                "prompts/list" => p.prompts.extend(prompts_from(&v["result"], &s.name)),
                _ => p.resources.extend(resources_from(&v["result"], &s.name)),
            }
            cursor = v["result"]
                .get("nextCursor")
                .and_then(|c| c.as_str())
                .map(String::from);
            pages += 1;
            if cursor.is_none() || pages > 50 {
                break;
            }
        }
        Ok(())
    };
    list("tools/list", p)?;
    if has_prompts {
        list("prompts/list", p)?;
    }
    if has_resources {
        list("resources/list", p)?;
    }
    Ok(())
}

/// `FROSTAGENT_AUTH_<SERVER_NAME>`: a full Authorization header value to probe a
/// server the user has already signed in to elsewhere.
pub fn auth_override(server: &str) -> Option<String> {
    let key = format!(
        "FROSTAGENT_AUTH_{}",
        server
            .to_ascii_uppercase()
            .replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    );
    std::env::var(&key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|v| {
            if v.contains(' ') {
                v
            } else {
                format!("Bearer {v}")
            }
        })
}

/// Describe an OAuth-protected server from its 401 challenge and, when
/// present, its protected-resource metadata document. Read-only GETs; no sign-in.
fn oauth_metadata(agent: &ureq::Agent, url: &str, challenge: Option<&str>) -> Option<String> {
    let mut parts = Vec::new();
    let mut metadata_url = None;
    if let Some(ch) = challenge {
        parts.push(format!(
            "challenge `{}`",
            ch.chars().take(120).collect::<String>()
        ));
        if let Some(c) = regex::Regex::new(r#"resource_metadata="?([^",\s]+)"#)
            .ok()?
            .captures(ch)
        {
            metadata_url = Some(c[1].to_string());
        }
        if let Some(c) = regex::Regex::new(r#"scope="([^"]+)""#).ok()?.captures(ch) {
            parts.push(format!("scope `{}`", &c[1]));
        }
    }
    if metadata_url.is_none() {
        // RFC 9728 well-known location for the resource.
        if let Some(origin) = url
            .split('/')
            .take(3)
            .collect::<Vec<_>>()
            .get(2)
            .map(|h| format!("{}//{h}", url.split('/').next().unwrap_or("https:")))
        {
            metadata_url = Some(format!("{origin}/.well-known/oauth-protected-resource"));
        }
    }
    if let Some(mu) = metadata_url {
        if let Ok(resp) = agent.get(&mu).call() {
            if let Ok(v) = resp.into_json::<serde_json::Value>() {
                if let Some(servers) = v.get("authorization_servers").and_then(|a| a.as_array()) {
                    let list: Vec<&str> = servers.iter().filter_map(|x| x.as_str()).collect();
                    if !list.is_empty() {
                        parts.push(format!(
                            "authorization server{} {}",
                            if list.len() == 1 { "" } else { "s" },
                            list.join(", ")
                        ));
                    }
                }
                if let Some(scopes) = v.get("scopes_supported").and_then(|a| a.as_array()) {
                    let list: Vec<&str> = scopes.iter().filter_map(|x| x.as_str()).collect();
                    if !list.is_empty() {
                        parts.push(format!("scopes {}", list.join(" ")));
                    }
                }
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("OAuth sign-in required: {}. Export FROSTAGENT_AUTH_<NAME> with a token from a client you have signed in with to inspect its tools.", parts.join("; ")))
    }
}

/// Concatenate the `data:` payloads of an SSE body; return the last complete JSON message.
fn sse_data(body: &str) -> String {
    let mut last = String::new();
    let mut cur = String::new();
    for line in body.lines() {
        if let Some(d) = line.strip_prefix("data:") {
            cur.push_str(d.trim_start());
        } else if line.trim().is_empty() && !cur.is_empty() {
            last = std::mem::take(&mut cur);
        }
    }
    if !cur.is_empty() {
        last = cur;
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_expansion() {
        std::env::set_var("FROST_T", "v");
        assert_eq!(
            expand_env("a ${FROST_T} $FROST_T ${NOPE_X:-d} $"),
            "a v v d $"
        );
    }

    #[test]
    fn helpers_never_panic_on_garbage() {
        let mut seed: u64 = 0x9E3779B97F4A7C15;
        for _ in 0..3000 {
            let mut t = String::new();
            for _ in 0..(seed % 24) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                t.push(match seed % 10 {
                    0 => '$',
                    1 => '{',
                    2 => '}',
                    3 => ':',
                    4 => '-',
                    5 => '\n',
                    6 => 'é',
                    _ => 'a',
                });
            }
            let _ = expand_env(&t);
            let _ = sse_data(&format!("data:{t}\n\n{t}"));
            let _ = tools_from(&serde_json::json!({"tools": [{"name": t}, 5, null]}), "s");
            let _ = prompts_from(&serde_json::json!({"prompts": [{"name": t}, 5]}), "s");
            let _ = resources_from(
                &serde_json::json!({"resources": [{"uri": t}], "resourceTemplates": [7]}),
                "s",
            );
        }
    }

    #[test]
    fn parsers_never_panic() {
        let mut seed: u64 = 0xD1B54A32D192ED03;
        for _ in 0..3000 {
            let mut t = String::new();
            for _ in 0..(seed % 60) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                t.push(match seed % 14 {
                    0 => '$',
                    1 => '{',
                    2 => '}',
                    3 => ':',
                    4 => '-',
                    5 => '\n',
                    6 => 'd',
                    7 => 'a',
                    8 => ' ',
                    9 => '\u{1F600}',
                    _ => (b'a' + (seed % 26) as u8) as char,
                });
            }
            let _ = expand_env(&t);
            let _ = sse_data(&t);
            let _ = sse_data(&format!("data:{t}\n\n"));
        }
    }

    #[test]
    fn sse() {
        assert_eq!(sse_data("event: message\ndata: {\"a\":1}\n\n"), "{\"a\":1}");
        assert_eq!(sse_data("data: {\"a\":\ndata: 1}\n"), "{\"a\":1}");
    }
}
