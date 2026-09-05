//! Start each server the way the agent host would, ask it for its tools, stop it.

use crate::model::{Probe, Server, Tool, Transport};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const PROTOCOLS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

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
        tools: Vec::new(),
        stderr: String::new(),
        millis: 0,
    };
    let r = match s.transport {
        Transport::Stdio => probe_stdio(s, timeout, &mut p),
        Transport::Http => probe_http(s, timeout, &mut p),
        Transport::Sse => Err("legacy SSE transport is not probed; switch the server to streamable http if it supports it".to_string()),
        Transport::Unknown => Err("no command and no url".to_string()),
    };
    match r {
        Ok(()) => p.ok = true,
        Err(e) => p.error = Some(e),
    }
    p.millis = start.elapsed().as_millis();
    p
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
        let mut r = BufReader::new(stdout);
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
        send(
            &mut stdin,
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )?;
        let mut cursor: Option<String> = None;
        loop {
            let id = next_id;
            next_id += 1;
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            send(
                &mut stdin,
                &json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": params}),
            )?;
            let resp = wait_for(&rx, id, deadline)?;
            if let Some(e) = resp.get("error") {
                return Err(format!("tools/list failed: {e}"));
            }
            p.tools.extend(tools_from(&resp["result"], &s.name));
            cursor = resp["result"]
                .get("nextCursor")
                .and_then(|c| c.as_str())
                .map(String::from);
            if cursor.is_none() || p.tools.len() > 5000 {
                break;
            }
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
                let text = resp.into_string().map_err(|e| e.to_string())?;
                let text = if ct.contains("text/event-stream") {
                    sse_data(&text)
                } else {
                    text
                };
                Ok((status, sid, text))
            }
            Err(ureq::Error::Status(code, resp)) => {
                let text = resp.into_string().unwrap_or_default();
                Err(match code {
                    401 | 403 => format!(
                        "HTTP {code}: authentication rejected{}",
                        if s.headers.is_empty() {
                            " (no Authorization header configured)"
                        } else {
                            ""
                        }
                    ),
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
    let proto = p.protocol_version.clone().or(proto_used.map(String::from));
    let _ = post(
        &agent,
        &session,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        proto.as_deref(),
    );
    let mut cursor: Option<String> = None;
    let mut id = 2;
    loop {
        let params = match &cursor {
            Some(c) => json!({"cursor": c}),
            None => json!({}),
        };
        let (_, _, text) = post(
            &agent,
            &session,
            &json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": params}),
            proto.as_deref(),
        )?;
        id += 1;
        let v: Value = serde_json::from_str(text.trim())
            .map_err(|e| format!("tools/list returned non-JSON: {e}"))?;
        if let Some(e) = v.get("error") {
            return Err(format!("tools/list failed: {e}"));
        }
        p.tools.extend(tools_from(&v["result"], &s.name));
        cursor = v["result"]
            .get("nextCursor")
            .and_then(|c| c.as_str())
            .map(String::from);
        if cursor.is_none() || p.tools.len() > 5000 {
            break;
        }
    }
    Ok(())
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
    fn sse() {
        assert_eq!(sse_data("event: message\ndata: {\"a\":1}\n\n"), "{\"a\":1}");
        assert_eq!(sse_data("data: {\"a\":\ndata: 1}\n"), "{\"a\":1}");
    }
}
