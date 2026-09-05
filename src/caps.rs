//! Source-level capabilities of a local server: what the code can do, read
//! from the files the launch command points at. Regex-level and honest about
//! it; frostjs and frostpy do the taint analysis.

use crate::model::{Server, Source};
use crate::rules::{Finding, Severity};
use regex::Regex;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct Capabilities {
    pub root: Option<String>,
    pub files: usize,
    pub exec: BTreeSet<String>,
    pub eval: BTreeSet<String>,
    pub fs_write: BTreeSet<String>,
    pub network: BTreeSet<String>,
    pub hosts: BTreeSet<String>,
    pub env: BTreeSet<String>,
    pub credential_paths: BTreeSet<String>,
}

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

/// Where the server's code lives, if it is on this machine.
pub fn locate(s: &Server) -> Option<PathBuf> {
    let cmd = s.command.as_deref()?;
    let base = Path::new(cmd).file_name()?.to_string_lossy().into_owned();
    let home = std::env::var("HOME").unwrap_or_default();
    let expand = |a: &str| crate::probe::expand_env(a).replacen('~', &home, 1);
    // Scripts named directly: node server.js, python3 x.py, ./bin/x
    for a in &s.args {
        let p = PathBuf::from(expand(a));
        if p.extension()
            .map(|e| matches!(e.to_str().unwrap_or(""), "js" | "mjs" | "cjs" | "ts" | "py"))
            .unwrap_or(false)
            && p.exists()
        {
            return Some(p);
        }
    }
    // uv --directory <dir> run ..., or cwd-style args
    if let Some(i) = s
        .args
        .iter()
        .position(|a| a == "--directory" || a == "--project")
    {
        if let Some(d) = s.args.get(i + 1) {
            let p = PathBuf::from(expand(d));
            if p.is_dir() {
                return Some(p);
            }
        }
    }
    // The command itself is a local script or a directory's binary.
    let cp = PathBuf::from(expand(cmd));
    if cp.exists()
        && cp
            .extension()
            .map(|e| {
                matches!(
                    e.to_str().unwrap_or(""),
                    "js" | "mjs" | "cjs" | "ts" | "py" | "sh"
                )
            })
            .unwrap_or(false)
    {
        return Some(cp);
    }
    // npx packages that have run before live in the npm cache.
    if matches!(base.as_str(), "npx" | "bunx") {
        let mut pkg = None;
        let mut i = 0;
        while i < s.args.len() {
            let a = s.args[i].as_str();
            if a == "-p" || a == "--package" {
                pkg = s.args.get(i + 1).map(String::as_str);
                break;
            }
            if !a.starts_with('-') {
                pkg = Some(a);
                break;
            }
            i += 1;
        }
        let pkg = pkg?;
        let name = strip_version(pkg);
        if let Some(found) = find_in_npx_cache(&home, &name) {
            return Some(found);
        }
    }
    None
}

fn strip_version(pkg: &str) -> String {
    let body = pkg.strip_prefix('@').unwrap_or(pkg);
    match body.rfind('@') {
        Some(i) => format!(
            "{}{}",
            if pkg.starts_with('@') { "@" } else { "" },
            &body[..i]
        ),
        None => pkg.to_string(),
    }
}

fn find_in_npx_cache(home: &str, pkg: &str) -> Option<PathBuf> {
    let cache = Path::new(home).join(".npm").join("_npx");
    let rd = std::fs::read_dir(&cache).ok()?;
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for e in rd.flatten() {
        let p = e.path().join("node_modules").join(pkg);
        if p.join("package.json").exists() {
            let t = std::fs::metadata(&p)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            if best.as_ref().map(|(bt, _)| t > *bt).unwrap_or(true) {
                best = Some((t, p));
            }
        }
    }
    best.map(|(_, p)| p)
}

fn source_files(root: &Path, out: &mut Vec<PathBuf>, depth: usize) {
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
        } else if re(r"\.(js|mjs|cjs|ts|mts|cts|py)$").is_match(&name)
            && !name.ends_with(".d.ts")
            && !name.contains(".test.")
            && !name.contains(".spec.")
            && !name.ends_with(".map")
        {
            out.push(p);
        }
    }
}

/// Extract capabilities from the code at `root`.
pub fn extract(root: &Path) -> Capabilities {
    let mut caps = Capabilities {
        root: Some(crate::model::shorten_home(root)),
        ..Default::default()
    };
    let mut files = Vec::new();
    // A script inside a package (package.json or pyproject.toml beside it): scan the package, since its
    // imports live there. A loose script: scan only that file, so neighbours are not blamed for each other.
    let parent = root
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.to_path_buf());
    let in_package = root.is_file()
        && (parent.join("package.json").exists()
            || parent.join("pyproject.toml").exists()
            || parent.join("setup.py").exists());
    let scan_root = if root.is_dir() {
        root.to_path_buf()
    } else {
        parent.clone()
    };
    if root.is_file() && !in_package {
        files.push(root.to_path_buf());
    } else {
        source_files(&scan_root, &mut files, 0);
    }
    caps.files = files.len();
    for f in files {
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
        let js = !f.extension().map(|e| e == "py").unwrap_or(false);
        let mark = |set: &mut BTreeSet<String>, what: &str| {
            set.insert(format!("{what} ({rel})"));
        };
        if js {
            for m in re(r"\b(child_process|execSync|execFileSync|spawnSync|\bexec\(|\bspawn\(|execFile\(|Deno\.run|Deno\.Command|Bun\.spawn|\$`)").find_iter(&text) {
                mark(&mut caps.exec, m.as_str().trim_end_matches('(').trim_end_matches('`'));
            }
            for m in
                re(r"\b(eval\(|new\s+Function\(|vm\.runIn[A-Za-z]*\(|vm\.Script)").find_iter(&text)
            {
                mark(&mut caps.eval, m.as_str().trim_end_matches('('));
            }
            for m in re(r"\b(writeFile(Sync)?|appendFile(Sync)?|unlink(Sync)?|rm(Sync)?|rmdir(Sync)?|rename(Sync)?|mkdir(Sync)?|createWriteStream|truncate(Sync)?|chmod(Sync)?|copyFile(Sync)?)\(").find_iter(&text) {
                mark(&mut caps.fs_write, m.as_str().trim_end_matches('('));
            }
            for m in re(r"\b(fetch\(|axios|node-fetch|undici|got\(|https?\.request|https?\.get\(|new\s+WebSocket|net\.connect|net\.createConnection|dgram|tls\.connect|XMLHttpRequest)").find_iter(&text) {
                mark(&mut caps.network, m.as_str().trim_end_matches('('));
            }
            for c in re(r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)|process\.env\[['\x22]([A-Za-z_][A-Za-z0-9_]*)['\x22]\]").captures_iter(&text) {
                let name = c.get(1).or_else(|| c.get(2)).map(|m| m.as_str()).unwrap_or("");
                if !name.is_empty() {
                    caps.env.insert(name.to_string());
                }
            }
            if re(r"process\.env(?:[^.\[A-Za-z0-9_]|$)").is_match(&text) {
                caps.env.insert("* (whole environment)".into());
            }
        } else {
            for m in re(r"\b(subprocess\.[a-zA-Z_]+|os\.system|os\.popen|os\.exec[a-z]*|os\.spawn[a-z]*|pty\.spawn|asyncio\.create_subprocess_[a-z]+|commands\.getoutput)").find_iter(&text) {
                mark(&mut caps.exec, m.as_str());
            }
            for m in re(r"(?m)(^|[^.\w])(eval\(|exec\(|compile\(|__import__\(|importlib\.import_module|pickle\.loads?\(|marshal\.loads?\()").find_iter(&text) {
                mark(&mut caps.eval, m.as_str().trim_start_matches(|c: char| !c.is_alphabetic()).trim_end_matches('('));
            }
            for m in re(r"\b(open\([^)]*,\s*['\x22][wa]|shutil\.(rmtree|move|copy[a-z]*)|os\.(remove|unlink|rmdir|rename|makedirs|mkdir|chmod)|\.write_text\(|\.write_bytes\(|\.unlink\(|\.rmdir\(|\.rename\(|\.touch\()").find_iter(&text) {
                mark(&mut caps.fs_write, m.as_str().trim_end_matches('(').trim_end_matches(['\'', '"', 'w', 'a', ',', ' ']));
            }
            for m in re(r"\b(requests\.[a-z]+|httpx\.[A-Za-z]+|urllib\.request|urllib3|aiohttp|http\.client|socket\.(socket|create_connection)|websockets?\.|smtplib|ftplib|paramiko)").find_iter(&text) {
                mark(&mut caps.network, m.as_str().trim_end_matches('.'));
            }
            for c in re(r"os\.environ(?:\.get)?\(?\[?['\x22]([A-Za-z_][A-Za-z0-9_]*)['\x22]|os\.getenv\(\s*['\x22]([A-Za-z_][A-Za-z0-9_]*)['\x22]").captures_iter(&text) {
                let name = c.get(1).or_else(|| c.get(2)).map(|m| m.as_str()).unwrap_or("");
                if !name.is_empty() {
                    caps.env.insert(name.to_string());
                }
            }
            if re(r"os\.environ(?:[^.\[A-Za-z0-9_]|$)|dict\(os\.environ\)|os\.environ\.copy\(\)|os\.environ\.items\(\)").is_match(&text) {
                caps.env.insert("* (whole environment)".into());
            }
        }
        for c in
            re(r"(?i)https?://([a-z0-9][a-z0-9.\-]*\.[a-z]{2,}(?::[0-9]+)?)").captures_iter(&text)
        {
            let h = c.get(1).unwrap().as_str().to_ascii_lowercase();
            if !is_doc_host(&h) {
                caps.hosts.insert(h);
            }
        }
        for m in re(r"(?i)(\.ssh/|\.aws/credentials|\.netrc|\.npmrc|\.pypirc|\.docker/config\.json|\.kube/config|\.gnupg|\.git-credentials|Library/Keychains|/etc/shadow|\.claude\.json|\.config/gh/hosts\.yml)").find_iter(&text) {
            caps.credential_paths.insert(format!("{} ({rel})", m.as_str()));
        }
    }
    caps
}

fn is_doc_host(h: &str) -> bool {
    h.ends_with("w3.org")
        || h.ends_with("schema.org")
        || h.ends_with("schemas.org")
        || h.contains("example.")
        || h.ends_with("json-schema.org")
        || h == "localhost"
        || h.starts_with("127.")
        || h.ends_with(".local")
        || h.ends_with("opensource.org")
        || h.ends_with("spdx.org")
        || h.ends_with("mozilla.org")
        || h.ends_with("apache.org") && h.starts_with("www")
        || h.ends_with("purl.org")
        || h.ends_with("xmlns.com")
        || h.ends_with("ietf.org")
        || h.ends_with("iana.org")
        || h.ends_with("unicode.org")
        || h.ends_with("microsoft.com") && h.starts_with("aka")
        || h.ends_with("typescriptlang.org")
        || h.ends_with("nodejs.org")
        || h.ends_with("npmjs.com")
        || h.ends_with("python.org")
        || h.ends_with("pypi.org")
        || h.ends_with("readthedocs.io")
        || h.ends_with("modelcontextprotocol.io")
        || h.ends_with("openxmlformats.org")
}

fn list(set: &BTreeSet<String>, max: usize) -> String {
    let v: Vec<&str> = set.iter().take(max).map(String::as_str).collect();
    if set.len() > max {
        format!("{} and {} more", v.join(", "), set.len() - max)
    } else {
        v.join(", ")
    }
}

/// Turn capabilities into findings for a server.
pub fn findings(s: &Server, caps: &Capabilities, out: &mut Vec<Finding>) {
    let src: Option<Source> = Some(s.source.clone());
    let mk = |rule: &'static str, sev: Severity, msg: String| Finding {
        rule,
        severity: sev,
        kind: "server",
        subject: s.name.clone(),
        message: msg,
        source: src.clone(),
        allowed_by: None,
    };
    let root = caps.root.clone().unwrap_or_default();
    if !caps.exec.is_empty() {
        out.push(mk(
            "server-exec",
            Severity::Warn,
            format!(
                "source at {root} spawns processes: {}.",
                list(&caps.exec, 6)
            ),
        ));
    }
    if !caps.eval.is_empty() {
        out.push(mk(
            "server-eval",
            Severity::Warn,
            format!(
                "source at {root} evaluates code at runtime: {}.",
                list(&caps.eval, 6)
            ),
        ));
    }
    if !caps.credential_paths.is_empty() {
        out.push(mk(
            "server-credential-access",
            Severity::Fail,
            format!(
                "source at {root} references credential stores: {}.",
                list(&caps.credential_paths, 6)
            ),
        ));
    }
    if !caps.network.is_empty() || !caps.hosts.is_empty() {
        let hosts = if caps.hosts.is_empty() {
            "no fixed host in source".to_string()
        } else {
            list(&caps.hosts, 10)
        };
        out.push(mk(
            "server-network",
            Severity::Info,
            format!(
                "source at {root} uses the network ({}); hosts: {hosts}.",
                list(&caps.network, 4)
            ),
        ));
    }
    if !caps.env.is_empty() {
        let whole = caps.env.contains("* (whole environment)");
        out.push(mk("server-env", if whole { Severity::Warn } else { Severity::Info }, format!("source at {root} reads env: {}.{}", list(&caps.env, 12), if whole { " Reading the whole environment means every token in your shell is visible to it." } else { "" })));
    }
    if !caps.fs_write.is_empty() {
        out.push(mk(
            "server-fs-write",
            Severity::Info,
            format!(
                "source at {root} writes files: {}.",
                list(&caps.fs_write, 6)
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_and_py_extraction() {
        let dir = std::env::temp_dir().join(format!("frostagent-caps-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.js"), "const { execSync } = require('child_process');\nfetch('https://api.github.com/x');\nconst t = process.env.GITHUB_TOKEN; const all = process.env;\nfs.writeFileSync('a', 'b'); eval('1');\nconst k = fs.readFileSync(home + '/.ssh/id_rsa');\n").unwrap();
        std::fs::write(dir.join("tool.py"), "import subprocess, os, requests\nsubprocess.run(['ls'])\nrequests.get('https://api.example.com')\nk = os.environ['API_KEY']\nv = os.getenv(\"OTHER\")\nopen('x', 'w').write('y')\nexec(code)\n").unwrap();
        let c = extract(&dir);
        assert_eq!(c.files, 2);
        assert!(c
            .exec
            .iter()
            .any(|x| x.starts_with("child_process") || x.starts_with("execSync")));
        assert!(c.exec.iter().any(|x| x.starts_with("subprocess.run")));
        assert!(c.eval.iter().any(|x| x.starts_with("eval")));
        assert!(c.eval.iter().any(|x| x.starts_with("exec")));
        assert!(c.fs_write.iter().any(|x| x.starts_with("writeFileSync")));
        assert!(c.fs_write.iter().any(|x| x.starts_with("open")));
        assert!(c.hosts.contains("api.github.com"));
        assert!(!c.hosts.contains("api.example.com"));
        assert!(
            c.env.contains("GITHUB_TOKEN")
                && c.env.contains("API_KEY")
                && c.env.contains("OTHER")
                && c.env.contains("* (whole environment)")
        );
        assert!(c.credential_paths.iter().any(|x| x.starts_with(".ssh/")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn version_strip() {
        assert_eq!(strip_version("@scope/pkg@1.2.3"), "@scope/pkg");
        assert_eq!(strip_version("pkg@latest"), "pkg");
        assert_eq!(strip_version("pkg"), "pkg");
    }
}
