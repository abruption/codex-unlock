#![cfg(windows)]
//! Run with WINDOWS_DIAGNOSTIC_FIXTURE_PARENT pointing at a fresh private scratch
//! directory. The tests never inspect the user's default Codex home.
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

fn diagnostic_bin() -> std::ffi::OsString {
    std::env::var_os("WINDOWS_DIAGNOSTIC_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_codex-unlock-windows-diagnostic").into())
}
fn fixture_bin() -> std::ffi::OsString {
    std::env::var_os("WINDOWS_FIXTURE_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_codex-unlock-windows-fixture").into())
}

struct Fixture {
    child: Child,
    lines: Receiver<String>,
    home: PathBuf,
    thread: String,
}
impl Fixture {
    fn start(mode: &str) -> Self {
        let parent = std::env::var_os("WINDOWS_DIAGNOSTIC_FIXTURE_PARENT").expect(
            "set WINDOWS_DIAGNOSTIC_FIXTURE_PARENT to an existing private scratch directory",
        );
        let mut child = Command::new(fixture_bin())
            .args(["--mode", mode, "--lifetime-ms", "60000", "--parent"])
            .arg(parent)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start synthetic fixture");
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if tx.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        let ready: Value = serde_json::from_str(
            &lines
                .recv_timeout(Duration::from_secs(10))
                .expect("fixture ready"),
        )
        .unwrap();
        assert_eq!(ready["event"], "ready");
        Self {
            child,
            lines,
            home: PathBuf::from(ready["home"].as_str().unwrap()),
            thread: ready["thread"].as_str().unwrap().into(),
        }
    }
    fn command(&mut self, command: &str) {
        writeln!(self.child.stdin.as_mut().unwrap(), "{command}").unwrap();
        self.child.stdin.as_mut().unwrap().flush().unwrap();
    }
    fn inspect(&self, pid: bool) -> (i32, Value) {
        let mut command = Command::new(diagnostic_bin());
        command
            .arg("inspect")
            .arg("--home")
            .arg(&self.home)
            .arg("--thread")
            .arg(&self.thread);
        if pid {
            command.arg("--pid").arg(self.child.id().to_string());
        }
        let output = command.output().expect("diagnostic process");
        let value: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "invalid JSON {error}: {}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["experimental"], true);
        assert_eq!(value["safeToUnlock"], false);
        (output.status.code().unwrap(), value)
    }
    fn locks(&self) -> PathBuf {
        self.home.join("thread-writer-locks")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // EOF requests ordinary self-exit; no Child::kill fallback.
        self.child.stdin.take();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        eprintln!("fixture exit {status}");
                        if !std::thread::panicking() {
                            panic!("fixture failed to finish normally: {status}");
                        }
                    }
                    return;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(error) => {
                    eprintln!("incomplete fixture {}: {error}", self.child.id());
                    if !std::thread::panicking() {
                        panic!("fixture completion unconfirmed");
                    }
                    return;
                }
            }
        }
        eprintln!(
            "incomplete fixture {}, scratch preserved at {}",
            self.child.id(),
            self.home.display()
        );
        if !std::thread::panicking() {
            panic!("fixture completion unconfirmed; no termination attempted");
        }
    }
}

#[test]
fn real_thread_lock_then_release_and_unchanged_files() {
    let mut fixture = Fixture::start("thread");
    let path = fixture.locks().join(format!("{}.lock", fixture.thread));
    let before = fs::metadata(&path).unwrap();
    let guard_path = fixture.locks().join(".coordination.lock");
    let guard_before = fs::metadata(&guard_path).unwrap();
    let (code, held) = fixture.inspect(true);
    assert_eq!(code, 0, "{held}");
    assert_eq!(held["lock"]["state"], "held");
    let process = &held["observation"]["process"];
    assert_eq!(process["state"], "observed");
    assert_eq!(process["pid"], fixture.child.id());
    assert_eq!(process["sameUser"], true);
    assert_eq!(process["live"], true);
    assert_eq!(process["evidence"], "requested_pid_only_not_holder");
    assert!(
        process["startTime"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    assert_eq!(held["observation"]["holder"], "unproven");
    let after = fs::metadata(&path).unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    let guard_after = fs::metadata(&guard_path).unwrap();
    assert_eq!(guard_before.len(), guard_after.len());
    assert_eq!(
        guard_before.modified().unwrap(),
        guard_after.modified().unwrap()
    );
    fixture.command("release");
    let released: Value =
        serde_json::from_str(&fixture.lines.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
    assert_eq!(released["event"], "released");
    let (code, free) = fixture.inspect(false);
    assert_eq!(code, 0, "{free}");
    assert_eq!(free["lock"]["state"], "free");
    assert!(fs::read(path).unwrap().is_empty());
}

#[test]
fn busy_guard_is_unknown() {
    let fixture = Fixture::start("guard");
    let (code, value) = fixture.inspect(false);
    assert_eq!(code, 2, "{value}");
    assert_eq!(value["lock"]["state"], "unknown");
    assert_eq!(value["lock"]["reason"], "coordination_busy");
}

#[test]
fn missing_native_files_are_not_created() {
    let fixture = Fixture::start("free");
    let guard = fixture.locks().join(".coordination.lock");
    let renamed = fixture.locks().join("guard.saved");
    fs::rename(&guard, &renamed).unwrap();
    let result = fixture.inspect(false);
    let absent = !guard.exists();
    fs::rename(&renamed, &guard).unwrap();
    assert!(absent);
    assert_eq!(result.0, 2, "{}", result.1);
    assert_eq!(result.1["lock"]["state"], "unknown");
    let thread = fixture.locks().join(format!("{}.lock", fixture.thread));
    let renamed = fixture.locks().join("thread.saved");
    fs::rename(&thread, &renamed).unwrap();
    let result = fixture.inspect(false);
    let absent = !thread.exists();
    fs::rename(&renamed, &thread).unwrap();
    assert!(absent);
    assert_eq!(result.0, 2, "{}", result.1);
}

#[test]
fn hardlinked_thread_is_refused() {
    let fixture = Fixture::start("free");
    let thread = fixture.locks().join(format!("{}.lock", fixture.thread));
    let link = fixture.locks().join("extra.link");
    fs::hard_link(&thread, &link).unwrap();
    let result = fixture.inspect(false);
    fs::remove_file(link).unwrap();
    assert_eq!(result.0, 2, "{}", result.1);
    assert_eq!(result.1["lock"]["state"], "unknown");
    assert_eq!(result.1["lock"]["reason"], "unsafe_file_type_or_links");
}

#[test]
fn hardlinked_guard_is_refused() {
    let fixture = Fixture::start("free");
    let guard = fixture.locks().join(".coordination.lock");
    let link = fixture.locks().join("guard.link");
    fs::hard_link(&guard, &link).unwrap();
    let result = fixture.inspect(false);
    fs::remove_file(link).unwrap();
    assert_eq!(result.0, 2, "{}", result.1);
    assert_eq!(result.1["lock"]["reason"], "unsafe_file_type_or_links");
}

#[test]
fn invalid_thread_is_usage_error() {
    let fixture = Fixture::start("free");
    for invalid in [
        "../other",
        "not-a-uuid",
        "",
        "11111111-2222-4333-8444-555555555555/extra",
    ] {
        let result = Command::new(diagnostic_bin())
            .arg("inspect")
            .arg("--home")
            .arg(&fixture.home)
            .arg("--thread")
            .arg(invalid)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(64), "invalid thread {invalid}");
    }
}

#[test]
fn junction_ancestor_is_refused() {
    let fixture = Fixture::start("free");
    let junction = fixture.home.parent().unwrap().join("home-junction");
    // cmd is used only for its unprivileged junction builtin. Reject all shell
    // expansion/metacharacters in the operator-supplied parent before invoking it.
    for path in [&junction, &fixture.home] {
        assert!(
            !path
                .to_string_lossy()
                .chars()
                .any(|c| "\"%&|<>^!\r\n".contains(c)),
            "unsafe cmd path spelling"
        );
    }
    let script = format!(
        "mklink /J \"{}\" \"{}\"",
        junction.display(),
        fixture.home.display()
    );
    let created = Command::new("cmd.exe")
        .args(["/D", "/V:OFF", "/C"])
        .raw_arg(&script)
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "junction creation failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    let result = Command::new(diagnostic_bin())
        .arg("inspect")
        .arg("--home")
        .arg(&junction)
        .arg("--thread")
        .arg(&fixture.thread)
        .output();
    // remove_dir on a junction removes the junction entry, not its target tree.
    fs::remove_dir(&junction).expect("remove only the synthetic junction");
    assert!(fixture.home.is_dir());
    let result = result.unwrap();
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result.status.code(), Some(2), "{value}");
    assert_eq!(value["lock"]["state"], "unknown");
    assert_eq!(value["safeToUnlock"], false);
}

#[test]
fn nonexistent_requested_pid_is_unknown() {
    let fixture = Fixture::start("free");
    let result = Command::new(diagnostic_bin())
        .arg("inspect")
        .arg("--home")
        .arg(&fixture.home)
        .arg("--thread")
        .arg(&fixture.thread)
        .args(["--pid", "4294967295"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result.status.code(), Some(2), "{value}");
    assert_eq!(value["lock"]["state"], "free");
    assert_eq!(value["safeToUnlock"], false);
    assert_eq!(value["observation"]["process"]["state"], "unknown");
    assert_eq!(
        value["observation"]["process"]["reason"],
        "process_open_failed"
    );
}
