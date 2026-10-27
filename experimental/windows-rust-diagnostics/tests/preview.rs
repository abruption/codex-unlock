use serde_json::Value;
use std::process::Command;

#[test]
#[cfg(any(windows, unix))]
fn invalid_encoding_preserves_explicit_json_format() {
    #[cfg(windows)]
    let invalid = {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&[0xd800])
    };
    #[cfg(unix)]
    let invalid = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(vec![0xff])
    };
    for json_first in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_codex-unlock-windows"));
        if json_first {
            command.arg("--json").arg(&invalid);
        } else {
            command.arg(&invalid).arg("--json");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(64));
        assert!(output.stderr.is_empty());
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["reason"], "argument_encoding_invalid");
        assert_eq!(value["error"], "usage");
        assert_eq!(value["safeToUnlock"], false);
    }
}

fn preview(args: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_codex-unlock-windows"))
        .args(args)
        .output()
        .unwrap();
    assert!(output.stderr.is_empty());
    (
        output.status.code().unwrap(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

fn assert_release_envelope(value: &Value) {
    let version = env!("CARGO_PKG_VERSION");
    let (schema, channel, prerelease) = match version {
        "0.0.0" | "0.5.0-alpha.1" => ("codex-unlock-windows-preview", None, true),
        "0.5.0-rc.1" => ("codex-unlock-windows", Some("rc"), true),
        "0.5.0" => ("codex-unlock-windows", Some("stable"), false),
        _ => panic!("unreviewed release version"),
    };
    assert_eq!(value["schema"], schema);
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["version"], version);
    assert_eq!(value["preview"], prerelease);
    assert_eq!(value["experimental"], prerelease);
    assert_eq!(value.get("releaseChannel").and_then(Value::as_str), channel);
    assert_eq!(value["safeToUnlock"], false);
    assert_eq!(value["recoveryAvailable"], false);
}

#[test]
fn real_context_capabilities_and_refusal_agree() {
    let (code, cap) = preview(&["capabilities", "--json"]);
    assert_eq!(code, 0);
    assert_release_envelope(&cap);
    assert_eq!(cap["safeToUnlock"], false);
    assert_eq!(cap["recoveryAvailable"], false);
    if cap["diagnosticsAvailable"] == true {
        assert!(cfg!(windows));
        assert!(cfg!(target_arch = "x86_64"));
        assert_eq!(cap["context"]["state"], "observed");
        assert_eq!(cap["context"]["integrityRid"], 8192);
        assert_eq!(cap["context"]["elevated"], false);
        assert_eq!(cap["context"]["appContainer"], false);
        // Do not emulate a forbidden token or alter the real native fixture tests.
        eprintln!(
            "Real context permits preview; refusal assertions require a real non-Medium/elevated/AppContainer context."
        );
        return;
    }
    let (code, refused) = preview(&[
        "inspect",
        "--home",
        "C:\\preview-nonexistent-home",
        "--thread",
        "12345678-1234-1234-1234-123456789abc",
        "--pid",
        "4294967295",
        "--json",
    ]);
    assert_eq!(code, 2);
    assert_release_envelope(&refused);
    assert_eq!(refused["reason"], cap["reason"]);
    assert_eq!(refused["lock"]["state"], "unknown");
    assert!(refused.get("diagnostic").is_none());
    assert_eq!(refused["safeToUnlock"], false);
    assert_eq!(
        refused["requestedPidEvidence"],
        "requested_pid_only_not_holder"
    );
}

#[test]
fn human_help_version_and_json_usage_are_separate() {
    for command in ["--help", "help", "--version", "capabilities"] {
        let output = Command::new(env!("CARGO_BIN_EXE_codex-unlock-windows"))
            .arg(command)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(serde_json::from_slice::<Value>(&output.stdout).is_err());
        if command == "--version" {
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                format!("codex-unlock-windows {}\n", env!("CARGO_PKG_VERSION"))
            );
        }
    }
    let (code, value) = preview(&["unlock", "--json"]);
    assert_eq!(code, 64);
    assert_eq!(value["error"], "usage");
    assert_eq!(value["safeToUnlock"], false);
}

#[test]
fn closed_stdout_pipe_preserves_exit_code() {
    use std::process::Stdio;
    let mut cases = vec![
        (vec!["capabilities", "--json"], 0),
        (vec!["unlock", "--json"], 64),
    ];
    let (_, cap) = preview(&["capabilities", "--json"]);
    if cap["diagnosticsAvailable"] == false {
        cases.push((
            vec![
                "inspect",
                "--home",
                "C:\\preview-nonexistent-home",
                "--thread",
                "12345678-1234-1234-1234-123456789abc",
                "--json",
            ],
            2,
        ));
    } else {
        eprintln!("Real context permits preview; closed-pipe context-refusal case is unmeasured.");
    }
    for (args, expected) in cases {
        let mut child = Command::new(env!("CARGO_BIN_EXE_codex-unlock-windows"))
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(expected));
        assert!(output.stderr.is_empty());
    }
}
