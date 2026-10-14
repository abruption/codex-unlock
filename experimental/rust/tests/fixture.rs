use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn real_cross_process_fixture_protocol_and_cleanup() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = std::env::var_os("CODEX_UNLOCK_LAB_SCRATCH_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let root = scratch.join(format!(
        "codex-unlock-lab-test-{}-{stamp}",
        std::process::id()
    ));
    #[cfg(unix)]
    let mut builder = fs::DirBuilder::new();
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&root).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_codex-unlock-lab"))
        .arg("self-test")
        .arg("--scratch-root")
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = String::from_utf8(output.stdout).unwrap();
    for field in [
        "\"crossProcessContention\":true",
        "\"releaseObserved\":true",
        "\"safeToUnlock\":false",
        "\"contentsUnchanged\":true",
        "\"missingGuard\":\"unknown\"",
        "\"busyGuard\":\"unknown\"",
    ] {
        assert!(json.contains(field), "{json}");
    }
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    fs::remove_dir(root).unwrap();
}

#[test]
fn capabilities_explicitly_excludes_production_safety_claims() {
    let output = Command::new(env!("CARGO_BIN_EXE_codex-unlock-lab"))
        .arg("capabilities")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "{\"experimentalSchema\":\"codex-unlock-lab/v1\",\"command\":\"capabilities\",\"fixtureOnly\":true,\"safeToUnlock\":false,\"ownerAttribution\":false,\"productionSupport\":false}\n"
    );
}

#[test]
fn refuses_missing_or_invalid_scratch_arguments() {
    for args in [
        vec!["self-test"],
        vec!["self-test", "--scratch-root"],
        vec!["self-test", "--scratch-root", ""],
        vec!["self-test", "--home", "."],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_codex-unlock-lab"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn rejects_production_operations() {
    for command in ["inspect", "unlock", "list", "probe"] {
        let output = Command::new(env!("CARGO_BIN_EXE_codex-unlock-lab"))
            .args([command, "--codex-home", "not-a-real-home"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
