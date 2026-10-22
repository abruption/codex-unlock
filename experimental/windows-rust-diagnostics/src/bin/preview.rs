//! User-facing diagnostic-only preview. The research observer remains separate.
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    process::ExitCode,
};

#[cfg(windows)]
#[path = "../windows.rs"]
mod windows;

const HELP: &str = "codex-unlock-windows — diagnostic-only Windows preview\n\nUsage:\n  codex-unlock-windows --help\n  codex-unlock-windows --version\n  codex-unlock-windows capabilities [--json]\n  codex-unlock-windows inspect --home ABS --thread UUID [--pid POSITIVE] [--json]\n\nUse an absolute local Windows drive path and a normal non-admin terminal.\nOnly NTFS and a non-elevated Medium-integrity, non-AppContainer context are supported.\nInspection briefly takes existing coordination/thread locks. It creates no native files.\n--pid observes only the requested process; it does not identify the lock owner.\nNo unlock, list, signal, deletion, or recovery command is available.\n";

#[derive(Debug, PartialEq)]
enum Request {
    Help,
    Version,
    Capabilities,
    Inspect {
        home: String,
        thread: String,
        pid: Option<u32>,
    },
}

fn parse(args: &[String]) -> Result<(Request, bool), &'static str> {
    match args.first().map(String::as_str) {
        Some("--help" | "help") if args.len() == 1 => return Ok((Request::Help, false)),
        Some("--version") if args.len() == 1 => return Ok((Request::Version, false)),
        Some("capabilities" | "inspect") => {}
        _ => return Err("command_required"),
    }
    let inspect = args[0] == "inspect";
    let (mut home, mut thread, mut pid, mut json) = (None, None, None, false);
    let mut i = 1;
    while i < args.len() {
        let option = args[i].as_str();
        if option == "--json" && !json {
            json = true;
            i += 1;
            continue;
        }
        if !inspect || !["--home", "--thread", "--pid"].contains(&option) {
            return Err("unknown_or_duplicate_option");
        }
        let value = args
            .get(i + 1)
            .filter(|v| !v.is_empty() && !v.starts_with("--"))
            .ok_or("option_value_required")?;
        match option {
            "--home" if home.is_none() => home = Some(value.clone()),
            "--thread" if thread.is_none() => thread = Some(value.clone()),
            "--pid" if pid.is_none() => {
                if !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("invalid_pid");
                }
                pid = Some(
                    value
                        .parse::<u32>()
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or("invalid_pid")?,
                );
            }
            _ => return Err("unknown_or_duplicate_option"),
        }
        i += 2;
    }
    if !inspect {
        return Ok((Request::Capabilities, json));
    }
    let home = home.ok_or("home_required")?;
    let b = home.as_bytes();
    if b.len() < 4 || !b[0].is_ascii_alphabetic() || &b[1..3] != b":\\" {
        return Err("absolute_home_argument_required");
    }
    let thread = thread.ok_or("thread_required")?;
    if thread.len() != 36
        || !thread.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err("uuid_thread_id_required");
    }
    Ok((Request::Inspect { home, thread, pid }, json))
}

fn context() -> Value {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        windows::preview_context()
    }
    #[cfg(all(windows, not(target_arch = "x86_64")))]
    {
        json!({"state":"unknown", "reason":"windows_x64_required"})
    }
    #[cfg(not(windows))]
    {
        json!({"state":"unknown", "reason":"windows_required"})
    }
}

/// Missing or unrecognized data never grants access to the observation callback.
fn context_decision(c: &Value) -> Result<(), &'static str> {
    if c["reason"] == "windows_x64_required" {
        return Err("windows_x64_required");
    }
    if c["reason"] == "windows_required" {
        return Err("windows_required");
    }
    if c["state"] != "observed"
        || !c["integrityRid"].is_u64()
        || !c["elevated"].is_boolean()
        || !c["appContainer"].is_boolean()
    {
        return Err("current_token_unknown");
    }
    if c["appContainer"] != false {
        return Err("app_container_refused");
    }
    if c["elevated"] != false {
        return Err("elevated_context_refused");
    }
    if c["integrityRid"] != 8192 {
        return Err("medium_integrity_required");
    }
    Ok(())
}

fn gated_observation(c: &Value, observe: impl FnOnce() -> Value) -> Result<Value, &'static str> {
    context_decision(c)?;
    Ok(observe())
}

fn envelope() -> Value {
    json!({"schema":"codex-unlock-windows-preview", "schemaVersion":1,
        "preview":true, "experimental":true, "version":env!("CARGO_PKG_VERSION"),
        "platform":std::env::consts::OS, "architecture":std::env::consts::ARCH,
        "safeToUnlock":false, "recoveryAvailable":false})
}

fn execute(request: Request) -> (u8, Value) {
    let mut out = envelope();
    let c = context();
    let decision = context_decision(&c);
    out["context"] = c.clone();
    out["diagnosticsAvailable"] = json!(decision.is_ok());
    match request {
        Request::Capabilities => {
            out["command"] = json!("capabilities");
            out["commands"] = json!(["capabilities", "inspect"]);
            out["supportedFilesystems"] = json!(["NTFS"]);
            out["holderAttribution"] = json!("unproven");
            out["reason"] = json!(decision.err().unwrap_or("diagnostic_preview_available"));
            (0, out)
        }
        Request::Inspect { home, thread, pid } => {
            out["command"] = json!("inspect");
            out["requestedPid"] = json!(pid);
            out["requestedPidEvidence"] = json!("requested_pid_only_not_holder");
            let result = gated_observation(&c, || {
                #[cfg(windows)]
                {
                    windows::inspect(&home, &thread, pid)
                }
                #[cfg(not(windows))]
                {
                    let _ = (home, thread, pid);
                    unreachable!("Windows context required")
                }
            });
            match result {
                Err(reason) => {
                    out["reason"] = json!(reason);
                    out["lock"] = json!({"state":"unknown", "reason":reason, "win32":null});
                    (2, out)
                }
                Ok(result) => finish_observation(out, result),
            }
        }
        Request::Help | Request::Version => unreachable!("handled before execution"),
    }
}

/// Pure presentation mapping. This function grants no permission to inspect.
fn finish_observation(mut out: Value, result: Value) -> (u8, Value) {
    let process = &result["observation"]["process"];
    let process_unknown =
        !process.is_null() && (process["state"] != "observed" || process["sameUser"] != true);
    let unknown = result["lock"]["state"] == "unknown" || process_unknown;
    out["reason"] = json!(if result["lock"]["state"] == "unknown" {
        result["lock"]["reason"]
            .as_str()
            .unwrap_or("observation_unknown")
    } else if process_unknown {
        "requested_process_unverified"
    } else {
        "diagnostic_observation_only"
    });
    out["lock"] = result["lock"].clone();
    out["diagnostic"] = result;
    (if unknown { 2 } else { 0 }, out)
}

fn guidance(reason: &str) -> &'static str {
    match reason {
        "requested_process_unverified" => {
            "The requested PID could not be verified as a live same-user process. Check that PID and its owner; it is not evidence of lock ownership."
        }
        "final_path_not_exact" => {
            "Use the exact existing path spelling and case. This preview does not normalize alternate path spellings."
        }
        "windows_required" => "Run this preview on Windows in a normal non-admin terminal.",
        "windows_x64_required" => {
            "Use the Windows x64 preview executable in a normal non-admin terminal; this build architecture is unsupported."
        }
        "current_token_unknown"
        | "app_container_refused"
        | "elevated_context_refused"
        | "medium_integrity_required" => {
            "Use a normal non-admin terminal with Medium integrity outside AppContainer; no files or requested process were inspected."
        }
        "diagnostic_preview_available" => {
            "Use inspect with an explicit absolute local home and thread UUID."
        }
        "diagnostic_observation_only" => {
            "This observation does not establish lock ownership or authorize recovery."
        }
        _ => {
            "Check the explicit home/thread, file ownership, local NTFS filesystem and coordination availability. No recovery is authorized."
        }
    }
}

fn escaped(s: &str) -> String {
    s.chars().flat_map(char::escape_default).collect()
}
fn human(value: &Value) -> String {
    let reason = value["reason"].as_str().unwrap_or("observation_unknown");
    let mut text = format!(
        "Windows diagnostic preview — recovery unavailable\nReason: {}\n",
        escaped(reason)
    );
    if value["error"] == "usage" {
        text.push_str("Run codex-unlock-windows --help for usage.\n");
        return text;
    }
    if let Some(state) = value["lock"]["state"].as_str() {
        text.push_str(&format!("Lock: {} (owner unproven)\n", escaped(state)));
    }
    if let Some(pid) = value["requestedPid"].as_u64() {
        text.push_str(&format!(
            "Requested PID: {pid} (observation only; not lock-owner evidence)\n"
        ));
    }
    text.push_str(guidance(reason));
    text.push('\n');
    text
}

fn emit_output(mut writer: impl Write, output: &str, code: u8) -> u8 {
    match writer
        .write_all(output.as_bytes())
        .and_then(|()| writer.flush())
    {
        Ok(()) => code,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => code,
        Err(_) => 74,
    }
}

fn main() -> ExitCode {
    let raw_args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let json_requested = raw_args.iter().any(|a| a == "--json");
    let args: Result<Vec<String>, _> = raw_args.into_iter().map(|a| a.into_string()).collect();
    let parsed = args
        .as_ref()
        .map_err(|_| "argument_encoding_invalid")
        .and_then(|a| parse(a));
    let (code, output) = match parsed {
        Ok((Request::Help, _)) => (0, HELP.to_string()),
        Ok((Request::Version, _)) => (
            0,
            format!("codex-unlock-windows {}\n", env!("CARGO_PKG_VERSION")),
        ),
        Ok((request, json)) => {
            let (code, value) = execute(request);
            (
                code,
                if json {
                    format!("{value}\n")
                } else {
                    human(&value)
                },
            )
        }
        Err(reason) => {
            let mut value = envelope();
            value["error"] = json!("usage");
            value["reason"] = json!(reason);
            (
                64,
                if json_requested {
                    format!("{value}\n")
                } else {
                    human(&value)
                },
            )
        }
    };
    ExitCode::from(emit_output(io::stdout().lock(), &output, code))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_errors_preserve_diagnostic_status_only_for_broken_pipe() {
        struct FailingWriter {
            kind: io::ErrorKind,
            fail_flush: bool,
        }
        impl Write for FailingWriter {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                if self.fail_flush {
                    Ok(data.len())
                } else {
                    Err(io::Error::from(self.kind))
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::from(self.kind))
            }
        }
        for code in [0, 2, 64] {
            assert_eq!(emit_output(Vec::new(), "output", code), code);
            for fail_flush in [false, true] {
                assert_eq!(
                    emit_output(
                        FailingWriter {
                            kind: io::ErrorKind::BrokenPipe,
                            fail_flush
                        },
                        "output",
                        code
                    ),
                    code
                );
                assert_eq!(
                    emit_output(
                        FailingWriter {
                            kind: io::ErrorKind::PermissionDenied,
                            fail_flush
                        },
                        "output",
                        code
                    ),
                    74
                );
            }
        }
    }
    #[test]
    fn allowed_observation_mapping_contract() {
        // Synthetic presentation cases only. No context probe or native access occurs.
        let home = "C:\\private\\home";
        let thread = "11111111-2222-4333-8444-555555555555";
        let snapshot = |leaf: &str| {
            json!({"volume":"1234567890abcdef",
            "file_id":"0123456789abcdef0123456789abcdef",
            "final_path":format!("\\\\?\\{home}\\thread-writer-locks\\{leaf}"),
            "links":1,"directory":false,"size":"0","write_time":"133000000000000000","change_time":"133000000000000000"})
        };
        let mut cases = Vec::new();
        for (name, state, process, expected) in [
            ("held_no_pid", "held", Value::Null, 0),
            ("free_no_pid", "free", Value::Null, 0),
            ("unknown_lock", "unknown", Value::Null, 2),
            (
                "unknown_process",
                "held",
                json!({"state":"unknown","reason":"process_open_failed","win32":5}),
                2,
            ),
            ("different_user", "free", json!({"sameUser":false}), 2),
            ("same_user", "held", json!({"sameUser":true}), 0),
        ] {
            let pid = if process.is_null() {
                Value::Null
            } else {
                json!(1234)
            };
            let process = if process.get("sameUser").is_some() {
                json!({"state":"observed","evidence":"requested_pid_only_not_holder","pid":1234,"live":true,
                    "startTime":"133000000000000000","image":"C:\\codex.exe","sameUser":process["sameUser"],"sessionId":1,"integrityRid":8192})
            } else {
                process
            };
            let lock = if state == "unknown" {
                json!({"state":state,"reason":"open_existing_failed","win32":2})
            } else {
                json!({"state":state,"reason":null,"win32":null})
            };
            let observation = if state == "unknown" {
                json!({"state":state,"reason":"open_existing_failed","win32":2,"process":process})
            } else {
                json!({"state":state,"coordination":"acquired_and_released","range":"offset_0_length_18446744073709551615",
                    "filesystem":"NTFS","fileOwnerSelf":true,"holder":"unproven","guard":snapshot(".coordination.lock"),
                    "thread":snapshot(&format!("{thread}.lock")),"process":process})
            };
            let diagnostic = json!({"schemaVersion":1,"experimental":true,"safeToUnlock":false,"platform":"windows",
                "requestedPid":pid,"lock":lock,"observation":observation});
            let mut out = envelope();
            out["platform"] = json!("windows");
            out["architecture"] = json!("x86_64");
            out["context"] = json!({"state":"observed","integrityRid":8192,"elevated":false,"appContainer":false});
            out["diagnosticsAvailable"] = json!(true);
            out["command"] = json!("inspect");
            out["requestedPid"] = pid.clone();
            out["requestedPidEvidence"] = json!("requested_pid_only_not_holder");
            let (code, result) = finish_observation(out, diagnostic.clone());
            assert_eq!(code, expected, "{name}");
            assert_eq!(result["diagnostic"], diagnostic);
            assert_eq!(result["lock"], diagnostic["lock"]);
            assert_eq!(result["safeToUnlock"], false);
            assert_eq!(result["recoveryAvailable"], false);
            assert_eq!(
                result["reason"],
                if state == "unknown" {
                    "open_existing_failed"
                } else if expected == 2 {
                    "requested_process_unverified"
                } else {
                    "diagnostic_observation_only"
                }
            );
            cases.push(json!({"name":name,"exitCode":code,"result":result,
                "request":{"command":"inspect","home":home,"thread":thread,"pid":pid,
                    "expectedVersion":env!("CARGO_PKG_VERSION")}}));
        }
        if let Some(directory) = std::env::var_os("PREVIEW_TEST_GOLDEN_DIR") {
            let directory = std::path::PathBuf::from(directory);
            assert!(
                directory.is_absolute() && directory.is_dir(),
                "golden directory must be explicit, absolute and existing"
            );
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join("preview-mapping-golden.json"))
                .unwrap();
            serde_json::to_writer_pretty(&mut file, &cases).unwrap();
            file.write_all(b"\n").unwrap();
        }
    }
    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn only_exact_medium_non_elevated_non_container_reaches_observer() {
        let valid =
            json!({"state":"observed","integrityRid":8192,"elevated":false,"appContainer":false});
        let mut refusals = vec![
            json!({}),
            json!({"state":"unknown"}),
            json!({"reason":"windows_required"}),
            json!({"reason":"windows_x64_required"}),
        ];
        for rid in [0, 4096, 8193, 8448, 12288, 16384, 20480] {
            let mut c = valid.clone();
            c["integrityRid"] = json!(rid);
            refusals.push(c);
        }
        for field in ["state", "integrityRid", "elevated", "appContainer"] {
            for value in [Value::Null, json!("unknown")] {
                let mut c = valid.clone();
                c[field] = value;
                refusals.push(c);
            }
        }
        for field in ["elevated", "appContainer"] {
            let mut c = valid.clone();
            c[field] = json!(true);
            refusals.push(c);
        }
        for c in refusals {
            let mut called = false;
            assert!(
                gated_observation(&c, || {
                    called = true;
                    json!({})
                })
                .is_err()
            );
            assert!(
                !called,
                "native files / requested PID callback reached: {c}"
            );
        }
        let result = json!({"unchanged":"research observation"});
        assert_eq!(
            gated_observation(&valid, || result.clone()).unwrap(),
            result
        );
    }
    #[test]
    fn parser_is_closed() {
        let base = args(&[
            "inspect",
            "--home",
            "C:\\home",
            "--thread",
            "12345678-1234-1234-1234-123456789abc",
        ]);
        assert!(parse(&base).is_ok());
        for suffix in [
            &["--json", "--json"][..],
            &["--force"],
            &["--pid"],
            &["--pid", "0"],
            &["--pid", "-1"],
            &["--pid", "4294967296"],
            &["--pid", "1", "--pid", "2"],
            &["--home", "C:\\other"],
            &["--thread", "12345678-1234-1234-1234-123456789abc"],
        ] {
            let mut a = base.clone();
            a.extend(args(suffix));
            assert!(parse(&a).is_err(), "{a:?}");
        }
        for a in [
            &["unlock"][..],
            &["list"],
            &["recovery"],
            &["capabilities", "--pid", "1"],
            &["help", "--json"],
            &["--version", "extra"],
        ] {
            assert!(parse(&args(a)).is_err());
        }
        for a in [
            &["--help"][..],
            &["help"],
            &["--version"],
            &["capabilities"],
            &["capabilities", "--json"],
        ] {
            assert!(parse(&args(a)).is_ok());
        }
        let mut a = base.clone();
        a[2] = "relative".into();
        assert!(parse(&a).is_err());
        let mut a = base;
        a[4] = "../unsafe".into();
        assert!(parse(&a).is_err());
    }
    #[test]
    fn presentation_is_control_safe_and_does_not_disclose_paths() {
        let value = json!({"reason":"evil\u{1b}\n", "lock":{"state":"unknown\r"}, "diagnostic":{"path":"SECRET_PATH"}, "requestedPid":123});
        let text = human(&value);
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains('\r'));
        assert!(!text.contains("SECRET_PATH"));
        assert!(text.contains("not lock-owner evidence"));
    }
    #[test]
    fn capabilities_always_denies_recovery() {
        let (_, value) = execute(Request::Capabilities);
        assert_eq!(value["schema"], "codex-unlock-windows-preview");
        assert_eq!(value["safeToUnlock"], false);
        assert_eq!(value["recoveryAvailable"], false);
        assert_eq!(
            value["diagnosticsAvailable"],
            context_decision(&value["context"]).is_ok()
        );
    }
}
