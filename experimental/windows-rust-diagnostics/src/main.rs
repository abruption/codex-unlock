use serde_json::{Value, json};
use std::process::ExitCode;

#[cfg(windows)]
mod windows;

#[derive(Debug, PartialEq)]
enum Request {
    Capabilities,
    Inspect {
        home: String,
        thread: String,
        pid: Option<u32>,
    },
}

fn parse(args: &[String]) -> Result<Request, &'static str> {
    if args == ["capabilities"] {
        return Ok(Request::Capabilities);
    }
    if args.first().map(String::as_str) != Some("inspect") {
        return Err("command_required");
    }
    let (mut home, mut thread, mut pid) = (None, None, None);
    let mut fields = args[1..].chunks_exact(2);
    for pair in &mut fields {
        match pair[0].as_str() {
            "--home" if home.is_none() && !pair[1].is_empty() => home = Some(pair[1].clone()),
            "--thread" if thread.is_none() => thread = Some(pair[1].clone()),
            "--pid" if pid.is_none() => {
                if pair[1].is_empty() || !pair[1].bytes().all(|b| b.is_ascii_digit()) {
                    return Err("invalid_pid");
                }
                let value = pair[1].parse::<u32>().map_err(|_| "invalid_pid")?;
                if value == 0 {
                    return Err("invalid_pid");
                }
                pid = Some(value);
            }
            _ => return Err("unknown_or_duplicate_option"),
        }
    }
    if !fields.remainder().is_empty() {
        return Err("option_value_required");
    }
    let home = home.ok_or("home_required")?;
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
    Ok(Request::Inspect { home, thread, pid })
}

fn execute(request: Request) -> (u8, Value) {
    match request {
        Request::Capabilities => (
            0,
            json!({
                "schemaVersion":1, "experimental":true, "safeToUnlock":false,
                "prototypeVersion":env!("CARGO_PKG_VERSION"),
                "platform":std::env::consts::OS, "architecture":std::env::consts::ARCH,
                "diagnosticsAvailable":cfg!(windows), "commands":["capabilities","inspect"],
                "supportedFilesystems":["NTFS"], "holderAttribution":"unproven",
                "recoveryAvailable":false,
                "probeEffects":"brief exclusive coordination/thread locks; directory rename sharing denied during observation"
            }),
        ),
        Request::Inspect { home, thread, pid } => {
            #[cfg(windows)]
            let result = windows::inspect(&home, &thread, pid);
            #[cfg(not(windows))]
            let result = {
                let _ = (home, thread, pid);
                json!({"schemaVersion":1,"experimental":true,"safeToUnlock":false,
                    "platform":std::env::consts::OS,"lock":{"state":"unknown","reason":"windows_required"}})
            };
            let process = &result["observation"]["process"];
            let unknown = result["lock"]["state"] == "unknown"
                || (!process.is_null()
                    && (process["state"] != "observed" || process["sameUser"] != true));
            (if unknown { 2 } else { 0 }, result)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (code, value) = match parse(&args) {
        Ok(request) => execute(request),
        Err(reason) => (
            64,
            json!({"schemaVersion":1,"experimental":true,"safeToUnlock":false,"error":"usage","reason":reason}),
        ),
    };
    println!("{value}");
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }
    #[test]
    fn commands_and_unknown_options_are_closed() {
        for command in ["unlock", "release", "kill", "list", ""] {
            assert!(parse(&args(&[command])).is_err());
        }
        assert!(parse(&args(&["capabilities", "--force"])).is_err());
        assert_eq!(parse(&args(&["capabilities"])), Ok(Request::Capabilities));
    }
    #[test]
    fn inspect_requires_explicit_inputs_and_rejects_duplicates() {
        let valid = args(&[
            "inspect",
            "--home",
            "C:\\lab\\home",
            "--thread",
            "12345678-1234-1234-1234-123456789abc",
        ]);
        assert!(parse(&valid).is_ok());
        for suffix in [
            &["--force", "true"][..],
            &["--home", "other"][..],
            &["--pid", "0"][..],
            &["--pid", "4294967296"][..],
            &["--pid", "-1"][..],
            &["--pid"][..],
        ] {
            let mut request = valid.clone();
            request.extend(args(suffix));
            assert!(parse(&request).is_err());
        }
    }
    #[test]
    fn capabilities_never_authorize_recovery() {
        let (code, result) = execute(Request::Capabilities);
        assert_eq!(code, 0);
        assert_eq!(result["safeToUnlock"], false);
        assert_eq!(result["recoveryAvailable"], false);
    }
}
