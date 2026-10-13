//! Fixture-only research. This binary cannot inspect or terminate Codex processes.
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const LIMIT: Duration = Duration::from_secs(10);
const CONTENT: &[u8] = b"codex-unlock-lab disposable fixture\n";

#[derive(Debug, PartialEq)]
enum Observation {
    Held,
    Free,
    UnknownMissingGuard,
    UnknownBusyGuard,
}

fn create_fixture(root: &Path) -> io::Result<PathBuf> {
    let root = root.canonicalize()?;
    if !root.is_dir() {
        return Err(io::Error::other("scratch root is not a directory"));
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let dir = root.join(format!("codex-unlock-lab-{}-{stamp}", std::process::id()));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&dir)?;
    for name in ["guard.fixture", "thread.fixture"] {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(dir.join(name))?.write_all(CONTENT)?;
    }
    Ok(dir)
}

fn open_fixture(dir: &Path, name: &str) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join(name))
}

// Entire guard interval is synchronous. This is a fixture protocol, not a
// production path/identity adapter; only freshly created owned files are used.
fn observe(dir: &Path, guard_name: &str) -> io::Result<Observation> {
    let guard = match open_fixture(dir, guard_name) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(Observation::UnknownMissingGuard);
        }
        Err(e) => return Err(e),
    };
    match guard.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(Observation::UnknownBusyGuard),
        Err(std::fs::TryLockError::Error(e)) => return Err(e),
    }
    let result = (|| {
        let thread = open_fixture(dir, "thread.fixture")?;
        match thread.try_lock() {
            Ok(()) => {
                thread.unlock()?;
                Ok(Observation::Free)
            }
            Err(std::fs::TryLockError::WouldBlock) => Ok(Observation::Held),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    })();
    guard.unlock()?;
    result
}

fn lines(reader: impl io::Read + Send + 'static) -> Receiver<io::Result<String>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in io::BufReader::new(reader).lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

fn receive(rx: &Receiver<io::Result<String>>, deadline: Instant) -> io::Result<String> {
    rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| io::Error::other("fixture protocol deadline or closed pipe"))?
}

fn say(message: &str) -> io::Result<()> {
    println!("{message}");
    io::stdout().flush()
}

// Internal owner creates its OWN fresh directory. Arguments never identify an
// existing lock or home. Even if its parent disappears it releases after LIMIT.
fn fixture_owner(root: &Path) -> io::Result<()> {
    let deadline = Instant::now() + LIMIT;
    let dir = create_fixture(root)?;
    let guard = open_fixture(&dir, "guard.fixture")?;
    let thread = open_fixture(&dir, "thread.fixture")?;
    guard.try_lock().map_err(io::Error::other)?;
    thread.try_lock().map_err(io::Error::other)?;
    guard.unlock()?;
    say(dir
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or_else(|| io::Error::other("invalid fixture name"))?)?;
    let commands = lines(io::stdin());
    let mut guarded = false;
    loop {
        match receive(&commands, deadline).as_deref() {
            Ok("guard") if !guarded => {
                guard.try_lock().map_err(io::Error::other)?;
                guarded = true;
                say("guarded")?;
            }
            Ok("unguard") if guarded => {
                guard.unlock()?;
                guarded = false;
                say("unguarded")?;
            }
            Ok("release") => {
                if !guarded {
                    guard.try_lock().map_err(io::Error::other)?;
                }
                thread.unlock()?;
                guard.unlock()?;
                say("released")?;
                return Ok(());
            }
            _ => {
                return Err(io::Error::other(
                    "fixture owner expired or received invalid command",
                ));
            }
        }
    }
}

fn send(stdin: &mut ChildStdin, command: &str) -> io::Result<()> {
    writeln!(stdin, "{command}")?;
    stdin.flush()
}

fn wait(child: &mut Child, deadline: Instant) -> io::Result<bool> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("fixture child exit deadline"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn expect(actual: Observation, expected: Observation) -> io::Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::other("unexpected fixture lock result"))
    }
}

fn self_test(root: &Path) -> io::Result<()> {
    let root = root.canonicalize()?;
    let mut child = Command::new(std::env::current_exe()?)
        .arg("__fixture-owner")
        .arg("--scratch-root")
        .arg(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + LIMIT + Duration::from_secs(2);
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("missing fixture stdin"))?;
    let output = lines(
        child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing fixture stdout"))?,
    );
    let mut owned_dir = None;
    let result = (|| {
        let name = receive(&output, deadline)?;
        let prefix = format!("codex-unlock-lab-{}-", child.id());
        let suffix = name
            .strip_prefix(&prefix)
            .ok_or_else(|| io::Error::other("unexpected fixture directory"))?;
        if suffix.is_empty() || !suffix.bytes().all(|x| x.is_ascii_digit()) {
            return Err(io::Error::other("invalid fixture suffix"));
        }
        let dir = root.join(name);
        owned_dir = Some(dir.clone());
        expect(observe(&dir, "guard.fixture")?, Observation::Held)?;
        expect(
            observe(&dir, "missing.fixture")?,
            Observation::UnknownMissingGuard,
        )?;
        send(&mut input, "guard")?;
        if receive(&output, deadline)? != "guarded" {
            return Err(io::Error::other("expected guard acknowledgment"));
        }
        expect(
            observe(&dir, "guard.fixture")?,
            Observation::UnknownBusyGuard,
        )?;
        send(&mut input, "unguard")?;
        if receive(&output, deadline)? != "unguarded" {
            return Err(io::Error::other("expected guard release"));
        }
        send(&mut input, "release")?;
        if receive(&output, deadline)? != "released" {
            return Err(io::Error::other("expected thread release"));
        }
        if !wait(&mut child, deadline)? {
            return Err(io::Error::other("fixture child failed"));
        }
        expect(observe(&dir, "guard.fixture")?, Observation::Free)?;
        for name in ["guard.fixture", "thread.fixture"] {
            if fs::read(dir.join(name))? != CONTENT {
                return Err(io::Error::other("fixture contents changed"));
            }
        }
        if dir.join("missing.fixture").exists() {
            return Err(io::Error::other("probe created missing guard"));
        }
        Ok(())
    })();
    // Never send OS signals. Child has its own deadline if cooperative release
    // fails. Only remove the two known fixture files after confirming exit.
    let _ = send(&mut input, "release");
    drop(input);
    if wait(&mut child, deadline).is_ok() {
        if let Some(dir) = owned_dir {
            fs::remove_file(dir.join("guard.fixture"))?;
            fs::remove_file(dir.join("thread.fixture"))?;
            fs::remove_dir(dir)?;
        }
    } else {
        return Err(io::Error::other(
            "fixture exit unconfirmed; scratch preserved",
        ));
    }
    result?;
    println!(
        "{{\"experimentalSchema\":\"codex-unlock-lab/v1\",\"command\":\"self-test\",\"status\":\"passed\",\"crossProcessContention\":true,\"releaseObserved\":true,\"missingGuard\":\"unknown\",\"busyGuard\":\"unknown\",\"contentsUnchanged\":true,\"safeToUnlock\":false,\"productionSupport\":false}}"
    );
    Ok(())
}

fn run() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "capabilities" {
        println!(
            "{{\"experimentalSchema\":\"codex-unlock-lab/v1\",\"command\":\"capabilities\",\"fixtureOnly\":true,\"safeToUnlock\":false,\"ownerAttribution\":false,\"productionSupport\":false}}"
        );
        return Ok(());
    }
    if args.len() == 3 && args[1] == "--scratch-root" {
        if args[2].is_empty() {
            return Err(io::Error::other("scratch root must not be empty"));
        }
        if args[0] == "self-test" {
            return self_test(Path::new(&args[2]));
        }
        if args[0] == "__fixture-owner" {
            return fixture_owner(Path::new(&args[2]));
        }
    }
    Err(io::Error::other(
        "usage: codex-unlock-lab capabilities | self-test --scratch-root EXISTING_PRIVATE_DIRECTORY",
    ))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("codex-unlock-lab: {error}");
        std::process::exit(1);
    }
}
