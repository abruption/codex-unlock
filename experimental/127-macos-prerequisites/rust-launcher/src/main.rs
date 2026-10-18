//! Synthetic macOS std::process::Command inheritance experiment; unpublished.
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

// Darwin fcntl constants. The executable refuses other operating systems.
const F_GETFD: i32 = 1;
const F_SETFD: i32 = 2;
const FD_CLOEXEC: i32 = 1;
unsafe extern "C" { fn fcntl(fd: i32, cmd: i32, ...) -> i32; }

fn lines<R: BufRead + Send + 'static>(mut reader: R) -> Receiver<io::Result<String>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => { if tx.send(Ok(line.trim().to_owned())).is_err() { break; } }
            Err(e) => { let _ = tx.send(Err(e)); break; }
        }
    });
    rx
}

fn emit(value: &str) -> io::Result<()> {
    println!("{value}");
    io::stdout().flush()
}

fn finish(child: &mut Child) -> io::Result<()> {
    drop(child.stdin.take()); // EOF only; never kill a child.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait()? {
            emit(&format!("{{\"event\":\"child_exit\",\"ok\":{},\"code\":{}}}",
                status.success(), status.code().map_or("null".to_owned(), |n| n.to_string())))?;
            return if status.success() { Ok(()) } else { Err(io::Error::other("child failed")) };
        }
        if Instant::now() >= deadline {
            emit(&format!("{{\"event\":\"incomplete\",\"pid\":{}}}", child.id()))?;
            return Err(io::Error::other("child exit unconfirmed"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn keeper(args: &[String]) -> io::Result<()> {
    let fd: i32 = args[2].parse().map_err(io::Error::other)?;
    let dev: u64 = args[3].parse().map_err(io::Error::other)?;
    let ino: u64 = args[4].parse().map_err(io::Error::other)?;
    let mut inherited = None;
    // If startup reused the numeric descriptor, identity comparison prevents
    // counting that unrelated descriptor as the fixture file.
    if unsafe { fcntl(fd, F_GETFD) } >= 0 {
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        if metadata.dev() == dev && metadata.ino() == ino {
            inherited = Some(file);
        } else {
            std::mem::forget(file); // Do not close an unrelated runtime FD.
        }
    }
    emit(&format!("{{\"event\":\"keeper\",\"pid\":{},\"has_fd\":{}}}",
        std::process::id(), inherited.is_some()))?;
    let input = lines(io::BufReader::new(io::stdin()));
    match input.recv_timeout(Duration::from_secs(20)) {
        Err(mpsc::RecvTimeoutError::Disconnected) => Ok(()),
        Ok(Ok(line)) if line == "exit" => Ok(()),
        _ => Err(io::Error::other("keeper lifetime or protocol failure")),
    }
    // inherited File drops on every return, without an explicit LOCK_UN:
    // unlocking a shared description would also unlock the parent's lock.
}

fn parent(args: &[String]) -> io::Result<()> {
    if args.len() != 3 || !["default", "inheritable"].contains(&args[1].as_str()) {
        return Err(io::Error::other("usage: lab default|inheritable NEW_FILE"));
    }
    let file = OpenOptions::new().read(true).write(true).create_new(true).open(&args[2])?;
    file.try_lock().map_err(io::Error::other)?;
    let fd = file.as_raw_fd();
    let flags = unsafe { fcntl(fd, F_GETFD) };
    if flags < 0 { return Err(io::Error::last_os_error()); }
    if args[1] == "inheritable" && unsafe { fcntl(fd, F_SETFD, flags & !FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let spawn_flags = unsafe { fcntl(fd, F_GETFD) };
    if spawn_flags < 0 { return Err(io::Error::last_os_error()); }
    let metadata = file.metadata()?;
    let mut child = Command::new(std::env::current_exe()?)
        .args(["keeper", &fd.to_string(), &metadata.dev().to_string(), &metadata.ino().to_string()])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
    let child_output = lines(io::BufReader::new(child.stdout.take().unwrap()));
    let result = (|| {
        let ready = child_output.recv_timeout(Duration::from_secs(5)).map_err(io::Error::other)??;
        emit(&ready)?;
        emit(&format!("{{\"event\":\"ready\",\"pid\":{},\"child_pid\":{},\"initial_fd_flags\":{},\"pre_spawn_fd_flags\":{}}}",
            std::process::id(), child.id(), flags, spawn_flags))?;
        let input = lines(io::BufReader::new(io::stdin()));
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut held_file = Some(file);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match input.recv_timeout(remaining) {
                Ok(Ok(line)) if line == "close" && held_file.is_some() => {
                    drop(held_file.take());
                    emit("{\"event\":\"closed\"}")?;
                }
                Ok(Ok(line)) if line == "exit" => return Ok(()),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                _ => return Err(io::Error::other("parent lifetime or protocol failure")),
            }
        }
    })();
    let cleanup = finish(&mut child);
    result.and(cleanup)
}

fn main() -> ExitCode {
    if !cfg!(target_os = "macos") { eprintln!("macOS only"); return ExitCode::from(3); }
    let args: Vec<String> = std::env::args().collect();
    let result = if args.get(1).is_some_and(|v| v == "keeper") && args.len() == 5 {
        keeper(&args)
    } else { parent(&args) };
    match result { Ok(()) => ExitCode::SUCCESS, Err(e) => { eprintln!("{e}"); ExitCode::from(1) } }
}
