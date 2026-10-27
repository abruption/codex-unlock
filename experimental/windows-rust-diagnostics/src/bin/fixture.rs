//! Synthetic writer only: parent must be an operator-created private scratch directory.
//! Never pass an existing Codex home. This program creates a fresh child and removes
//! only the exact files it created. No signals or process termination APIs are used.
use serde_json::json;
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const THREAD: &str = "11111111-2222-4333-8444-555555555555";

#[cfg(windows)]
mod private_creation {
    use super::*;
    use std::mem::size_of;
    use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
    use std::path::Path;
    use std::ptr::null_mut;
    use windows_sys::Win32::{
        Foundation::*,
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
        System::Threading::*,
    };

    pub struct Creator(PSECURITY_DESCRIPTOR);
    impl Drop for Creator {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    impl Creator {
        pub fn new() -> io::Result<Self> {
            let mut token = null_mut();
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut needed = 0;
            unsafe {
                GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
            }
            // usize alignment suffices for TOKEN_USER and the SID it references.
            let mut bytes = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
            let read = unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    bytes.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            };
            let read_error = io::Error::last_os_error();
            unsafe {
                CloseHandle(token);
            }
            if read == 0 {
                return Err(read_error);
            }
            let sid = unsafe { (*(bytes.as_ptr() as *const TOKEN_USER)).User.Sid };
            if unsafe { IsValidSid(sid) } == 0 {
                return Err(io::Error::other("invalid current token SID"));
            }
            let mut sid_text = null_mut();
            if unsafe { ConvertSidToStringSidW(sid, &mut sid_text) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0;
            while unsafe { *sid_text.add(len) } != 0 {
                len += 1;
            }
            let text =
                String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid_text, len) });
            unsafe {
                LocalFree(sid_text.cast());
            }
            // Explicit owner avoids an elevated token's default Administrators
            // owner. Only new objects receive this protected single-self ACE.
            let sddl: Vec<u16> = format!("O:{text}D:P(A;OICI;FA;;;{text})")
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut descriptor = null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(descriptor))
        }
        fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0,
                bInheritHandle: 0,
            }
        }
        fn wide(path: &Path) -> Vec<u16> {
            path.as_os_str().encode_wide().chain(Some(0)).collect()
        }
        pub fn directory(&self, path: &Path) -> io::Result<()> {
            if unsafe { CreateDirectoryW(Self::wide(path).as_ptr(), &self.attributes()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        pub fn file(&self, path: &Path) -> io::Result<File> {
            let handle = unsafe {
                CreateFileW(
                    Self::wide(path).as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    &self.attributes(),
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL,
                    null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { File::from_raw_handle(handle) })
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("fixture failed: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut parent = None;
    let mut mode = None;
    let mut lifetime = 20_000u64;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args.next().ok_or("missing argument value")?;
        match arg.as_str() {
            "--parent" => parent = Some(PathBuf::from(value)),
            "--mode" => mode = Some(value),
            "--lifetime-ms" => lifetime = value.parse()?,
            _ => return Err("unknown fixture argument".into()),
        }
    }
    let parent = parent.ok_or("--parent is required (existing private scratch)")?;
    let mode = mode.ok_or("--mode thread|guard|free is required")?;
    if !matches!(mode.as_str(), "thread" | "guard" | "free")
        || !(1000..=60_000).contains(&lifetime)
        || !parent.is_absolute()
        || !fs::symlink_metadata(&parent)?.is_dir()
        || fs::symlink_metadata(&parent)?.file_type().is_symlink()
    {
        return Err("invalid fixture arguments or parent".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        for ancestor in parent.ancestors() {
            if fs::symlink_metadata(ancestor)?.file_attributes() & 0x400 != 0 {
                return Err("fixture parent ancestry contains a reparse point".into());
            }
        }
    }
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = parent.join(format!(
        "codex-windows-rust-fixture-{}-{nonce}",
        std::process::id()
    ));
    #[cfg(windows)]
    let creator = private_creation::Creator::new()?;
    let make_directory = |path: &PathBuf| -> io::Result<()> {
        #[cfg(windows)]
        {
            creator.directory(path)
        }
        #[cfg(not(windows))]
        {
            fs::create_dir(path)
        }
    };
    make_directory(&root)?; // fails on collision, never reuses a directory
    let home = root.join("home");
    make_directory(&home)?;
    let locks = home.join("thread-writer-locks");
    make_directory(&locks)?;
    let guard_path = locks.join(".coordination.lock");
    let thread_path = locks.join(format!("{THREAD}.lock"));
    let open_new = |path: &PathBuf| -> io::Result<File> {
        #[cfg(windows)]
        {
            creator.file(path)
        }
        #[cfg(not(windows))]
        {
            // std Windows default sharing includes READ | WRITE | DELETE.
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path)
        }
    };
    let guard = open_new(&guard_path)?;
    let thread = open_new(&thread_path)?;
    // Both paths use the std whole-range exclusive lock, like the pinned Codex source.
    guard.try_lock()?;
    if mode == "thread" {
        thread.try_lock()?;
    }
    if mode != "guard" {
        guard.unlock()?;
    }
    println!(
        "{}",
        json!({"event":"ready", "home":home, "root":root,
        "thread":THREAD, "pid":std::process::id(), "mode":mode,
        "safeToUnlock":false, "synthetic":true})
    );
    io::stdout().flush()?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            match line {
                Ok(line) => {
                    if sender.send(line).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
        // Dropping sender makes EOF visible to the main thread.
    });
    let deadline = std::time::Instant::now() + Duration::from_millis(lifetime);
    let mut locked = mode != "free";
    let expired = loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(command) if command == "release" => {
                if locked {
                    if mode == "thread" {
                        thread.unlock()?;
                    } else {
                        guard.unlock()?;
                    }
                    locked = false;
                }
                println!("{}", json!({"event":"released"}));
                io::stdout().flush()?;
            }
            Ok(command) if command == "exit" => break false,
            Ok(_) => return Err("unknown fixture command".into()),
            Err(mpsc::RecvTimeoutError::Disconnected) => break false,
            Err(mpsc::RecvTimeoutError::Timeout) => break true,
        }
    };
    drop(thread);
    drop(guard);
    // A failed cleanup is reported; no recursive deletion or forced process exit.
    fs::remove_file(&thread_path)?;
    fs::remove_file(&guard_path)?;
    fs::remove_dir(&locks)?;
    fs::remove_dir(&home)?;
    fs::remove_dir(&root)?;
    println!("{}", json!({"event":"finished", "expired":expired}));
    if expired {
        return Err("fixture lifetime expired".into());
    }
    Ok(())
}
