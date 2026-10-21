//! Experimental, synchronous Windows observations. No recovery authority is returned.
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{IO::OVERLAPPED, Threading::*, WindowsProgramming::DRIVE_FIXED},
};

type Result<T> = std::result::Result<T, Failure>;
#[derive(Debug)]
struct Failure {
    reason: &'static str,
    win32: Option<u32>,
}
fn fail(reason: &'static str) -> Failure {
    Failure {
        reason,
        win32: None,
    }
}
fn os_error(reason: &'static str) -> Failure {
    Failure {
        reason,
        win32: Some(unsafe { GetLastError() }),
    }
}
fn failure_value(e: Failure) -> Value {
    json!({"state":"unknown", "reason":e.reason, "win32":e.win32})
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Deliberately excludes UNC, device paths, ADS, dot segments and DOS aliases.
fn validate(home: &str, thread: &str) -> Result<()> {
    let bytes = home.as_bytes();
    if bytes.len() < 4
        || !bytes[0].is_ascii_alphabetic()
        || &bytes[1..3] != b":\\"
        || home.ends_with('\\')
        || home.contains('/')
    {
        return Err(fail("absolute_local_drive_path_required"));
    }
    if format!("{home}\\thread-writer-locks\\{thread}.lock")
        .encode_utf16()
        .count()
        >= 260
    {
        return Err(fail("path_too_long"));
    }
    for part in home[3..].split('\\') {
        if part.is_empty()
            || part.ends_with([' ', '.'])
            || part.chars().any(|c| c < ' ' || "<>:\"|?*".contains(c))
        {
            return Err(fail("unsafe_path_component"));
        }
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"].contains(&stem.as_str())
            || ["COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"].contains(&stem.as_str())
            || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.len() == 4
                && stem.as_bytes()[3].is_ascii_digit())
        {
            return Err(fail("reserved_path_component"));
        }
    }
    if thread.len() != 36
        || !thread.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(fail("uuid_thread_id_required"));
    }
    Ok(())
}
fn open(path: &str, directory: bool) -> Result<Handle> {
    let access = if directory {
        FILE_READ_ATTRIBUTES
    } else {
        GENERIC_READ
    } | READ_CONTROL;
    // Pin directories against rename/removal for the complete observation.
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | if directory { 0 } else { FILE_SHARE_DELETE };
    let h = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            access,
            share,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        Err(os_error("open_existing_failed"))
    } else {
        Ok(Handle(h))
    }
}
fn info<T>(h: &Handle, class: FILE_INFO_BY_HANDLE_CLASS) -> Result<T> {
    let mut out: T = unsafe { zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            h.0,
            class,
            &mut out as *mut _ as *mut c_void,
            size_of::<T>() as u32,
        )
    } == 0
    {
        Err(os_error("file_information_failed"))
    } else {
        Ok(out)
    }
}
#[derive(Serialize, PartialEq, Eq)]
struct Snapshot {
    volume: String,
    file_id: String,
    final_path: String,
    links: u32,
    size: String,
    write_time: String,
    change_time: String,
    directory: bool,
}
fn snapshot(h: &Handle, directory: bool) -> Result<Snapshot> {
    let tag: FILE_ATTRIBUTE_TAG_INFO = info(h, FileAttributeTagInfo)?;
    let standard: FILE_STANDARD_INFO = info(h, FileStandardInfo)?;
    let id: FILE_ID_INFO = info(h, FileIdInfo)?;
    let basic: FILE_BASIC_INFO = info(h, FileBasicInfo)?;
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || standard.DeletePending
        || standard.Directory != directory
        || (!directory && standard.NumberOfLinks != 1)
    {
        return Err(fail("unsafe_file_type_or_links"));
    }
    let mut path = vec![0u16; 32768];
    let n = unsafe { GetFinalPathNameByHandleW(h.0, path.as_mut_ptr(), path.len() as u32, 0) };
    if n == 0 || n as usize >= path.len() {
        return Err(os_error("final_path_failed"));
    }
    let final_path =
        String::from_utf16(&path[..n as usize]).map_err(|_| fail("final_path_encoding"))?;
    Ok(Snapshot {
        volume: format!("{:016x}", id.VolumeSerialNumber),
        file_id: id
            .FileId
            .Identifier
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        final_path,
        links: standard.NumberOfLinks,
        size: standard.EndOfFile.to_string(),
        write_time: basic.LastWriteTime.to_string(),
        change_time: basic.ChangeTime.to_string(),
        directory,
    })
}
fn expected_path(s: &Snapshot, path: &str) -> Result<()> {
    let expected = format!("\\\\?\\{path}");
    // Conservative: case-sensitive paths and alternate spellings are not normalized.
    if s.final_path != expected {
        return Err(fail("final_path_not_exact"));
    }
    Ok(())
}
fn token(process: HANDLE) -> Result<Handle> {
    let mut h = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut h) } == 0 {
        Err(os_error("token_open_failed"))
    } else {
        Ok(Handle(h))
    }
}
// usize allocation ensures alignment for TOKEN_USER and TOKEN_MANDATORY_LABEL.
fn token_info(t: &Handle, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<usize>> {
    let mut needed = 0;
    unsafe {
        GetTokenInformation(t.0, class, null_mut(), 0, &mut needed);
    }
    if needed == 0 || needed > 65536 {
        return Err(os_error("token_information_size_failed"));
    }
    let mut b = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            t.0,
            class,
            b.as_mut_ptr().cast(),
            (b.len() * size_of::<usize>()) as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(os_error("token_information_failed"));
    }
    Ok(b)
}
fn user_sid(b: &[usize]) -> PSID {
    unsafe { (*(b.as_ptr() as *const TOKEN_USER)).User.Sid }
}
fn owner_self(h: &Handle, current: &[usize]) -> Result<()> {
    let mut owner: PSID = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let code = unsafe {
        GetSecurityInfo(
            h.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(Failure {
            reason: "file_owner_query_failed",
            win32: Some(code),
        });
    }
    let matches = !owner.is_null()
        && unsafe { IsValidSid(owner) != 0 && EqualSid(owner, user_sid(current)) != 0 };
    unsafe {
        LocalFree(descriptor);
    }
    if matches {
        Ok(())
    } else {
        Err(fail("file_owner_not_self"))
    }
}
fn ntfs(h: &Handle) -> Result<()> {
    let mut fs = [0u16; 64];
    if unsafe {
        GetVolumeInformationByHandleW(
            h.0,
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            fs.as_mut_ptr(),
            fs.len() as u32,
        )
    } == 0
    {
        return Err(os_error("filesystem_query_failed"));
    }
    let n = fs.iter().position(|x| *x == 0).unwrap_or(fs.len());
    if String::from_utf16_lossy(&fs[..n]) != "NTFS" {
        return Err(fail("filesystem_not_supported"));
    }
    Ok(())
}
fn process_observation(pid: u32, current: &[usize]) -> Result<Value> {
    if pid == 0 {
        return Err(fail("invalid_pid"));
    }
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    if raw.is_null() {
        return Err(os_error("process_open_failed"));
    }
    let h = Handle(raw);
    if unsafe { WaitForSingleObject(h.0, 0) } != WAIT_TIMEOUT {
        return Err(fail("process_not_live"));
    }
    if unsafe { GetProcessId(h.0) } != pid {
        return Err(fail("process_pid_mismatch"));
    }
    let (mut create, mut exit, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { zeroed() };
    if unsafe { GetProcessTimes(h.0, &mut create, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(os_error("process_times_failed"));
    }
    let mut image = vec![0u16; 32768];
    let mut len = image.len() as u32;
    if unsafe { QueryFullProcessImageNameW(h.0, 0, image.as_mut_ptr(), &mut len) } == 0 {
        return Err(os_error("process_image_failed"));
    }
    let t = token(h.0)?;
    let u = token_info(&t, TokenUser)?;
    let session = token_info(&t, TokenSessionId)?;
    let integrity = token_info(&t, TokenIntegrityLevel)?;
    let sid = unsafe {
        (*(integrity.as_ptr() as *const TOKEN_MANDATORY_LABEL))
            .Label
            .Sid
    };
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(fail("integrity_sid_invalid"));
    }
    let count = unsafe { *GetSidSubAuthorityCount(sid) };
    if count == 0 {
        return Err(fail("integrity_sid_invalid"));
    }
    let rid = unsafe { *GetSidSubAuthority(sid, u32::from(count - 1)) };
    let same_user = unsafe { EqualSid(user_sid(&u), user_sid(current)) != 0 };
    if unsafe { WaitForSingleObject(h.0, 0) } != WAIT_TIMEOUT {
        return Err(fail("process_exited_during_observation"));
    }
    Ok(
        json!({"state":"observed", "evidence":"requested_pid_only_not_holder", "pid":pid, "live":true, "startTime":((u64::from(create.dwHighDateTime)<<32)|u64::from(create.dwLowDateTime)).to_string(), "image":String::from_utf16_lossy(&image[..len as usize]), "sameUser":same_user, "sessionId":unsafe { *(session.as_ptr() as *const u32) }, "integrityRid":rid}),
    )
}
struct Lock<'a> {
    h: &'a Handle,
    active: bool,
    ov: OVERLAPPED,
}
impl<'a> Lock<'a> {
    fn acquire(h: &'a Handle) -> Result<Self> {
        let mut lock = Self {
            h,
            active: false,
            ov: unsafe { zeroed() },
        };
        if unsafe {
            LockFileEx(
                h.0,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut lock.ov,
            )
        } == 0
        {
            return Err(os_error("lock_failed"));
        }
        lock.active = true;
        Ok(lock)
    }
    fn release(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        if unsafe { UnlockFileEx(self.h.0, 0, u32::MAX, u32::MAX, &mut self.ov) } == 0 {
            return Err(os_error("unlock_failed"));
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for Lock<'_> {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

fn inspect_inner(home: &str, thread: &str) -> Result<Value> {
    validate(home, thread)?;
    let root = &home[..3];
    if unsafe { GetDriveTypeW(wide(root).as_ptr()) } != DRIVE_FIXED {
        return Err(fail("fixed_local_drive_required"));
    }
    let current_token = token(unsafe { GetCurrentProcess() })?;
    let current = token_info(&current_token, TokenUser)?;
    let lock_dir = format!("{home}\\thread-writer-locks");
    let mut pinned: Vec<(Handle, Snapshot)> = Vec::new();
    let mut path = root.to_string();
    let root_handle = open(&path, true)?;
    ntfs(&root_handle)?;
    let root_snapshot = snapshot(&root_handle, true)?;
    expected_path(&root_snapshot, &path)?;
    pinned.push((root_handle, root_snapshot));
    for component in lock_dir[3..].split('\\') {
        if !path.ends_with('\\') {
            path.push('\\');
        }
        path.push_str(component);
        let h = open(&path, true)?;
        let s = snapshot(&h, true)?;
        expected_path(&s, &path)?;
        if path == home || path == lock_dir {
            owner_self(&h, &current)?;
        }
        pinned.push((h, s));
    }
    let guard_path = format!("{lock_dir}\\.coordination.lock");
    let thread_path = format!("{lock_dir}\\{thread}.lock");
    let guard_handle = open(&guard_path, false)?;
    let thread_handle = open(&thread_path, false)?;
    let guard_before = snapshot(&guard_handle, false)?;
    let thread_before = snapshot(&thread_handle, false)?;
    expected_path(&guard_before, &guard_path)?;
    expected_path(&thread_before, &thread_path)?;
    owner_self(&guard_handle, &current)?;
    owner_self(&thread_handle, &current)?;
    let mut guard = Lock::acquire(&guard_handle).map_err(|e| Failure {
        reason: if e.win32 == Some(ERROR_LOCK_VIOLATION) {
            "coordination_busy"
        } else {
            "coordination_lock_failed"
        },
        win32: e.win32,
    })?;
    // Only synchronous existing-handle operations below. No PID queries or spawning.
    let probe = match Lock::acquire(&thread_handle) {
        Ok(mut l) => match l.release() {
            Ok(()) => Ok("free"),
            Err(e) => Err(Failure {
                reason: "thread_unlock_failed",
                win32: e.win32,
            }),
        },
        Err(e) if e.win32 == Some(ERROR_LOCK_VIOLATION) => Ok("held"),
        Err(e) => Err(Failure {
            reason: "thread_lock_failed",
            win32: e.win32,
        }),
    };
    let release = guard.release();
    if let Err(e) = release {
        return Err(Failure {
            reason: "coordination_unlock_failed",
            win32: e.win32,
        });
    }
    let state = probe?;
    if snapshot(&guard_handle, false)? != guard_before
        || snapshot(&thread_handle, false)? != thread_before
    {
        return Err(fail("file_changed_during_probe"));
    }
    owner_self(&guard_handle, &current)?;
    owner_self(&thread_handle, &current)?;
    for (h, before) in &pinned {
        let after = snapshot(h, true)?;
        if after.volume != before.volume
            || after.file_id != before.file_id
            || after.final_path != before.final_path
            || after.directory != before.directory
        {
            return Err(fail("directory_changed_during_probe"));
        }
    }
    Ok(
        json!({"state":state,"coordination":"acquired_and_released","range":"offset_0_length_18446744073709551615","filesystem":"NTFS","fileOwnerSelf":true,"guard":guard_before,"thread":thread_before,"holder":"unproven"}),
    )
}

pub fn inspect(home: &str, thread_id: &str, pid: Option<u32>) -> Value {
    // The requested PID observation is independent and survives a lock refusal.
    // Its handle closes before any coordination lock is acquired.
    let process = pid.map(|p| {
        token(unsafe { GetCurrentProcess() })
            .and_then(|t| token_info(&t, TokenUser))
            .and_then(|current| process_observation(p, &current))
            .unwrap_or_else(failure_value)
    });
    let mut observation = inspect_inner(home, thread_id).unwrap_or_else(failure_value);
    observation["process"] = json!(process);
    let lock = json!({"state":observation["state"], "reason":observation.get("reason"), "win32":observation.get("win32")});
    json!({"schemaVersion":1,"experimental":true,"platform":"windows","safeToUnlock":false,"requestedPid":pid,"lock":lock,"observation":observation})
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "12345678-1234-1234-1234-123456789abc";
    #[test]
    fn local_path_grammar_rejects_aliases_and_redirecting_spellings() {
        for home in [
            "C:",
            "C:\\",
            "C:home",
            "\\\\server\\home",
            "\\\\?\\C:\\home",
            "C:\\a\\..\\b",
            "C:\\a\\.\\b",
            "C:\\a\\\\b",
            "C:\\a.",
            "C:\\a ",
            "C:\\NUL.txt",
            "C:\\CONIN$",
            "C:\\CONOUT$.txt",
            "C:\\COM¹",
            "C:\\LPT².log",
            "C:\\a:stream",
            "C:/home",
            "C:\\a\0b",
        ] {
            assert!(validate(home, ID).is_err(), "accepted {home:?}");
        }
        assert!(validate("C:\\Users\\quintet\\홈", ID).is_ok());
        assert!(validate(&format!("C:\\{}", "a".repeat(220)), ID).is_err());
    }
    #[test]
    fn thread_component_is_only_uuid() {
        for id in [
            "",
            "..",
            "12345678-1234-1234-1234-123456789abg",
            "12345678/1234-1234-1234-123456789abc",
        ] {
            assert!(validate("C:\\home", id).is_err());
        }
    }
}
