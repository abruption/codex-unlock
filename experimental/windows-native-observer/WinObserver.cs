// Windows observation helpers for codex-unlock research W6/W7 (#151, #152).
// Loaded by observer.ps1 through Add-Type. It never creates, writes, deletes, or
// renames a file, never changes an ACL or privilege, and never terminates or
// signals a process. Paths are restricted lexically to the disposable
// CODEX_HOME passed to SetRoot. Results are evidence only and never authorize
// recovery.
//
// NOT purely passive: GuardedRangeProbe takes a brief EXCLUSIVE, fail-
// immediately LockFileEx on the LIVE .coordination.lock and holds it across the
// thread-lock probes, and ProbeThreadRanges takes an exclusive lock on the
// thread lock file for each range that is currently free. Codex acquires with a
// fail-immediately try_lock, so a Codex acquisition that happens inside one of
// those windows FAILS. That is an effect on the observed process, not an
// observation of it. Every lock is released before the call returns (the guard
// in a finally), and a failed release makes the result `unknown`.
//
// Compiled by the Windows static gate without invoking these native methods.
// The checked-in windows-native-observer workflow checks compilation only;
// native runtime behavior and real Codex interoperability remain unverified.
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class WinObserver
{
    const uint GENERIC_READ = 0x80000000;
    const uint DELETE = 0x00010000;
    const uint FILE_READ_ATTRIBUTES = 0x80;
    const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, FILE_SHARE_DELETE = 4;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
    const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    const uint LOCKFILE_FAIL_IMMEDIATELY = 1, LOCKFILE_EXCLUSIVE_LOCK = 2;
    const int ERROR_LOCK_VIOLATION = 33, ERROR_MORE_DATA = 234;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, SYNCHRONIZE = 0x00100000;
    const uint TOKEN_QUERY = 0x0008;
    const uint WAIT_OBJECT_0 = 0, WAIT_TIMEOUT = 0x102;
    const int TokenUser = 1, TokenSessionId = 12, TokenElevationType = 18, TokenIntegrityLevel = 25;
    // A lock file the observer probes must be a single-link regular file. The
    // expected link count is fixed here, not taken from the caller.
    const uint EXPECTED_LINKS = 1;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr sa,
        uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool LockFileEx(SafeFileHandle h, uint flags, uint reserved, uint lenLow,
        uint lenHigh, ref NativeOverlapped ov);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UnlockFileEx(SafeFileHandle h, uint reserved, uint lenLow, uint lenHigh,
        ref NativeOverlapped ov);

    [StructLayout(LayoutKind.Sequential)]
    struct FILE_ATTRIBUTE_TAG_INFO { public uint FileAttributes; public uint ReparseTag; }

    [StructLayout(LayoutKind.Sequential)]
    struct FILE_ID_INFO { public ulong VolumeSerialNumber; public ulong IdLow; public ulong IdHigh; }

    [StructLayout(LayoutKind.Sequential)]
    struct FILE_STANDARD_INFO
    {
        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        [MarshalAs(UnmanagedType.U1)] public bool DeletePending;
        [MarshalAs(UnmanagedType.U1)] public bool Directory;
    }

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
    static extern bool GetTagInfo(SafeFileHandle h, int cls, out FILE_ATTRIBUTE_TAG_INFO info, uint size);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
    static extern bool GetFileIdInfo(SafeFileHandle h, int cls, out FILE_ID_INFO info, uint size);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
    static extern bool GetStandardInfo(SafeFileHandle h, int cls, out FILE_STANDARD_INFO info, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder buf, uint n, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr h, uint ms);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetProcessTimes(IntPtr h, out long create, out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool QueryFullProcessImageNameW(IntPtr h, uint flags, StringBuilder buf, ref uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr buf, int len, out int needed);

    // Restart Manager reports resource users (openers). It is never proof of a
    // byte-range lock holder.
    [StructLayout(LayoutKind.Sequential)]
    struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmStartSession(out uint session, int flags, StringBuilder key);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmRegisterResources(uint session, uint nFiles, string[] files, uint nApps,
        IntPtr apps, uint nServices, string[] services);

    [DllImport("rstrtmgr.dll")]
    static extern int RmGetList(uint session, out uint needed, ref uint count,
        [In, Out] RM_PROCESS_INFO[] info, out uint rebootReasons);

    [DllImport("rstrtmgr.dll")]
    static extern int RmEndSession(uint session);

    // Probe ranges. "rust" is Rust std File::lock/try_lock (offset 0, length
    // u32::MAX:u32::MAX). "fsext" is the fs-ext 2.2.14 emulation (offset 0,
    // length 0xffff0000). "beyond_fsext" is one byte just past the fs-ext range;
    // it conflicts only with a holder whose range extends past 0xffff0000.
    // "tail" is the last 64-bit offset, outside the Rust range; it is recorded
    // only, because acceptance of that offset is not established.
    static void Range(string name, out uint offLow, out uint offHigh, out uint lenLow, out uint lenHigh)
    {
        switch (name)
        {
            case "rust": offLow = 0; offHigh = 0; lenLow = uint.MaxValue; lenHigh = uint.MaxValue; return;
            case "fsext": offLow = 0; offHigh = 0; lenLow = 0xffff0000; lenHigh = 0; return;
            case "beyond_fsext": offLow = 0xffff0000; offHigh = 0; lenLow = 1; lenHigh = 0; return;
            case "tail": offLow = uint.MaxValue; offHigh = uint.MaxValue; lenLow = 1; lenHigh = 0; return;
            default: throw new ArgumentException("unknown range " + name);
        }
    }

    static readonly string[] ThreadRanges = { "rust", "fsext", "beyond_fsext", "tail" };

    static string J(string s)
    {
        if (s == null) return "null";
        var b = new StringBuilder("\"");
        foreach (char c in s)
        {
            if (c == '"' || c == '\\') b.Append('\\').Append(c);
            // ASCII-only output survives any console code page.
            else if (c < 0x20 || c > 0x7e) b.AppendFormat("\\u{0:x4}", (int)c);
            else b.Append(c);
        }
        return b.Append('"').ToString();
    }

    static string Err(int code)
    {
        return "{\"ok\":false,\"win32\":" + code + ",\"message\":" + J(new Win32Exception(code).Message) + "}";
    }

    static string Ok(string extra)
    {
        return "{\"ok\":true" + (string.IsNullOrEmpty(extra) ? "" : "," + extra) + "}";
    }

    static string Unknown(string reason, int win32)
    {
        return "{\"ok\":true,\"state\":\"unknown\",\"reason\":" + J(reason) + ",\"win32\":" + win32 + "}";
    }

    static string Bool(bool v) { return v ? "true" : "false"; }

    // ---- Scope -----------------------------------------------------------
    static string Root;

    // Directory identity without following reparse points. It returns null for
    // four different causes — the open failed, the attribute query failed, the
    // target is a reparse point, or the target is not a directory — and does
    // NOT distinguish them. Callers must not report a Win32 code next to a null
    // from here: the handle is already closed by then, and two of the four
    // causes set no error at all. The per-sample `*.identity` records carry the
    // attributes, file ID and Win32 codes that do distinguish them.
    public static string DirFileId(string path)
    {
        using (var d = OpenNoFollow(path, FILE_READ_ATTRIBUTES, "rwd"))
        {
            if (d.IsInvalid) return null;
            uint attrs = Attributes(d);
            if (attrs == uint.MaxValue || (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) return null;
            return FileId(d);
        }
    }

    public static void SetRoot(string root)
    {
        string full = Path.GetFullPath(root).TrimEnd('\\');
        if (DirFileId(full) == null) throw new InvalidOperationException("observation root is not a plain directory");
        Root = full;
    }

    static string Scoped(string path)
    {
        if (Root == null) throw new InvalidOperationException("observation root not set");
        string full = Path.GetFullPath(path);
        if (!full.StartsWith(Root + "\\", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("path outside observation root");
        return full;
    }

    static string Leaf(string name)
    {
        if (name.Length == 0 || name.IndexOfAny(new[] { '\\', '/', ':' }) >= 0 || name == "." || name == "..")
            throw new ArgumentException("name must be a leaf");
        return name;
    }

    // ---- File handles (never create, never write access) -----------------
    static uint Share(string spec)
    {
        uint s = 0;
        foreach (char c in spec)
        {
            if (c == 'r') s |= FILE_SHARE_READ;
            else if (c == 'w') s |= FILE_SHARE_WRITE;
            else if (c == 'd') s |= FILE_SHARE_DELETE;
            else if (c != '-') throw new ArgumentException("share spec " + spec);
        }
        return s;
    }

    static SafeFileHandle OpenNoFollow(string path, uint access, string share)
    {
        return CreateFileW(path, access, Share(share), IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
    }

    static uint Attributes(SafeFileHandle h)
    {
        FILE_ATTRIBUTE_TAG_INFO tag;
        return GetTagInfo(h, 9, out tag, (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO)))
            ? tag.FileAttributes : uint.MaxValue;
    }

    static string FileId(SafeFileHandle h)
    {
        FILE_ID_INFO id;
        if (!GetFileIdInfo(h, 18, out id, (uint)Marshal.SizeOf(typeof(FILE_ID_INFO)))) return null;
        return id.VolumeSerialNumber.ToString("x16") + ":" + id.IdHigh.ToString("x16") + id.IdLow.ToString("x16");
    }

    static string FinalPath(SafeFileHandle h)
    {
        var buf = new StringBuilder(1024);
        uint n = GetFinalPathNameByHandleW(h, buf, (uint)buf.Capacity, 0);
        return n > 0 && n < buf.Capacity ? buf.ToString() : null;
    }

    static bool IsRegular(SafeFileHandle h)
    {
        uint a = Attributes(h);
        return a != uint.MaxValue && (a & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) == 0;
    }

    static string IdentityFields(SafeFileHandle h)
    {
        FILE_ATTRIBUTE_TAG_INFO tag;
        bool tagOk = GetTagInfo(h, 9, out tag, (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO)));
        int tagErr = tagOk ? 0 : Marshal.GetLastWin32Error();
        string id = FileId(h);
        int idErr = id != null ? 0 : Marshal.GetLastWin32Error();
        FILE_STANDARD_INFO std;
        bool stdOk = GetStandardInfo(h, 1, out std, (uint)Marshal.SizeOf(typeof(FILE_STANDARD_INFO)));
        int stdErr = stdOk ? 0 : Marshal.GetLastWin32Error();
        string final = FinalPath(h);
        bool complete = tagOk && id != null && stdOk && final != null;
        return "\"complete\":" + Bool(complete) +
            ",\"attributes\":" + (tagOk ? tag.FileAttributes.ToString() : "null") +
            ",\"reparse\":" + (tagOk ? Bool((tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) : "null") +
            ",\"directory\":" + (tagOk ? Bool((tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) : "null") +
            ",\"tagWin32\":" + tagErr +
            ",\"fileId\":" + J(id) + ",\"idWin32\":" + idErr +
            ",\"links\":" + (stdOk ? std.NumberOfLinks.ToString() : "null") +
            ",\"size\":" + (stdOk ? std.EndOfFile.ToString() : "null") +
            ",\"deletePending\":" + (stdOk ? Bool(std.DeletePending) : "null") +
            ",\"stdWin32\":" + stdErr +
            ",\"finalPath\":" + J(final);
    }

    // Attribute-only open: FILE_READ_ATTRIBUTES is exempt from sharing checks,
    // so this observes identity without contending with the holder's share mode.
    public static string Identity(string path)
    {
        string full = Scoped(path);
        using (var h = OpenNoFollow(full, FILE_READ_ATTRIBUTES, "rwd"))
        {
            if (h.IsInvalid) return Err(Marshal.GetLastWin32Error());
            return Ok(IdentityFields(h));
        }
    }

    // No-follow ancestry of a directory, root first. Each component is opened
    // with FILE_FLAG_OPEN_REPARSE_POINT and read for attributes only, so a
    // junction or symlink anywhere above the target is reported as a reparse
    // point instead of being silently traversed. The caller refuses the path
    // when any component is not a plain directory.
    //
    // This is NOT scoped (it runs before SetRoot, to validate the candidate
    // temp root itself) and it is NOT a pin: components are opened one after
    // another, so an ancestry that passes here can still be replaced
    // afterwards. That residual window is why the native modes stay refused.
    public static string Ancestry(string path)
    {
        string full = Path.GetFullPath(path);
        string root = Path.GetPathRoot(full);
        if (string.IsNullOrEmpty(root)) return Unknown("no_path_root", 0);
        // Trim the separator only below the root: trimming "C:\" would leave the
        // drive-relative spelling "C:", which names a different directory.
        if (full.Length > root.Length) full = full.TrimEnd('\\');
        var parts = full.Substring(root.Length).Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
        var b = new StringBuilder();
        bool complete = true;
        string cur = root;
        for (int i = 0; i <= parts.Length; i++)
        {
            if (i > 0) cur = Path.Combine(cur, parts[i - 1]);
            string lexical = i == 0 ? root : cur;
            using (var h = OpenNoFollow(lexical, FILE_READ_ATTRIBUTES, "rwd"))
            {
                if (b.Length > 0) b.Append(',');
                if (h.IsInvalid)
                {
                    complete = false;
                    b.Append("{\"path\":").Append(J(lexical)).Append(",\"fileId\":null,\"directory\":null,\"reparse\":null,\"win32\":")
                        .Append(Marshal.GetLastWin32Error()).Append('}');
                    continue;
                }
                uint attrs = Attributes(h);
                string id = FileId(h);
                if (attrs == uint.MaxValue || id == null) complete = false;
                b.Append("{\"path\":").Append(J(lexical))
                    .Append(",\"fileId\":").Append(J(id))
                    .Append(",\"directory\":").Append(attrs == uint.MaxValue ? "null" : Bool((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0))
                    .Append(",\"reparse\":").Append(attrs == uint.MaxValue ? "null" : Bool((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0))
                    .Append(",\"finalPath\":").Append(J(FinalPath(h)))
                    .Append(",\"win32\":0}");
            }
        }
        return Ok("\"complete\":" + Bool(complete) + ",\"entries\":[" + b + "]");
    }

    // Share-mode probe: open with one access right and one share mask, record
    // the Win32 result, close immediately. "read" requests GENERIC_READ.
    // "delete" requests the DELETE access right only to test whether the
    // holder shares delete; no delete disposition, rename, or file removal is
    // ever issued on that handle.
    //
    // The DEFAULT observer (observer.ps1) calls this only with the full share
    // mask "rwd", so it never withholds a sharing mode the Codex holder relies
    // on. A RESTRICTIVE share mask (one that omits write or delete sharing) can
    // block the holder's own writes or its Drop-time delete, so such masks are
    // a separately proposed, NOT-executed experiment (see README). Opening a
    // handle at all is not provably side-effect free even with full sharing;
    // requesting the DELETE access right is not a file-removal call, but that is
    // not proof of no interference.
    // FILE_READ_ATTRIBUTES is added to the DELETE probe because the file-type
    // classification below (FileAttributeTagInfo) needs that right: a handle
    // granted DELETE alone cannot be queried, so the probe would always report
    // `not_regular_file` instead of answering whether the holder shares delete.
    // The right is attribute-read only and is exempt from sharing checks, so it
    // does not change what the probe withholds from the holder. GENERIC_READ
    // already includes it.
    public static string ShareProbe(string path, string access, string share)
    {
        string full = Scoped(path);
        uint want;
        if (access == "read") want = GENERIC_READ;
        else if (access == "delete") want = DELETE | FILE_READ_ATTRIBUTES;
        else return Err(87);
        using (var h = OpenNoFollow(full, want, share))
        {
            string tail = ",\"access\":" + J(access) + ",\"share\":" + J(share);
            if (h.IsInvalid) return Ok("\"opened\":false,\"win32\":" + Marshal.GetLastWin32Error() + tail);
            if (!IsRegular(h)) return Unknown("not_regular_file", 0);
            return Ok("\"opened\":true,\"win32\":0" + tail);
        }
    }

    static int TryLock(SafeFileHandle h, string range)
    {
        uint ol, oh, ll, lh;
        Range(range, out ol, out oh, out ll, out lh);
        var ov = new NativeOverlapped();
        ov.OffsetLow = unchecked((int)ol);
        ov.OffsetHigh = unchecked((int)oh);
        return LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, ll, lh, ref ov)
            ? 0 : Marshal.GetLastWin32Error();
    }

    static int Unlock(SafeFileHandle h, string range)
    {
        uint ol, oh, ll, lh;
        Range(range, out ol, out oh, out ll, out lh);
        var ov = new NativeOverlapped();
        ov.OffsetLow = unchecked((int)ol);
        ov.OffsetHigh = unchecked((int)oh);
        return UnlockFileEx(h, 0, ll, lh, ref ov) ? 0 : Marshal.GetLastWin32Error();
    }

    static bool StandardOf(SafeFileHandle h, out uint links, out bool deletePending, out bool directory)
    {
        FILE_STANDARD_INFO std;
        bool ok = GetStandardInfo(h, 1, out std, (uint)Marshal.SizeOf(typeof(FILE_STANDARD_INFO)));
        links = ok ? std.NumberOfLinks : 0;
        deletePending = ok && std.DeletePending;
        directory = ok && std.Directory;
        return ok;
    }

    // Synchronous guarded range probe, bound to caller-validated expected
    // identities. Lock order: native coordination guard, then thread probes.
    //
    // The lock directory, the coordination guard and the thread lock are all
    // opened no-follow. Each one's identity is verified BEFORE any lock is
    // taken: the expected FILE_ID_INFO of the directory, of the guard and of
    // the thread lock must match, and the guard and thread lock must each be a
    // regular, non-reparse, single-link file that is not pending delete. The
    // link count is fixed at one here and is never taken from the caller. The
    // guard and the directory are revalidated AFTER the guard is released, and
    // any changed, unreadable or unreleasable identity makes the whole result
    // `unknown`. No native file is created and there is no fallback. Handles
    // use GENERIC_READ only; every successful probe lock is released before the
    // next, and the guard is released in finally. No await, spawn, or signal
    // happens while the guard is held.
    //
    // Limitation, not closed here: the directory, guard and thread handles are
    // opened separately by path, so this binds identity by comparison at two
    // points in time rather than pinning the path. A same-user actor can still
    // replace a component between those points. It is documented, not asserted
    // away, and it is one reason the native modes stay refused.
    public static string GuardedRangeProbe(string lockDir, string threadLeaf, string expectDirId, string expectGuardId, string expectThreadId)
    {
        string dir = Scoped(lockDir);
        string thread = Leaf(threadLeaf);
        if (string.IsNullOrEmpty(expectDirId) || string.IsNullOrEmpty(expectGuardId) || string.IsNullOrEmpty(expectThreadId))
            return Unknown("expected_identity_missing", 0);
        string dirBefore = DirFileId(dir);
        // No Win32 code here: DirFileId cannot attribute its null (see above).
        if (dirBefore == null) return Unknown("lock_directory_not_plain", 0);
        if (dirBefore != expectDirId) return Unknown("lock_directory_identity_changed", 0);
        using (var guard = OpenNoFollow(Path.Combine(dir, ".coordination.lock"), GENERIC_READ, "rwd"))
        {
            if (guard.IsInvalid)
            {
                int e = Marshal.GetLastWin32Error();
                return Unknown(e == 2 || e == 3 ? "missing_guard" : "guard_open", e);
            }
            if (!IsRegular(guard)) return Unknown("guard_not_regular", 0);
            string guardId = FileId(guard);
            if (guardId == null) return Unknown("guard_file_id", Marshal.GetLastWin32Error());
            if (guardId != expectGuardId) return Unknown("guard_identity_changed", 0);
            uint guardLinks; bool guardDelete, guardDir;
            if (!StandardOf(guard, out guardLinks, out guardDelete, out guardDir))
                return Unknown("guard_standard_info", Marshal.GetLastWin32Error());
            if (guardLinks != EXPECTED_LINKS || guardDelete || guardDir) return Unknown("guard_not_single_regular", 0);
            string guardPath = FinalPath(guard);
            if (guardPath == null) return Unknown("guard_final_path", Marshal.GetLastWin32Error());
            int g = TryLock(guard, "rust");
            if (g == ERROR_LOCK_VIOLATION) return Unknown("busy_guard", g);
            if (g != 0) return Unknown("guard_lock_error", g);
            string body;
            bool guardReleased = false;
            try
            {
                body = ProbeThreadRanges(Path.Combine(dir, thread), expectThreadId);
            }
            catch (Exception ex)
            {
                body = "\"state\":\"unknown\",\"reason\":\"probe_exception\",\"exception\":" + J(ex.GetType().Name + ": " + ex.Message);
            }
            finally
            {
                int gu = Unlock(guard, "rust");
                guardReleased = gu == 0;
                if (gu != 0) body = "\"state\":\"unknown\",\"reason\":\"guard_unlock_failed\",\"win32\":" + gu;
            }
            // Revalidate the guard on the SAME handle and the directory by path
            // after the guard was released. A failed RELEASE is the most
            // serious state this code can reach (the observer may still hold an
            // exclusive range on the live coordination guard), so its reason and
            // Win32 code are kept and the revalidation never overwrites them.
            string guardAfter = FileId(guard);
            uint linksAfter; bool deleteAfter, dirAfter2;
            bool stdAfter = StandardOf(guard, out linksAfter, out deleteAfter, out dirAfter2);
            string dirAfter = DirFileId(dir);
            if (!guardReleased)
            {
                // keep the guard_unlock_failed body
            }
            else if (guardAfter == null || guardAfter != expectGuardId || !stdAfter || linksAfter != EXPECTED_LINKS || deleteAfter)
                body = "\"state\":\"unknown\",\"reason\":\"guard_identity_changed_after\"";
            else if (dirAfter == null || dirAfter != expectDirId)
                body = "\"state\":\"unknown\",\"reason\":\"lock_directory_identity_changed_after\"";
            return Ok(body +
                ",\"dirFileIdBefore\":" + J(dirBefore) + ",\"dirFileIdAfter\":" + J(dirAfter) +
                ",\"guardFileId\":" + J(guardId) + ",\"guardFileIdAfter\":" + J(guardAfter) +
                ",\"guardLinks\":" + guardLinks + ",\"guardDeletePending\":" + Bool(guardDelete) +
                ",\"guardAcquired\":true,\"guardReleased\":" + Bool(guardReleased) +
                ",\"guardFinalPath\":" + J(guardPath));
        }
    }

    static string ProbeThreadRanges(string path, string expectThreadId)
    {
        using (var t = OpenNoFollow(path, GENERIC_READ, "rwd"))
        {
            if (t.IsInvalid)
            {
                int e = Marshal.GetLastWin32Error();
                return "\"state\":\"" + (e == 2 ? "absent" : "unknown") + "\",\"reason\":\"thread_open\",\"win32\":" + e;
            }
            if (!IsRegular(t)) return "\"state\":\"unknown\",\"reason\":\"thread_not_regular\",\"win32\":0";
            // Verify identity BEFORE taking any lock.
            string beforeId = FileId(t);
            uint linksBefore; bool delBefore, dirBefore;
            if (!StandardOf(t, out linksBefore, out delBefore, out dirBefore))
                return "\"state\":\"unknown\",\"reason\":\"thread_standard_info\",\"win32\":" + Marshal.GetLastWin32Error();
            if (beforeId == null || beforeId != expectThreadId)
                return "\"state\":\"unknown\",\"reason\":\"thread_identity_changed\",\"threadFileIdBefore\":" + J(beforeId);
            if (linksBefore != EXPECTED_LINKS || delBefore || dirBefore)
                return "\"state\":\"unknown\",\"reason\":\"thread_not_single_regular\",\"threadLinks\":" + linksBefore +
                    ",\"threadDeletePending\":" + Bool(delBefore);
            var b = new StringBuilder();
            foreach (string r in ThreadRanges)
            {
                int rc = TryLock(t, r);
                bool released = false;
                if (rc == 0)
                {
                    int un = Unlock(t, r);
                    released = un == 0;
                    if (un != 0)
                        return "\"state\":\"unknown\",\"reason\":\"thread_unlock_failed\",\"range\":" + J(r) + ",\"win32\":" + un;
                }
                if (b.Length > 0) b.Append(',');
                b.Append(J(r)).Append(":{\"win32\":").Append(rc).Append(",\"acquired\":").Append(Bool(rc == 0))
                    .Append(",\"released\":").Append(rc == 0 ? Bool(released) : "null").Append('}');
            }
            // Revalidate the SAME handle AFTER all locks were released.
            string afterId = FileId(t);
            uint linksAfter; bool delAfter, dirAfter;
            bool afterOk = StandardOf(t, out linksAfter, out delAfter, out dirAfter);
            if (afterId == null || afterId != expectThreadId || !afterOk || linksAfter != EXPECTED_LINKS || delAfter || dirAfter)
                return "\"state\":\"unknown\",\"reason\":\"thread_identity_changed_after\",\"threadFileIdAfter\":" + J(afterId);
            return "\"state\":\"probed\"" +
                ",\"threadFileIdBefore\":" + J(beforeId) + ",\"threadFileIdAfter\":" + J(afterId) +
                ",\"threadLinks\":" + linksBefore + ",\"threadDeletePending\":" + Bool(delBefore) +
                ",\"ranges\":{" + b + "}";
        }
    }

    public static string RmList(string[] files)
    {
        var scoped = new string[files.Length];
        var names = new StringBuilder();
        for (int i = 0; i < files.Length; i++)
        {
            scoped[i] = Scoped(files[i]);
            if (i > 0) names.Append(',');
            names.Append(J(scoped[i]));
        }
        string target = ",\"files\":[" + names + "],\"interpretation\":\"opener_candidates_only\"";
        uint session;
        var key = new StringBuilder(64);
        int rc = RmStartSession(out session, 0, key);
        if (rc != 0) return Err(rc);
        try
        {
            rc = RmRegisterResources(session, (uint)scoped.Length, scoped, 0, IntPtr.Zero, 0, null);
            if (rc != 0) return Err(rc);
            uint needed, count = 0, reasons;
            RM_PROCESS_INFO[] info = null;
            for (int attempt = 0; attempt < 4; attempt++)
            {
                rc = RmGetList(session, out needed, ref count, info, out reasons);
                if (rc == 0) break;
                if (rc != ERROR_MORE_DATA) return Err(rc);
                count = needed;
                info = new RM_PROCESS_INFO[needed];
            }
            if (rc != 0) return Ok("\"complete\":false,\"reason\":\"list_kept_growing\"" + target);
            var b = new StringBuilder();
            for (int i = 0; i < count; i++)
            {
                var p = info[i];
                long start = ((long)(uint)p.Process.ProcessStartTime.dwHighDateTime << 32) | (uint)p.Process.ProcessStartTime.dwLowDateTime;
                if (i > 0) b.Append(',');
                // The creation FILETIME exceeds 2^53, so it is emitted as an
                // exact decimal STRING; a JSON number would lose precision and
                // break the equality the evaluator relies on.
                b.Append("{\"pid\":").Append(p.Process.dwProcessId)
                    .Append(",\"startFiletime\":").Append(J(start.ToString()))
                    .Append(",\"app\":").Append(J(p.strAppName))
                    .Append(",\"service\":").Append(J(p.strServiceShortName))
                    .Append(",\"type\":").Append(p.ApplicationType)
                    .Append(",\"session\":").Append(p.TSSessionId).Append('}');
            }
            return Ok("\"complete\":true,\"count\":" + count + ",\"processes\":[" + b + "]" + target);
        }
        finally { RmEndSession(session); }
    }

    // ---- Tokens and processes (query only) --------------------------------
    static string TokenFields(IntPtr process)
    {
        IntPtr token;
        if (!OpenProcessToken(process, TOKEN_QUERY, out token))
            return "\"tokenOpened\":false,\"tokenWin32\":" + Marshal.GetLastWin32Error();
        try
        {
            string user = SidInfo(token, TokenUser);
            string integrity = SidInfo(token, TokenIntegrityLevel);
            int elevation = IntInfo(token, TokenElevationType);
            int session = IntInfo(token, TokenSessionId);
            return "\"tokenOpened\":true,\"userSid\":" + J(user) + ",\"integritySid\":" + J(integrity) +
                ",\"elevationType\":" + (elevation < 0 ? "null" : elevation.ToString()) +
                ",\"sessionId\":" + (session < 0 ? "null" : session.ToString());
        }
        finally { CloseHandle(token); }
    }

    // TokenUser and TokenIntegrityLevel both start with SID_AND_ATTRIBUTES.
    static string SidInfo(IntPtr token, int cls)
    {
        int needed;
        GetTokenInformation(token, cls, IntPtr.Zero, 0, out needed);
        if (needed <= 0) return null;
        IntPtr buf = Marshal.AllocHGlobal(needed);
        try
        {
            if (!GetTokenInformation(token, cls, buf, needed, out needed)) return null;
            return new SecurityIdentifier(Marshal.ReadIntPtr(buf)).Value;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    static int IntInfo(IntPtr token, int cls)
    {
        IntPtr buf = Marshal.AllocHGlobal(4);
        try
        {
            int needed;
            if (!GetTokenInformation(token, cls, buf, 4, out needed)) return -1;
            return Marshal.ReadInt32(buf);
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    public static string SelfToken()
    {
        // GetCurrentProcess returns a pseudo handle; it needs no CloseHandle.
        return Ok(TokenFields(GetCurrentProcess()) + ",\"pid\":" + System.Diagnostics.Process.GetCurrentProcess().Id);
    }

    // Query-only identity of a process the operator started. This opens a NEW
    // handle on every call; it is not a run-long pinned handle, so a PID that is
    // reused between calls is a distinct risk the caller must weigh (the
    // creation FILETIME is the only cross-call witness, and it too is sampled,
    // not pinned). Every result echoes the PID that was queried, so the
    // evaluator can bind each record to the run's declared target instead of
    // trusting the record's position in the file. Access failures (for example a
    // Medium observer and a High target) are reported with their Win32 code; the
    // caller maps them to unknown. Liveness comes only from WaitForSingleObject
    // on this handle, never from STILL_ACTIVE.
    public static string ProcessIdentity(int pid)
    {
        string queried = "\"pid\":" + pid;
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, pid);
        if (h == IntPtr.Zero) return Ok(queried + ",\"opened\":false,\"state\":\"unknown\",\"reason\":\"open_process\",\"win32\":" + Marshal.GetLastWin32Error());
        try
        {
            uint w = WaitForSingleObject(h, 0);
            if (w == WAIT_OBJECT_0) return Ok(queried + ",\"opened\":true,\"state\":\"exited\"");
            if (w != WAIT_TIMEOUT) return Ok(queried + ",\"opened\":true,\"state\":\"unknown\",\"reason\":\"wait_failed\",\"win32\":" + Marshal.GetLastWin32Error());
            long create, exit, k, u;
            if (!GetProcessTimes(h, out create, out exit, out k, out u))
                return Ok(queried + ",\"opened\":true,\"state\":\"unknown\",\"reason\":\"process_times\",\"win32\":" + Marshal.GetLastWin32Error());
            var img = new StringBuilder(32768);
            uint size = (uint)img.Capacity;
            string image = QueryFullProcessImageNameW(h, 0, img, ref size) ? img.ToString() : null;
            string token = TokenFields(h);
            uint w2 = WaitForSingleObject(h, 0);
            string state = w2 == WAIT_OBJECT_0 ? "exited" : w2 == WAIT_TIMEOUT ? "live" : "unknown";
            // FILETIME exceeds 2^53; emit it as a string so JSON consumers keep
            // exact equality (JavaScript numbers would round it).
            return Ok(queried + ",\"opened\":true,\"state\":\"" + state + "\",\"createFiletime\":" + J(create.ToString()) +
                ",\"image\":" + J(image) + "," + token);
        }
        finally { CloseHandle(h); }
    }
}
