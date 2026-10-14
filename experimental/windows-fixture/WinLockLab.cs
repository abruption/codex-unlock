// Fixture-only Windows lock observation helpers for codex-unlock research (#122).
// Loaded by lab.ps1 through Add-Type. It never terminates or signals a process.
// Agent path arguments are restricted lexically to the validated scratch root
// (see Scoped). Every result is observation evidence only; nothing here
// authorizes recovery.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class WinLockLab
{
    const uint GENERIC_READ = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, FILE_SHARE_DELETE = 4;
    const uint OPEN_EXISTING = 3, CREATE_NEW = 1;
    const uint FILE_READ_ATTRIBUTES = 0x80;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
    const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    const uint LOCKFILE_FAIL_IMMEDIATELY = 1, LOCKFILE_EXCLUSIVE_LOCK = 2;
    const int ERROR_SHARING_VIOLATION = 32, ERROR_LOCK_VIOLATION = 33, ERROR_MORE_DATA = 234;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, SYNCHRONIZE = 0x00100000;
    const uint TOKEN_QUERY = 0x0008;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr sa,
        uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool LockFileEx(SafeFileHandle h, uint flags, uint reserved, uint lenLow,
        uint lenHigh, ref NativeOverlapped ov);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UnlockFileEx(SafeFileHandle h, uint reserved, uint lenLow, uint lenHigh,
        ref NativeOverlapped ov);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(SafeFileHandle h, byte[] buf, uint n, out uint read, IntPtr ov);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool DeleteFileW(string path);

    [StructLayout(LayoutKind.Sequential)]
    struct FILE_ATTRIBUTE_TAG_INFO { public uint FileAttributes; public uint ReparseTag; }

    [StructLayout(LayoutKind.Sequential)]
    struct FILE_ID_INFO { public ulong VolumeSerialNumber; public ulong IdLow; public ulong IdHigh; }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int cls,
        out FILE_ATTRIBUTE_TAG_INFO info, uint size);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
    static extern bool GetFileIdInfo(SafeFileHandle h, int cls, out FILE_ID_INFO info, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder buf, uint n, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    const uint WAIT_OBJECT_0 = 0, WAIT_TIMEOUT = 0x102;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr h, uint ms);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetProcessTimes(IntPtr h, out long create, out long exit, out long kernel, out long user);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr buf, int len, out int needed);

    // Restart Manager: reports processes that have the resource open. It is
    // opener/resource-user evidence, never proof of a byte-range lock holder.
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

    // Ranges under test. "rust" mirrors Rust std 1.95 File::lock/try_lock
    // (offset 0, length u32::MAX:u32::MAX). "fsext" mirrors fs-ext 2.2.14's
    // Windows flock emulation (offset 0, length 0xffff0000:0).
    static void Range(string name, out uint low, out uint high)
    {
        if (name == "rust") { low = uint.MaxValue; high = uint.MaxValue; return; }
        if (name == "fsext") { low = 0xffff0000; high = 0; return; }
        throw new ArgumentException("unknown range " + name);
    }

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

    static readonly Dictionary<string, SafeFileHandle> Handles = new Dictionary<string, SafeFileHandle>();

    static string J(string s)
    {
        if (s == null) return "null";
        var b = new StringBuilder("\"");
        foreach (char c in s)
        {
            if (c == '"' || c == '\\') b.Append('\\').Append(c);
            // ASCII-only output: localized Win32 messages must survive any console code page.
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

    // Opens an existing path without creating it. noFollow adds
    // FILE_FLAG_OPEN_REPARSE_POINT so a reparse point is observed, not followed.
    static SafeFileHandle OpenRaw(string path, string share, bool noFollow, out int err)
    {
        uint flags = FILE_FLAG_BACKUP_SEMANTICS | (noFollow ? FILE_FLAG_OPEN_REPARSE_POINT : 0);
        var h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, Share(share), IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero);
        err = h.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        return h;
    }

    static int TryLock(SafeFileHandle h, string range)
    {
        uint low, high; Range(range, out low, out high);
        var ov = new NativeOverlapped();
        return LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, low, high, ref ov)
            ? 0 : Marshal.GetLastWin32Error();
    }

    static int Unlock(SafeFileHandle h, string range)
    {
        uint low, high; Range(range, out low, out high);
        var ov = new NativeOverlapped();
        return UnlockFileEx(h, 0, low, high, ref ov) ? 0 : Marshal.GetLastWin32Error();
    }

    static string Identity(SafeFileHandle h)
    {
        FILE_ATTRIBUTE_TAG_INFO tag;
        FILE_ID_INFO id;
        bool tagOk = GetFileInformationByHandleEx(h, 9, out tag, (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO)));
        int tagErr = tagOk ? 0 : Marshal.GetLastWin32Error();
        bool idOk = GetFileIdInfo(h, 18, out id, (uint)Marshal.SizeOf(typeof(FILE_ID_INFO)));
        int idErr = idOk ? 0 : Marshal.GetLastWin32Error();
        var buf = new StringBuilder(1024);
        uint n = GetFinalPathNameByHandleW(h, buf, (uint)buf.Capacity, 0);
        return "\"attributes\":" + (tagOk ? tag.FileAttributes.ToString() : "null") +
            ",\"reparseTag\":" + (tagOk ? tag.ReparseTag.ToString() : "null") +
            ",\"tagWin32\":" + tagErr +
            ",\"fileId\":" + (idOk ? J(id.VolumeSerialNumber.ToString("x16") + ":" + id.IdHigh.ToString("x16") + id.IdLow.ToString("x16")) : "null") +
            ",\"idWin32\":" + idErr +
            ",\"finalPath\":" + (n > 0 && n < buf.Capacity ? J(buf.ToString()) : "null");
    }

    static bool IsReparse(SafeFileHandle h, out int err)
    {
        FILE_ATTRIBUTE_TAG_INFO tag;
        if (!GetFileInformationByHandleEx(h, 9, out tag, (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO))))
        {
            err = Marshal.GetLastWin32Error();
            return true; // unknown attributes are treated like an unsafe path
        }
        err = 0;
        return (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    }

    // Synchronous guarded probe. Lock order: native guard, then thread probe.
    // The guard is released before returning; no await or spawn happens inside.
    // policy "nofollow" refuses any reparse point on the directory, guard, or
    // thread lock; policy "follow" is the negative control showing that plain
    // CreateFileW silently follows a junction.
    public static string GuardProbe(string dir, string thread, string policy)
    {
        bool noFollow = policy == "nofollow";
        if (!noFollow && policy != "follow") return Err(87);
        int err;
        if (noFollow)
        {
            using (var d = CreateFileW(dir, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero))
            {
                if (d.IsInvalid) return Ok("\"state\":\"unknown\",\"reason\":\"directory_open\",\"win32\":" + Marshal.GetLastWin32Error());
                if (IsReparse(d, out err)) return Ok("\"state\":\"unknown\",\"reason\":\"directory_reparse_or_unreadable\",\"win32\":" + err);
            }
        }
        string guardPath = Path.Combine(dir, ".coordination.lock");
        using (var guard = OpenRaw(guardPath, "rwd", noFollow, out err))
        {
            if (guard.IsInvalid)
                return Ok("\"state\":\"unknown\",\"reason\":\"" + (err == 2 || err == 3 ? "missing_guard" : "guard_open") + "\",\"win32\":" + err);
            if (noFollow && (IsReparse(guard, out err) || (Attributes(guard) & FILE_ATTRIBUTE_DIRECTORY) != 0))
                return Ok("\"state\":\"unknown\",\"reason\":\"guard_not_regular\",\"win32\":" + err);
            int g = TryLock(guard, "rust");
            if (g == ERROR_LOCK_VIOLATION) return Ok("\"state\":\"unknown\",\"reason\":\"busy_guard\"");
            if (g != 0) return Ok("\"state\":\"unknown\",\"reason\":\"guard_lock_error\",\"win32\":" + g);
            string result = null;
            int gu = -1;
            try
            {
                result = ThreadProbe(Path.Combine(dir, thread), noFollow);
            }
            catch (Exception e)
            {
                result = "\"state\":\"unknown\",\"reason\":\"probe_exception\",\"exception\":" + J(e.GetType().Name + ": " + e.Message);
            }
            finally
            {
                // Released on every path, including exceptions from identity/serialization.
                gu = Unlock(guard, "rust");
            }
            if (gu != 0)
                return Ok("\"state\":\"unknown\",\"reason\":\"guard_unlock_failed\",\"win32\":" + gu + ",\"inner\":{" + result + "}");
            return Ok(result);
        }
    }

    static string ThreadProbe(string path, bool noFollow)
    {
        int err;
        using (var t = OpenRaw(path, "rwd", noFollow, out err))
        {
            if (t.IsInvalid)
                return err == 2 ? "\"state\":\"absent\"" : "\"state\":\"unknown\",\"reason\":\"thread_open\",\"win32\":" + err;
            if (noFollow && (IsReparse(t, out err) || (Attributes(t) & FILE_ATTRIBUTE_DIRECTORY) != 0))
                return "\"state\":\"unknown\",\"reason\":\"thread_not_regular\",\"win32\":" + err;
            int r = TryLock(t, "rust");
            if (r == ERROR_LOCK_VIOLATION) return "\"state\":\"held\"," + Identity(t);
            if (r != 0) return "\"state\":\"unknown\",\"reason\":\"thread_lock_error\",\"win32\":" + r;
            string id;
            try { id = Identity(t); }
            finally
            {
                int u = Unlock(t, "rust");
                // A probe lock we cannot release makes the observation unusable.
                if (u != 0) id = null;
                if (u != 0) err = u;
            }
            if (id == null) return "\"state\":\"unknown\",\"reason\":\"thread_unlock_failed\",\"win32\":" + err;
            return "\"state\":\"free\"," + id;
        }
    }

    static uint Attributes(SafeFileHandle h)
    {
        FILE_ATTRIBUTE_TAG_INFO tag;
        return GetFileInformationByHandleEx(h, 9, out tag, (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO)))
            ? tag.FileAttributes : uint.MaxValue;
    }

    public static string RmList(string[] files)
    {
        uint session;
        var key = new StringBuilder(64);
        int rc = RmStartSession(out session, 0, key);
        if (rc != 0) return Err(rc);
        try
        {
            rc = RmRegisterResources(session, (uint)files.Length, files, 0, IntPtr.Zero, 0, null);
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
            // The list can keep changing between calls; report that instead of guessing.
            if (rc != 0) return Ok("\"complete\":false,\"reason\":\"list_kept_growing\"");
            var b = new StringBuilder();
            for (int i = 0; i < count; i++)
            {
                var p = info[i];
                long start = ((long)(uint)p.Process.ProcessStartTime.dwHighDateTime << 32) | (uint)p.Process.ProcessStartTime.dwLowDateTime;
                if (i > 0) b.Append(',');
                b.Append("{\"pid\":").Append(p.Process.dwProcessId)
                    .Append(",\"startFiletime\":").Append(start)
                    .Append(",\"app\":").Append(J(p.strAppName))
                    .Append(",\"type\":").Append(p.ApplicationType)
                    .Append(",\"session\":").Append(p.TSSessionId).Append('}');
            }
            return Ok("\"complete\":true,\"processes\":[" + b + "]");
        }
        finally { RmEndSession(session); }
    }

    // Identity evidence through one process handle. expectedStart is the
    // creation FILETIME recorded earlier. A process object can outlive the
    // process (any open handle keeps it), so liveness comes from waiting on the
    // same handle; the exit code (STILL_ACTIVE = 259) is never used as proof.
    public static string ProcessIdentity(int pid, long expectedStart)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, pid);
        if (h == IntPtr.Zero) return Ok("\"state\":\"unknown\",\"reason\":\"open_process\",\"win32\":" + Marshal.GetLastWin32Error());
        try
        {
            uint w = WaitForSingleObject(h, 0);
            if (w == WAIT_OBJECT_0) return Ok("\"state\":\"exited\"");
            if (w != WAIT_TIMEOUT) return Ok("\"state\":\"unknown\",\"reason\":\"wait_failed\",\"wait\":" + w + ",\"win32\":" + Marshal.GetLastWin32Error());
            long create, exit, k, u;
            if (!GetProcessTimes(h, out create, out exit, out k, out u))
                return Ok("\"state\":\"unknown\",\"reason\":\"process_times\",\"win32\":" + Marshal.GetLastWin32Error());
            string sid = TokenSid(h);
            string self = WindowsIdentity.GetCurrent().User.Value;
            string state = create != expectedStart ? "identity_changed" : sid == null ? "unknown" : sid == self ? "live_same_user" : "other_user";
            // Re-check liveness on the same handle after collecting identity.
            uint w2 = WaitForSingleObject(h, 0);
            if (w2 == WAIT_OBJECT_0) state = "exited";
            else if (w2 != WAIT_TIMEOUT) state = "unknown";
            return Ok("\"state\":\"" + state + "\",\"createFiletime\":" + create + ",\"sid\":" + J(sid) + ",\"selfSid\":" + J(self));
        }
        finally { CloseHandle(h); }
    }

    static string TokenSid(IntPtr process)
    {
        IntPtr token;
        if (!OpenProcessToken(process, TOKEN_QUERY, out token)) return null;
        try
        {
            int needed;
            GetTokenInformation(token, 1, IntPtr.Zero, 0, out needed);
            if (needed <= 0) return null;
            IntPtr buf = Marshal.AllocHGlobal(needed);
            try
            {
                if (!GetTokenInformation(token, 1, buf, needed, out needed)) return null;
                return new SecurityIdentifier(Marshal.ReadIntPtr(buf)).Value;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        finally { CloseHandle(token); }
    }

    // Same source as ProcessIdentity (GetProcessTimes), avoiding DateTime
    // local-time round trips.
    public static long SelfStartFiletime()
    {
        long create, exit, k, u;
        return GetProcessTimes(Process.GetCurrentProcess().Handle, out create, out exit, out k, out u) ? create : -1;
    }

    // Directory identity without following reparse points; null when the path
    // is missing, unreadable, a reparse point, or not a directory.
    public static string DirFileId(string path)
    {
        using (var d = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero))
        {
            if (d.IsInvalid) return null;
            uint attrs = Attributes(d);
            if (attrs == uint.MaxValue || (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) return null;
            FILE_ID_INFO id;
            if (!GetFileIdInfo(d, 18, out id, (uint)Marshal.SizeOf(typeof(FILE_ID_INFO)))) return null;
            return id.VolumeSerialNumber.ToString("x16") + ":" + id.IdHigh.ToString("x16") + id.IdLow.ToString("x16");
        }
    }

    // Agents accept paths only under the validated scratch root. The check is
    // lexical after full-path normalization; it does not stop a reparse point
    // inside the root from redirecting elsewhere, so the orchestrator creates
    // only junctions whose targets are inside the root.
    static string Root;

    public static void SetRoot(string root)
    {
        string full = Path.GetFullPath(root).TrimEnd('\\');
        if (DirFileId(full) == null) throw new InvalidOperationException("scratch root is not a plain directory");
        Root = full;
    }

    static string Scoped(string path)
    {
        if (Root == null) throw new InvalidOperationException("scratch root not set");
        string full = Path.GetFullPath(path);
        if (!full.StartsWith(Root + "\\", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("path outside scratch root");
        return full;
    }

    static string Leaf(string name)
    {
        if (name.Length == 0 || name.IndexOfAny(new[] { '\\', '/', ':' }) >= 0 || name == "." || name == "..")
            throw new ArgumentException("thread name must be a leaf");
        return name;
    }

    // Called when stdin reaches EOF (parent gone) or on "exit".
    public static void DisposeAll()
    {
        foreach (var h in Handles.Values) h.Dispose();
        Handles.Clear();
    }

    // Line protocol for agent processes. One command in, exactly one JSON line out.
    public static string Execute(string line)
    {
        string[] a = line.Split(new[] { '\t' });
        try
        {
            switch (a[0])
            {
                case "create": // create <path> <bytes>: fixture-owned new file only
                {
                    int n = int.Parse(a[2]);
                    using (var h = CreateFileW(Scoped(a[1]), GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, CREATE_NEW, 0, IntPtr.Zero))
                    {
                        if (h.IsInvalid) return Err(Marshal.GetLastWin32Error());
                        using (var fs = new FileStream(h, FileAccess.ReadWrite)) fs.Write(new byte[n], 0, n);
                    }
                    return Ok(null);
                }
                case "open": // open <slot> <path> <share> <follow|nofollow>
                {
                    int err;
                    if (a[4] != "nofollow" && a[4] != "follow") return Err(87);
                    var h = OpenRaw(Scoped(a[2]), a[3], a[4] == "nofollow", out err);
                    if (h.IsInvalid) return Err(err);
                    Handles[a[1]] = h;
                    return Ok(Identity(h));
                }
                case "lock": // lock <slot> <range>
                {
                    int r = TryLock(Handles[a[1]], a[2]);
                    return r == 0 ? Ok("\"locked\":true") : r == ERROR_LOCK_VIOLATION ? Ok("\"locked\":false,\"win32\":33") : Err(r);
                }
                case "unlock":
                {
                    int r = Unlock(Handles[a[1]], a[2]);
                    return r == 0 ? Ok(null) : Err(r);
                }
                case "read": // read <slot> <n>
                {
                    int n = int.Parse(a[2]);
                    var buf = new byte[n];
                    uint got;
                    // A fresh handle reads from its own file pointer; reopen per test.
                    if (!ReadFile(Handles[a[1]], buf, (uint)n, out got, IntPtr.Zero)) return Err(Marshal.GetLastWin32Error());
                    return Ok("\"bytes\":" + got);
                }
                case "close":
                {
                    Handles[a[1]].Dispose();
                    Handles.Remove(a[1]);
                    return Ok(null);
                }
                case "delete": // delete <path>: DeleteFileW only, scratch paths only
                {
                    string target = Scoped(a[1]);
                    return DeleteFileW(target) ? Ok("\"existsAfter\":" + (File.Exists(target) ? "true" : "false")) : Err(Marshal.GetLastWin32Error());
                }
                case "probe": // probe <dir> <thread> <follow|nofollow>
                    return GuardProbe(Scoped(a[1]), Leaf(a[2]), a[3]);
                case "rm": // rm <path> [path...]
                {
                    var files = new string[a.Length - 1];
                    for (int i = 0; i < files.Length; i++) files[i] = Scoped(a[i + 1]);
                    return RmList(files);
                }
                case "procid": // procid <pid> <expectedStartFiletime>
                    return ProcessIdentity(int.Parse(a[1]), long.Parse(a[2]));
                default:
                    return Err(87);
            }
        }
        catch (Exception e)
        {
            return "{\"ok\":false,\"exception\":" + J(e.GetType().Name + ": " + e.Message) + "}";
        }
    }
}
