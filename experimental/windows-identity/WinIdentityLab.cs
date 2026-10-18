// Fixture-only Windows identity observations for codex-unlock research
// (W1 #146, W2 #147, W3 #148). Loaded by lab.ps1 through Add-Type (C# 5,
// Windows PowerShell 5.1). It only observes synthetic fixtures that it creates
// under a new private scratch directory. It never reads CODEX_HOME or a user
// Codex home, never changes the ACL or owner of an existing object, never
// enables a privilege, and never terminates or signals a process. Security
// descriptors are applied only at creation of new objects inside scratch.
// Classification lives in classify.mjs; every record carries
// safeToUnlock=false.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class WinIdentityLab
{
    const uint FILE_LIST_DIRECTORY = 0x1;
    const uint FILE_READ_ATTRIBUTES = 0x80;
    const uint DELETE = 0x00010000;
    const uint READ_CONTROL = 0x00020000;
    const uint GENERIC_READ = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, FILE_SHARE_DELETE = 4;
    const uint FILE_SHARE_ALL = 7;
    const uint OPEN_EXISTING = 3, CREATE_NEW = 1;
    const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
    const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const int FileStandardInfo = 1, FileDispositionInfo = 4, FileAttributeTagInfo = 9, FileIdInfo = 18;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, SYNCHRONIZE = 0x00100000;
    const uint TOKEN_QUERY = 0x0008;
    const uint WAIT_OBJECT_0 = 0, WAIT_TIMEOUT = 0x102;
    const int SE_FILE_OBJECT = 1;
    const uint OWNER_SECURITY_INFORMATION = 1, DACL_SECURITY_INFORMATION = 4;
    const uint SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE = 2;
    const int ProcessCommandLineInformation = 60;

    [StructLayout(LayoutKind.Sequential)]
    struct FILE_ATTRIBUTE_TAG_INFO { public uint FileAttributes; public uint ReparseTag; }

    // FILE_ID_128 is 16 bytes; IdLow holds bytes 0-7 and IdHigh bytes 8-15.
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

    // FILETIME members are 4-byte aligned pairs, so they are declared as uints.
    [StructLayout(LayoutKind.Sequential)]
    struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public uint CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh, FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh, FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }

    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr sa,
        uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    static extern SafeFileHandle CreateFileWithSecurity(string path, uint access, uint share, ref SECURITY_ATTRIBUTES sa,
        uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateDirectoryW")]
    static extern bool CreateDirectoryWithSecurity(string path, ref SECURITY_ATTRIBUTES sa);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateHardLinkW(string link, string existing, IntPtr sa);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    static extern bool CreateSymbolicLinkW(string link, string target, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool MoveFileExW(string from, string to, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle h, int cls, ref byte info, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int cls, out FILE_ATTRIBUTE_TAG_INFO info, uint size);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
    static extern bool GetFileIdInfo(SafeFileHandle h, int cls, out FILE_ID_INFO info, uint size);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetFileInformationByHandleEx")]
    static extern bool GetFileStandardInfo(SafeFileHandle h, int cls, out FILE_STANDARD_INFO info, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder buf, uint n, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool GetVolumeInformationByHandleW(SafeFileHandle h, StringBuilder volumeName, uint volumeSize,
        out uint serial, out uint maxComponent, out uint flags, StringBuilder fsName, uint fsSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint GetSecurityInfo(SafeFileHandle h, int objectType, uint info, out IntPtr owner,
        out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);

    [DllImport("advapi32.dll")]
    static extern uint GetSecurityDescriptorLength(IntPtr descriptor);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision,
        out IntPtr descriptor, IntPtr size);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr p);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint GetProcessId(IntPtr h);

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

    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationProcess(IntPtr h, int cls, IntPtr buf, int len, out int returned);

    // ---- JSON helpers (ASCII-only output) ---------------------------------

    static string J(string s)
    {
        if (s == null) return "null";
        var b = new StringBuilder("\"");
        foreach (char c in s)
        {
            if (c == '"' || c == '\\') b.Append('\\').Append(c);
            else if (c < 0x20 || c > 0x7e) b.AppendFormat("\\u{0:x4}", (int)c);
            else b.Append(c);
        }
        return b.Append('"').ToString();
    }

    static string B(bool v) { return v ? "true" : "false"; }

    static string Fail(string stage, int win32)
    {
        return "{\"ok\":false,\"stage\":" + J(stage) + ",\"win32\":" + win32 + "}";
    }

    static string Hex(ulong v)
    {
        var b = new StringBuilder();
        foreach (byte x in BitConverter.GetBytes(v)) b.Append(x.ToString("x2"));
        return b.ToString();
    }

    // ---- SID classes (no raw SIDs leave this process) ---------------------

    static SecurityIdentifier Self;
    static byte[] TagKey;

    static void InitIdentity()
    {
        if (Self != null) return;
        Self = WindowsIdentity.GetCurrent().User;
        TagKey = new byte[32];
        using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(TagKey);
    }

    // Per-run keyed tag: distinguishes principals within one run without
    // publishing their SIDs. Tags are not comparable across runs.
    static string Tag(string value)
    {
        using (var h = new HMACSHA256(TagKey))
        {
            byte[] d = h.ComputeHash(Encoding.UTF8.GetBytes(value));
            var b = new StringBuilder();
            for (int i = 0; i < 4; i++) b.Append(d[i].ToString("x2"));
            return b.ToString();
        }
    }

    static string SidClass(SecurityIdentifier sid)
    {
        if (sid == null) return null;
        if (sid.Equals(Self)) return "self";
        if (sid.IsWellKnown(WellKnownSidType.LocalSystemSid)) return "system";
        if (sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)) return "administrators";
        if (sid.IsWellKnown(WellKnownSidType.CreatorOwnerSid)) return "creator_owner";
        if (sid.Value == "S-1-3-4") return "owner_rights";
        if (sid.IsWellKnown(WellKnownSidType.WorldSid)) return "everyone";
        if (sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid)) return "authenticated_users";
        if (sid.IsWellKnown(WellKnownSidType.BuiltinUsersSid)) return "builtin_users";
        if (sid.Value.StartsWith("S-1-5-80-", StringComparison.Ordinal)) return "service:" + Tag(sid.Value);
        return "other:" + Tag(sid.Value);
    }

    // ---- Fault injection (synthetic; only for the lab's own checks) --------

    static readonly string[] Faults = { "during_file_cases", "after_child_launch", "during_child_observation",
        "child_abnormal_exit", "child_ignores_eof" };
    static string Fault;

    static void FaultPoint(string name)
    {
        if (Fault == name) throw new InvalidOperationException("fault injected: " + name);
    }

    // ---- W1: file identity through one no-follow handle --------------------

    // FILE_FLAG_OPEN_REPARSE_POINT applies to the last path component only.
    // Ancestors are traversed normally; their identity is not proven here.
    static SafeFileHandle OpenNoFollow(string path, out int err)
    {
        var h = CreateFileW(path, FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        err = h.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        return h;
    }

    static string FinalPath(SafeFileHandle h)
    {
        var buf = new StringBuilder(1024);
        uint n = GetFinalPathNameByHandleW(h, buf, (uint)buf.Capacity, 0);
        if (n == 0 || n >= buf.Capacity) return null;
        return buf.ToString();
    }

    static string NormalizeFinal(string final)
    {
        if (final == null) return null;
        if (final.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return @"\\" + final.Substring(8);
        if (final.StartsWith(@"\\?\", StringComparison.Ordinal)) return final.Substring(4);
        return final;
    }

    static string Filesystem(SafeFileHandle h)
    {
        var fs = new StringBuilder(64);
        uint serial, maxComponent, flags;
        if (!GetVolumeInformationByHandleW(h, null, 0, out serial, out maxComponent, out flags, fs, (uint)fs.Capacity)) return null;
        return fs.ToString();
    }

    static string IdentityOf(SafeFileHandle h)
    {
        FILE_ID_INFO id;
        if (!GetFileIdInfo(h, FileIdInfo, out id, (uint)Marshal.SizeOf(typeof(FILE_ID_INFO)))) return null;
        return id.VolumeSerialNumber.ToString("x16") + ":" + Hex(id.IdLow) + Hex(id.IdHigh);
    }

    static string IdentityAt(string path)
    {
        int err;
        using (var h = OpenNoFollow(path, out err)) return h.IsInvalid ? null : IdentityOf(h);
    }

    static string ObserveHandle(SafeFileHandle h, string requested)
    {
        FILE_ATTRIBUTE_TAG_INFO tag;
        if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, out tag, (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO))))
            return Fail("attribute_tag", Marshal.GetLastWin32Error());
        FILE_ID_INFO id;
        if (!GetFileIdInfo(h, FileIdInfo, out id, (uint)Marshal.SizeOf(typeof(FILE_ID_INFO))))
            return Fail("file_id", Marshal.GetLastWin32Error());
        FILE_STANDARD_INFO std;
        if (!GetFileStandardInfo(h, FileStandardInfo, out std, (uint)Marshal.SizeOf(typeof(FILE_STANDARD_INFO))))
            return Fail("standard_info", Marshal.GetLastWin32Error());
        string final = FinalPath(h);
        if (final == null) return Fail("final_path", Marshal.GetLastWin32Error());
        string fs = Filesystem(h);
        if (fs == null) return Fail("volume_information", Marshal.GetLastWin32Error());
        // Legacy identity is recorded for comparison only; ReFS can expose
        // 128-bit identifiers that do not fit the 64-bit index.
        BY_HANDLE_FILE_INFORMATION legacy;
        bool legacyOk = GetFileInformationByHandle(h, out legacy);
        string legacyIndex = legacyOk ? ((((ulong)legacy.FileIndexHigh) << 32) | legacy.FileIndexLow).ToString("x16") : null;
        return "{\"ok\":true,\"noFollow\":true" +
            ",\"requestedPath\":" + J(requested) +
            ",\"finalPath\":" + J(final) +
            ",\"attributes\":" + tag.FileAttributes +
            ",\"reparseTag\":" + tag.ReparseTag +
            ",\"volumeSerial\":" + J(id.VolumeSerialNumber.ToString("x16")) +
            ",\"fileId\":" + J(Hex(id.IdLow) + Hex(id.IdHigh)) +
            ",\"links\":" + std.NumberOfLinks +
            ",\"deletePending\":" + B(std.DeletePending) +
            ",\"directory\":" + B(std.Directory) +
            ",\"filesystem\":" + J(fs) +
            ",\"legacyIndex\":" + J(legacyIndex) +
            ",\"legacyVolumeSerial\":" + (legacyOk ? J(legacy.VolumeSerialNumber.ToString("x8")) : "null") + "}";
    }

    public static string ObservePath(string path)
    {
        int err;
        using (var h = OpenNoFollow(path, out err))
        {
            if (h.IsInvalid) return Fail("open", err);
            return ObserveHandle(h, path);
        }
    }

    static readonly Dictionary<string, SafeFileHandle> Held = new Dictionary<string, SafeFileHandle>();
    static readonly Dictionary<string, string> HeldPath = new Dictionary<string, string>();

    static string Hold(string label, string path)
    {
        int err;
        var h = OpenNoFollow(path, out err);
        if (h.IsInvalid) { h.Dispose(); return Fail("open", err); }
        Held[label] = h;
        HeldPath[label] = path;
        return ObserveHandle(h, path);
    }

    // Same handle, observed again against the path it was opened with.
    static string ObserveHeld(string label)
    {
        if (!Held.ContainsKey(label)) return Fail("held_missing", 0);
        return ObserveHandle(Held[label], HeldPath[label]);
    }

    // ---- W2: owner and DACL through GetSecurityInfo on a no-follow handle --

    public static string ObserveSecurity(string path)
    {
        InitIdentity();
        int err;
        using (var h = OpenNoFollow(path, out err))
        {
            if (h.IsInvalid) return Fail("open", err);
            FILE_ATTRIBUTE_TAG_INFO tag;
            if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, out tag, (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO))))
                return Fail("attribute_tag", Marshal.GetLastWin32Error());
            IntPtr owner, group, dacl, sacl, sd;
            uint rc = GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                out owner, out group, out dacl, out sacl, out sd);
            if (rc != 0) return Fail("security_info", (int)rc);
            byte[] bytes;
            try
            {
                uint len = GetSecurityDescriptorLength(sd);
                bytes = new byte[len];
                Marshal.Copy(sd, bytes, 0, (int)len);
            }
            finally { LocalFree(sd); }
            RawSecurityDescriptor raw;
            try { raw = new RawSecurityDescriptor(bytes, 0); }
            catch (ArgumentException) { return Fail("security_parse", 0); }
            // "present": a DACL with ACEs; "null": DACL flag set with no ACL
            // (everyone has access); "absent": no DACL flag at all.
            bool flag = (raw.ControlFlags & ControlFlags.DiscretionaryAclPresent) != 0;
            string daclState = !flag ? "absent" : raw.DiscretionaryAcl == null ? "null" : "present";
            bool isProtected = (raw.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0;
            var aces = new StringBuilder();
            if (daclState == "present")
            {
                aces.Append('[');
                bool first = true;
                foreach (GenericAce ace in raw.DiscretionaryAcl)
                {
                    if (!first) aces.Append(',');
                    first = false;
                    var common = ace as CommonAce;
                    string type = "other";
                    string sidClass = "unparsed";
                    long mask = 0;
                    if (common != null && !common.IsCallback)
                    {
                        if (common.AceQualifier == AceQualifier.AccessAllowed) type = "allow";
                        else if (common.AceQualifier == AceQualifier.AccessDenied) type = "deny";
                        sidClass = SidClass(common.SecurityIdentifier);
                        mask = (long)(uint)common.AccessMask;
                    }
                    aces.Append("{\"type\":" + J(type) + ",\"sidClass\":" + J(sidClass) + ",\"mask\":" + mask +
                        ",\"flags\":" + (int)ace.AceFlags +
                        ",\"inherited\":" + B((ace.AceFlags & AceFlags.Inherited) != 0) +
                        ",\"inheritOnly\":" + B((ace.AceFlags & AceFlags.InheritOnly) != 0) + "}");
                }
                aces.Append(']');
            }
            return "{\"ok\":true,\"noFollow\":true" +
                ",\"attributes\":" + tag.FileAttributes +
                ",\"reparseTag\":" + tag.ReparseTag +
                ",\"tokenUserClass\":" + J(SidClass(Self)) +
                ",\"tokenOwnerClass\":" + J(SidClass(WindowsIdentity.GetCurrent().Owner)) +
                ",\"ownerClass\":" + J(SidClass(raw.Owner)) +
                ",\"daclState\":" + J(daclState) +
                ",\"daclProtected\":" + B(isProtected) +
                ",\"aces\":" + (daclState == "present" ? aces.ToString() : "null") + "}";
        }
    }

    // ---- W3: process identity through one handle ---------------------------

    static string ProcessSid(IntPtr process)
    {
        IntPtr token;
        if (!OpenProcessToken(process, TOKEN_QUERY, out token)) return null;
        try { return SidClass(TokenSid(token, 1)); }
        finally { CloseHandle(token); }
    }

    // TokenUser (1) and TokenIntegrityLevel (25) both start with a SID pointer.
    static SecurityIdentifier TokenSid(IntPtr token, int cls)
    {
        int needed;
        GetTokenInformation(token, cls, IntPtr.Zero, 0, out needed);
        if (needed <= 0) return null;
        IntPtr buf = Marshal.AllocHGlobal(needed);
        try
        {
            if (!GetTokenInformation(token, cls, buf, needed, out needed)) return null;
            return new SecurityIdentifier(Marshal.ReadIntPtr(buf));
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    static string ImageBase(IntPtr process)
    {
        var buf = new StringBuilder(1024);
        uint size = (uint)buf.Capacity;
        if (!QueryFullProcessImageNameW(process, 0, buf, ref size)) return null;
        return Path.GetFileName(buf.ToString());
    }

    // Flattened command line (Windows 8.1+). The UNICODE_STRING header and the
    // string bytes must both lie inside the buffer that was actually returned.
    // Raw records stay local; see README.
    static string CommandLine(IntPtr process)
    {
        int needed;
        NtQueryInformationProcess(process, ProcessCommandLineInformation, IntPtr.Zero, 0, out needed);
        int header = Marshal.SizeOf(typeof(UNICODE_STRING));
        if (needed < header || needed > 1 << 20) return null;
        IntPtr buf = Marshal.AllocHGlobal(needed);
        try
        {
            int returned;
            if (NtQueryInformationProcess(process, ProcessCommandLineInformation, buf, needed, out returned) != 0) return null;
            if (returned < header || returned > needed) return null;
            var us = (UNICODE_STRING)Marshal.PtrToStructure(buf, typeof(UNICODE_STRING));
            if (us.Length == 0) return "";
            if (us.Buffer == IntPtr.Zero || (us.Length & 1) != 0 || us.Length > us.MaximumLength) return null;
            long start = buf.ToInt64(), end = start + returned, text = us.Buffer.ToInt64();
            if (text < start + header || text + us.Length > end) return null;
            return Marshal.PtrToStringUni(us.Buffer, us.Length / 2);
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    static string WaitName(uint w)
    {
        if (w == WAIT_OBJECT_0) return "signaled";
        if (w == WAIT_TIMEOUT) return "timeout";
        return "failed";
    }

    // source is "held" (a handle opened earlier and kept) or "fresh_open".
    static string ObserveProcessHandle(IntPtr h, string source)
    {
        InitIdentity();
        uint pid = GetProcessId(h);
        int pidErr = pid == 0 ? Marshal.GetLastWin32Error() : 0;
        string wait = WaitName(WaitForSingleObject(h, 0));
        long create, exit, k, u;
        bool timesOk = GetProcessTimes(h, out create, out exit, out k, out u);
        int timesErr = timesOk ? 0 : Marshal.GetLastWin32Error();
        string sid = ProcessSid(h);
        string image = ImageBase(h);
        string commandLine = CommandLine(h);
        // Liveness is checked again on the same handle after identity collection.
        string waitAfter = WaitName(WaitForSingleObject(h, 0));
        return "{\"ok\":true,\"handleSource\":" + J(source) +
            ",\"pid\":" + (pid == 0 ? "null" : pid.ToString()) +
            ",\"pidWin32\":" + pidErr +
            ",\"wait\":" + J(wait) +
            ",\"createFiletime\":" + (timesOk ? J(create.ToString()) : "null") +
            ",\"timesWin32\":" + timesErr +
            ",\"sidClass\":" + J(sid) +
            ",\"imageBase\":" + J(image) +
            ",\"commandLine\":" + J(commandLine) +
            ",\"waitAfter\":" + J(waitAfter) + "}";
    }

    public static string ObserveProcessPid(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, pid);
        if (h == IntPtr.Zero) return Fail("open_process", Marshal.GetLastWin32Error());
        try { return ObserveProcessHandle(h, "fresh_open"); }
        finally { CloseHandle(h); }
    }

    static string Filetime(IntPtr h)
    {
        long create, exit, k, u;
        return GetProcessTimes(h, out create, out exit, out k, out u) ? create.ToString() : null;
    }

    // ---- Child processes: registered immediately, never terminated ---------

    sealed class Child
    {
        public string Label;
        public Process P;
        public int Pid;
        public string Start;
        public IntPtr Probe = IntPtr.Zero;
        public bool StdinOpen;
        public bool Confirmed;
        public bool Finished;
        public int ExitCode = int.MinValue;
    }

    static readonly List<Child> Children = new List<Child>();
    static int ChildWaitBudgetMs = 15000;

    public static int ChildrenStillRunning
    {
        get
        {
            int n = 0;
            foreach (var c in Children) if (!c.Confirmed) n++;
            return n;
        }
    }

    // The child is registered before anything else can fail. Identity comes
    // from the creation handle kept by Process; the probe handle is a separate
    // limited handle opened like a real prober would.
    static Child Launch(string label, string args, bool stdin)
    {
        var psi = new ProcessStartInfo(Path.Combine(System.Environment.SystemDirectory, "cmd.exe"), args);
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.RedirectStandardInput = stdin;
        psi.RedirectStandardOutput = true;
        // Not the scratch root: a working directory handle would pin it.
        psi.WorkingDirectory = System.Environment.SystemDirectory;
        var c = new Child();
        c.Label = label;
        c.P = Process.Start(psi);
        Children.Add(c);
        c.StdinOpen = stdin;
        c.Pid = c.P.Id;
        c.P.StandardOutput.ReadToEndAsync();
        c.Start = Filetime(c.P.Handle);
        c.Probe = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, c.Pid);
        return c;
    }

    static void SendEof(Child c, string lastLine)
    {
        if (!c.StdinOpen) return;
        c.StdinOpen = false;
        try
        {
            if (lastLine != null) c.P.StandardInput.WriteLine(lastLine);
            c.P.StandardInput.Close();
        }
        catch (IOException) { }
        catch (InvalidOperationException) { }
    }

    static bool WaitExit(Child c, int budgetMs)
    {
        if (c.Confirmed) return true;
        try
        {
            if (c.P.WaitForExit(Math.Max(0, budgetMs)))
            {
                c.Confirmed = true;
                c.ExitCode = c.P.ExitCode;
            }
        }
        catch (InvalidOperationException) { }
        catch (Win32Exception) { }
        return c.Confirmed;
    }

    static void Finish(Child c)
    {
        if (c.Finished) return;
        if (c.Probe != IntPtr.Zero) { CloseHandle(c.Probe); c.Probe = IntPtr.Zero; }
        if (c.Confirmed) { c.P.Dispose(); c.Finished = true; }
    }

    // EOF, bounded wait, handle cleanup. Unconfirmed children stay registered
    // so that cleanup preserves the scratch directory.
    static void ReleaseAll()
    {
        foreach (var c in Children)
        {
            SendEof(c, null);
            WaitExit(c, ChildWaitBudgetMs);
            Finish(c);
        }
    }

    // ---- Scratch root, registry and creation -------------------------------

    sealed class Entry
    {
        public string Kind; // dir, file, dirlink, filelink
        public string Path;
        public string Identity;
    }

    static string Root;
    static string RootIdentity;
    static SafeFileHandle RootHold;
    static string ScratchAttemptPath;
    static string ScratchAttemptIdentity;
    static readonly List<Entry> Created = new List<Entry>();
    public static bool CleanupOk;

    static string Sddl(string body)
    {
        return "O:" + Self.Value + body;
    }

    static int WithSecurity(string sddl, Func<SECURITY_ATTRIBUTES, bool> create)
    {
        IntPtr sd;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, IntPtr.Zero)) return Marshal.GetLastWin32Error();
        try
        {
            var sa = new SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            sa.lpSecurityDescriptor = sd;
            return create(sa) ? 0 : Marshal.GetLastWin32Error();
        }
        finally { LocalFree(sd); }
    }

    static Entry Register(List<Entry> list, string kind, string path)
    {
        var e = new Entry();
        e.Kind = kind;
        e.Path = path;
        e.Identity = IdentityAt(path);
        list.Add(e);
        return e;
    }

    // Creation-time security descriptor on a new object only. A descriptor
    // without a DACL section inherits the parent's inheritable ACEs.
    static int CreateDirRaw(string path, string sddl)
    {
        return WithSecurity(sddl, delegate (SECURITY_ATTRIBUTES sa) { return CreateDirectoryWithSecurity(path, ref sa); });
    }

    static int CreateDir(string path, string sddl)
    {
        int rc = CreateDirRaw(path, sddl);
        if (rc == 0) Register(Created, "dir", path);
        return rc;
    }

    static int CreateFile(string path, string sddl)
    {
        int rc;
        if (sddl == null)
        {
            using (var h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero))
                rc = h.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        }
        else
        {
            rc = WithSecurity(sddl, delegate (SECURITY_ATTRIBUTES sa)
            {
                using (var h = CreateFileWithSecurity(path, GENERIC_READ | GENERIC_WRITE, 0, ref sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero))
                    return !h.IsInvalid;
            });
        }
        if (rc == 0) Register(Created, "file", path);
        return rc;
    }

    // Updates the registry for the renamed object and every descendant.
    static int Rename(string from, string to)
    {
        if (!MoveFileExW(from, to, 0)) return Marshal.GetLastWin32Error();
        foreach (var e in Created)
        {
            if (string.Equals(e.Path, from, StringComparison.OrdinalIgnoreCase)) e.Path = to;
            else if (e.Path.StartsWith(from + "\\", StringComparison.OrdinalIgnoreCase)) e.Path = to + e.Path.Substring(from.Length);
        }
        return 0;
    }

    static SafeFileHandle OpenDirectoryHold(string path, out int err)
    {
        // Data access (FILE_LIST_DIRECTORY) plus DELETE without FILE_SHARE_DELETE:
        // another open asking for DELETE (rename or delete) conflicts with it.
        var h = CreateFileW(path, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        err = h.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        return h;
    }

    // Held for the whole run: data access without FILE_SHARE_DELETE blocks
    // another open that asks for DELETE (rename or delete of the root). It has
    // no DELETE access itself, so it does not block the suite's own work.
    static SafeFileHandle OpenRootHold(string path, out int err)
    {
        var h = CreateFileW(path, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        err = h.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        return h;
    }

    static SafeFileHandle OpenLeafForDelete(string path, out int err)
    {
        var h = CreateFileW(path, FILE_READ_ATTRIBUTES | DELETE, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        err = h.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        return h;
    }

    // Creates %TEMP%\codex-win-identity-<random> owned by the current user with
    // a protected single-ACE DACL (current user, full control, inheritable),
    // then holds it with OpenRootHold for the whole run. Returns the final
    // (long-name) path, or null when verification fails; in that case no
    // fixture exists and the directory, if created, is preserved.
    public static string CreateScratch()
    {
        InitIdentity();
        if (Root != null) throw new InvalidOperationException("scratch already created");
        byte[] r = new byte[8];
        using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(r);
        string path = Path.Combine(Path.GetTempPath(), "codex-win-identity-" + BitConverter.ToString(r).Replace("-", "").ToLowerInvariant());
        if (CreateDirRaw(path, Sddl("D:P(A;OICI;FA;;;" + Self.Value + ")")) != 0) return null;
        ScratchAttemptPath = path;
        int err;
        var h = OpenRootHold(path, out err);
        if (h.IsInvalid) { h.Dispose(); return null; }
        bool retained = false;
        try
        {
        FILE_ATTRIBUTE_TAG_INFO tag;
        string final = NormalizeFinal(FinalPath(h));
        string identity = IdentityOf(h);
        ScratchAttemptIdentity = identity;
        if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, out tag, (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO))) ||
            (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            tag.ReparseTag != 0 || final == null || identity == null)
        {
            h.Dispose();
            return null;
        }
        string sec = ObserveSecurity(final);
        string expected = "\"ownerClass\":\"self\",\"daclState\":\"present\",\"daclProtected\":true,\"aces\":[{\"type\":\"allow\",\"sidClass\":\"self\",\"mask\":2032127,\"flags\":3,\"inherited\":false,\"inheritOnly\":false}]}";
        if (!sec.EndsWith(expected, StringComparison.Ordinal))
        {
            h.Dispose();
            return null;
        }
        RootHold = h;
        RootIdentity = identity;
        Root = final;
        retained = true;
        return Root;
        }
        finally { if (!retained) h.Dispose(); }
    }

    static string P(params string[] parts)
    {
        return Root + "\\" + string.Join("\\", parts);
    }

    // ---- Guarded deletion ----------------------------------------------------

    // Verifies the root and every entry before deleting anything: identity,
    // type, reparse state, final path, and that each entry's parent is the
    // root or an earlier verified directory. Directories stay held without
    // FILE_SHARE_DELETE during the whole operation; objects are deleted
    // through the verified handle (FileDispositionInfo), never by path. This
    // narrows but does not eliminate races (privileged principals, handles
    // held by other software); any failure deletes nothing further and
    // preserves the rest. Returns null on success, otherwise a reason.
    static string GuardedDelete(SafeFileHandle rootHandle, string rootPath, string rootIdentity, List<Entry> entries, out int removed)
    {
        removed = 0;
        var handles = new List<SafeFileHandle>();
        var dirs = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        string reason = null;
        try
        {
            int err;
            if (rootHandle == null) rootHandle = OpenDirectoryHold(rootPath, out err);
            if (rootHandle.IsInvalid) return "root_open_failed";
            if (rootIdentity == null || IdentityOf(rootHandle) != rootIdentity) return "root_identity_changed";
            if (!string.Equals(NormalizeFinal(FinalPath(rootHandle)), rootPath, StringComparison.OrdinalIgnoreCase)) return "root_path_changed";
            FILE_ATTRIBUTE_TAG_INFO tag;
            if (!GetFileInformationByHandleEx(rootHandle, FileAttributeTagInfo, out tag, (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO))) ||
                (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                return "root_type_changed";
            dirs[rootPath] = true;
            foreach (var e in entries)
            {
                int cut = e.Path.LastIndexOf('\\');
                if (cut <= 0 || !dirs.ContainsKey(e.Path.Substring(0, cut))) { reason = "ancestor_unverified:" + e.Kind; break; }
                var h = e.Kind == "dir" ? OpenDirectoryHold(e.Path, out err) : OpenLeafForDelete(e.Path, out err);
                handles.Add(h);
                if (h.IsInvalid) { reason = "entry_open_failed:" + err; break; }
                if (e.Identity == null || IdentityOf(h) != e.Identity) { reason = "entry_identity_changed:" + e.Kind; break; }
                if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, out tag, (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO))))
                { reason = "entry_attributes_failed"; break; }
                bool isDir = (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                bool isLink = (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                bool wantDir = e.Kind == "dir" || e.Kind == "dirlink";
                bool wantLink = e.Kind == "dirlink" || e.Kind == "filelink";
                if (isDir != wantDir || isLink != wantLink) { reason = "entry_type_changed:" + e.Kind; break; }
                if (!string.Equals(NormalizeFinal(FinalPath(h)), e.Path, StringComparison.OrdinalIgnoreCase))
                { reason = "entry_path_changed:" + e.Kind; break; }
                if (e.Kind == "dir") dirs[e.Path] = true;
            }
            if (reason != null) return reason;
            byte yes = 1;
            for (int i = handles.Count - 1; i >= 0; i--)
            {
                if (!SetFileInformationByHandle(handles[i], FileDispositionInfo, ref yes, 1))
                    return "delete_failed:" + entries[i].Kind + ":" + Marshal.GetLastWin32Error();
                handles[i].Dispose();
                removed++;
            }
            if (!SetFileInformationByHandle(rootHandle, FileDispositionInfo, ref yes, 1))
                return "root_delete_failed:" + Marshal.GetLastWin32Error();
            rootHandle.Dispose();
            removed++;
            return null;
        }
        finally
        {
            foreach (var h in handles) h.Dispose();
            if (rootHandle != null) rootHandle.Dispose();
        }
    }

    // ---- Suite --------------------------------------------------------------

    static List<string> Out = new List<string>();

    static void Emit(string kind, string name, string track, string body)
    {
        Out.Add("{\"kind\":" + J(kind) + ",\"case\":" + J(name) + ",\"track\":" + J(track) +
            (string.IsNullOrEmpty(body) ? "" : "," + body) + ",\"safeToUnlock\":false}");
    }

    static string Expect(string state, string reason)
    {
        return "\"expect\":{\"state\":" + J(state) + (reason == null ? "" : ",\"reason\":" + J(reason)) + "}";
    }

    static bool Setup(string name, int rc)
    {
        Emit("setup", name, "setup", "\"ok\":" + B(rc == 0) + ",\"win32\":" + rc);
        return rc == 0;
    }

    static string Win32Message(int code)
    {
        return new Win32Exception(code).Message;
    }

    // Partial evidence for the caller when an exception escapes RunSuite.
    public static string[] Partial() { return Out.ToArray(); }

    public static string[] RunSuite(int waitBudgetMs, int reuseAttempts, int reuseBudgetMs, string fault)
    {
        if (Root == null) throw new InvalidOperationException("scratch root not set");
        if (fault == "") fault = null;
        if (fault != null && Array.IndexOf(Faults, fault) < 0) throw new ArgumentException("unknown fault");
        Fault = fault;
        ChildWaitBudgetMs = fault == "child_ignores_eof" ? Math.Min(waitBudgetMs, 2000) : waitBudgetMs;
        Out = new List<string>();
        try
        {
            EmitEnvironment(waitBudgetMs, reuseAttempts, reuseBudgetMs);
            FileIdentityCases();
            SecurityCases();
            ProcessCases(reuseAttempts, reuseBudgetMs);
            CleanupProbes();
        }
        catch (Exception e)
        {
            Emit("suite_error", "suite_error", "setup", "\"fault\":" + J(Fault) + ",\"message\":" + J(e.GetType().Name + ": " + e.Message));
        }
        finally { ReleaseAll(); }
        int emitted = Out.Count;
        Emit("suite_end", "suite_end", "setup", "\"emitted\":" + emitted);
        return Out.ToArray();
    }

    static void EmitEnvironment(int waitBudgetMs, int reuseAttempts, int reuseBudgetMs)
    {
        string integrity = null;
        IntPtr token;
        if (OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_QUERY, out token))
        {
            try
            {
                var label = TokenSid(token, 25);
                if (label != null)
                {
                    string[] parts = label.Value.Split('-');
                    integrity = parts[parts.Length - 1];
                }
            }
            finally { CloseHandle(token); }
        }
        Emit("environment", "environment", "env",
            "\"os\":" + J(System.Environment.OSVersion.VersionString) +
            ",\"clr\":" + J(System.Environment.Version.ToString()) +
            ",\"is64BitProcess\":" + B(System.Environment.Is64BitProcess) +
            ",\"filesystem\":" + J(Filesystem(RootHold)) +
            ",\"integrityRid\":" + J(integrity) +
            ",\"tokenOwnerClass\":" + J(SidClass(WindowsIdentity.GetCurrent().Owner)) +
            ",\"fault\":" + J(Fault) +
            ",\"budgets\":{\"waitMs\":" + waitBudgetMs + ",\"childWaitMs\":" + ChildWaitBudgetMs +
            ",\"reuseAttempts\":" + reuseAttempts + ",\"reuseMs\":" + reuseBudgetMs + "}");
    }

    const string ThreadId = "00000000-0000-4000-8000-000000000001";

    static int Mklink(string link, string target)
    {
        Child c = Launch("mklink", "/d /c mklink /J \"" + link + "\" \"" + target + "\"", false);
        WaitExit(c, ChildWaitBudgetMs);
        Finish(c);
        if (!c.Confirmed) return -1;
        if (c.ExitCode != 0) return c.ExitCode;
        Register(Created, "dirlink", link);
        return 0;
    }

    static void FileIdentityCases()
    {
        string home = P("home"), locks = P("home", "thread-writer-locks"), sessions = P("home", "sessions");
        string coord = P("home", "thread-writer-locks", ".coordination.lock");
        string thread = P("home", "thread-writer-locks", ThreadId + ".lock");
        string transcript = P("home", "sessions", "rollout-" + ThreadId + ".jsonl");
        // Owner-only descriptors: owner is the current user, DACL is inherited.
        string ownerOnly = Sddl("");
        if (!Setup("create:home", CreateDir(home, ownerOnly))) return;
        if (!Setup("create:locks", CreateDir(locks, ownerOnly))) return;
        if (!Setup("create:sessions", CreateDir(sessions, ownerOnly))) return;
        if (!Setup("create:coordination", CreateFile(coord, ownerOnly))) return;
        if (!Setup("create:thread", CreateFile(thread, ownerOnly))) return;
        if (!Setup("create:transcript", CreateFile(transcript, ownerOnly))) return;

        string[][] shaped = new string[][] {
            new string[] { "home", home, "directory" }, new string[] { "lock_dir", locks, "directory" },
            new string[] { "coordination", coord, "file" }, new string[] { "thread_lock", thread, "file" },
            new string[] { "transcript", transcript, "file" } };
        foreach (var s in shaped)
            Emit("file", "file:" + s[0], "W1", "\"expectKind\":" + J(s[2]) + ",\"obs\":" + ObservePath(s[1]) + "," + Expect("match", null));
        FaultPoint("during_file_cases");

        string a = Hold("thread", thread);
        string b = ObserveHeld("thread");
        Emit("file_compare", "same_handle:before_after", "W1", "\"expectKind\":\"file\",\"before\":" + a + ",\"after\":" + b + "," + Expect("match", null));

        string upper = locks + "\\" + (ThreadId + ".lock").ToUpperInvariant();
        Emit("file_compare", "case_variant:path", "W1", "\"expectKind\":\"file\",\"before\":" + a + ",\"after\":" + ObservePath(upper) + "," + Expect("match", null));

        // Path replacement between observations while the first handle stays open.
        string victim = P("home", "thread-writer-locks", "replaced.lock");
        if (!Setup("create:replaced", CreateFile(victim, ownerOnly))) return;
        string before = Hold("victim", victim);
        if (!Setup("rename:replaced", Rename(victim, victim + ".old"))) return;
        if (!Setup("create:replacement", CreateFile(victim, ownerOnly))) return;
        Emit("file_compare", "path_replacement:file", "W1", "\"expectKind\":\"file\",\"before\":" + before + ",\"after\":" + ObservePath(victim) + "," + Expect("unknown", "identity_changed"));
        Emit("file", "path_replacement:same_handle", "W1", "\"expectKind\":\"file\",\"obs\":" + ObserveHeld("victim") + "," + Expect("unknown", "path_handle_mismatch"));

        // Parent-directory replacement between observations.
        string parent = P("home", "replaced-dir");
        if (!Setup("create:replaced_dir", CreateDir(parent, ownerOnly))) return;
        string beforeDir = Hold("parent", parent);
        if (!Setup("rename:replaced_dir", Rename(parent, parent + ".old"))) return;
        if (!Setup("create:replacement_dir", CreateDir(parent, ownerOnly))) return;
        Emit("file_compare", "parent_replacement:dir", "W1", "\"expectKind\":\"directory\",\"before\":" + beforeDir + ",\"after\":" + ObservePath(parent) + "," + Expect("unknown", "identity_changed"));

        // Hard link: both names report two links.
        string linked = P("home", "thread-writer-locks", "linked.lock");
        string alias = P("home", "thread-writer-locks", "linked-alias.lock");
        if (!Setup("create:linked", CreateFile(linked, ownerOnly))) return;
        int rc = CreateHardLinkW(alias, linked, IntPtr.Zero) ? 0 : Marshal.GetLastWin32Error();
        if (rc == 0) Register(Created, "file", alias);
        if (!Setup("create:hard_link", rc)) return;
        Emit("file", "hard_link:target", "W1", "\"expectKind\":\"file\",\"obs\":" + ObservePath(linked) + "," + Expect("unknown", "hard_link"));
        Emit("file", "hard_link:alias", "W1", "\"expectKind\":\"file\",\"obs\":" + ObservePath(alias) + "," + Expect("unknown", "hard_link"));

        // Junction (directory reparse point) opened without following it.
        string target = P("home", "junction-target"), junction = P("home", "junction-link");
        if (!Setup("create:junction_target", CreateDir(target, ownerOnly))) return;
        if (!Setup("create:junction", Mklink(junction, target))) return;
        Emit("file", "junction:nofollow", "W1", "\"expectKind\":\"directory\",\"obs\":" + ObservePath(junction) + "," + Expect("unknown", "reparse_point"));
        Emit("security", "sec:junction", "W2", "\"obs\":" + ObserveSecurity(junction) + "," + Expect("unknown", "reparse_point"));

        // File symbolic link: unprivileged creation needs Developer Mode or the
        // symlink privilege already present; no privilege is enabled here.
        string symlink = P("home", "thread-writer-locks", "symlink.lock");
        if (CreateSymbolicLinkW(symlink, thread, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE))
        {
            Register(Created, "filelink", symlink);
            Emit("file", "symlink:file", "W1", "\"expectKind\":\"file\",\"obs\":" + ObservePath(symlink) + "," + Expect("unknown", "reparse_point"));
        }
        else
        {
            int code = Marshal.GetLastWin32Error();
            Emit("skipped", "symlink:file", "W1", "\"win32\":" + code + ",\"message\":" + J(Win32Message(code)));
        }

        Emit("file", "missing:path", "W1", "\"expectKind\":\"file\",\"obs\":" + ObservePath(P("home", "thread-writer-locks", "absent.lock")) + "," + Expect("unknown", "open_failed"));
    }

    static void SecurityCases()
    {
        string self = Self.Value;
        Emit("security", "sec:scratch_root", "W2", "\"obs\":" + ObserveSecurity(Root) + "," + Expect("match", null));
        string[][] shaped = new string[][] {
            new string[] { "home", P("home") }, new string[] { "lock_dir", P("home", "thread-writer-locks") },
            new string[] { "coordination", P("home", "thread-writer-locks", ".coordination.lock") },
            new string[] { "thread_lock", P("home", "thread-writer-locks", ThreadId + ".lock") },
            new string[] { "transcript", P("home", "sessions", "rollout-" + ThreadId + ".jsonl") } };
        foreach (var s in shaped)
            Emit("security", "sec:" + s[0], "W2", "\"obs\":" + ObserveSecurity(s[1]) + "," + Expect("match", null));

        if (!Setup("create:sec", CreateDir(P("sec"), Sddl("")))) return;

        // Default owner comes from the token. An elevated administrator token
        // usually defaults to the Administrators group, which must be refused.
        string defaultOwner = P("sec", "default-owner.lock");
        if (!Setup("create:default_owner", CreateFile(defaultOwner, null))) return;
        string tokenOwner = SidClass(WindowsIdentity.GetCurrent().Owner);
        Emit("security", "sec:default_owner", "W2", "\"obs\":" + ObserveSecurity(defaultOwner) + "," +
            (tokenOwner == "self" ? Expect("match", null) : Expect("refuse", "owner_not_current_user")));

        // Owner set to Administrators at creation; only possible when the token
        // already carries Administrators as an assignable owner.
        string adminOwned = P("sec", "administrators-owner.lock");
        int adminRc = CreateFile(adminOwned, "O:BA");
        if (adminRc == 0)
            Emit("security", "sec:owner_administrators", "W2", "\"obs\":" + ObserveSecurity(adminOwned) + "," + Expect("refuse", "owner_not_current_user"));
        else
            Emit("skipped", "sec:owner_administrators", "W2", "\"win32\":" + adminRc + ",\"message\":" + J(Win32Message(adminRc)));

        // The deny case names ANONYMOUS LOGON, which an ordinary interactive or
        // service token does not contain, so the observer's own open is not
        // affected by it (an assumption recorded in the README).
        string[][] cases = new string[][] {
            new string[] { "other_writer_explicit", "D:P(A;;FA;;;" + self + ")(A;;FW;;;BU)", "refuse", "other_writer" },
            new string[] { "other_reader_only", "D:P(A;;FA;;;" + self + ")(A;;FR;;;BU)", "match", null },
            new string[] { "deny_other", "D:P(D;;FA;;;AN)(A;;FA;;;" + self + ")", "match", null },
            new string[] { "privileged_writers", "D:P(A;;FA;;;" + self + ")(A;;FA;;;BA)(A;;FA;;;SY)", "match", null },
            new string[] { "null_dacl", "D:NO_ACCESS_CONTROL", "refuse", "null_dacl" } };
        foreach (var c in cases)
        {
            string path = P("sec", c[0] + ".lock");
            if (!Setup("create:" + c[0], CreateFile(path, Sddl(c[1])))) return;
            Emit("security", "sec:" + c[0], "W2", "\"obs\":" + ObserveSecurity(path) + "," + Expect(c[2], c[3]));
        }

        // Inherited write access for Everyone through a parent directory.
        string inherit = P("sec", "inherit-everyone");
        if (!Setup("create:inherit_everyone", CreateDir(inherit, Sddl("D:P(A;OICI;FA;;;" + self + ")(A;OICI;FW;;;WD)")))) return;
        Emit("security", "sec:inherit_everyone_dir", "W2", "\"obs\":" + ObserveSecurity(inherit) + "," + Expect("refuse", "other_writer"));
        string child = P("sec", "inherit-everyone", "child.lock");
        if (!Setup("create:inherit_everyone_child", CreateFile(child, Sddl("")))) return;
        Emit("security", "sec:inherit_everyone_file", "W2", "\"obs\":" + ObserveSecurity(child) + "," + Expect("refuse", "other_writer"));

        Emit("security", "sec:missing", "W2", "\"obs\":" + ObserveSecurity(P("sec", "absent.lock")) + "," + Expect("unknown", "open_failed"));
    }

    static string Recorded(int pid, string start)
    {
        return "\"recorded\":{\"pid\":" + pid + ",\"createFiletime\":" + J(start) + "}";
    }

    static void ProcessCases(int reuseAttempts, int reuseBudgetMs)
    {
        var me = Process.GetCurrentProcess();
        string selfObs = ObserveProcessPid(me.Id);
        Emit("process", "proc:self", "W3", Recorded(me.Id, Filetime(me.Handle)) + ",\"obs\":" + selfObs + "," + Expect("live_same_user", null));
        Emit("mode", "mode:self", "W3", "\"obs\":" + selfObs + "," + Expect("unknown", "not_codex_image"));

        // A child that exits on stdin EOF; it is never terminated.
        string args = Fault == "child_ignores_eof" ? "/d /c ping -n 20 127.0.0.1" : "/d /q";
        Child c = Launch("child", args, true);
        string recorded = Recorded(c.Pid, c.Start);
        Emit("setup", "launch:child", "setup", "\"ok\":" + B(c.Start != null && c.Probe != IntPtr.Zero) + ",\"pid\":" + c.Pid + ",\"win32\":0");
        FaultPoint("after_child_launch");
        if (c.Start == null || c.Probe == IntPtr.Zero) return;
        string live = ObserveProcessHandle(c.Probe, "held");
        Emit("process", "proc:child_live", "W3", recorded + ",\"obs\":" + live + "," + Expect("live_same_user", null));
        FaultPoint("during_child_observation");
        string shifted = (long.Parse(c.Start) + 1).ToString();
        Emit("process", "proc:child_start_mismatch", "W3", Recorded(c.Pid, shifted) + ",\"obs\":" + ObserveProcessHandle(c.Probe, "held") + "," + Expect("unknown", "identity_changed"));
        Emit("mode", "mode:child", "W3", "\"obs\":" + live + "," + Expect("unknown", "not_codex_image"));

        SendEof(c, Fault == "child_abnormal_exit" ? "exit 7" : null);
        bool exited = WaitExit(c, ChildWaitBudgetMs);
        Emit("setup", "eof:child", "setup", "\"ok\":" + B(exited && c.ExitCode == 0) + ",\"exited\":" + B(exited) +
            ",\"exitCode\":" + (exited ? c.ExitCode.ToString() : "null") + ",\"win32\":0");
        if (!exited) return;
        Emit("process", "proc:child_after_exit", "W3", recorded + ",\"obs\":" + ObserveProcessHandle(c.Probe, "held") + "," + Expect("exited", null));
        Emit("process", "proc:child_fresh_open_while_held", "W3", recorded + ",\"obs\":" + ObserveProcessPid(c.Pid) + "," + Expect("exited", null));
        Finish(c);

        // Recorded without a hypothesis: another component may still hold a
        // handle, so the result can be exited, unknown or a reused PID.
        Emit("process", "proc:fresh_open_after_release", "W3", recorded + ",\"obs\":" + ObserveProcessPid(c.Pid));

        // Deliberate PID-reuse attempt under a bounded attempt and time budget.
        var clock = Stopwatch.StartNew();
        int attempts = 0, abnormal = 0;
        bool reused = false, unconfirmed = false;
        while (attempts < reuseAttempts && clock.ElapsedMilliseconds < reuseBudgetMs)
        {
            attempts++;
            Child probe = Launch("reuse", "/d /c exit 0", false);
            // The Process object keeps its creation handle, so the object
            // stays observable through a fresh open by PID.
            if (probe.Pid == c.Pid)
            {
                reused = true;
                Emit("process", "proc:pid_reuse", "W3", recorded + ",\"attempts\":" + attempts + ",\"obs\":" + ObserveProcessPid(c.Pid) + "," + Expect("unknown", "identity_changed"));
            }
            long left = Math.Max(0, Math.Min(ChildWaitBudgetMs, reuseBudgetMs - clock.ElapsedMilliseconds));
            if (!WaitExit(probe, (int)left)) { unconfirmed = true; Finish(probe); break; }
            if (probe.ExitCode != 0) abnormal++;
            Finish(probe);
            if (reused) break;
        }
        if (!reused)
            Emit("recorded", "proc:pid_reuse", "W3", "\"observed\":false,\"attempts\":" + attempts + ",\"elapsedMs\":" + clock.ElapsedMilliseconds);
        Emit("setup", "reuse:children", "setup", "\"ok\":" + B(abnormal == 0 && !unconfirmed) + ",\"attempts\":" + attempts +
            ",\"abnormalExits\":" + abnormal + ",\"unconfirmedExit\":" + B(unconfirmed) + ",\"win32\":0");
    }

    // Regression probes for cleanup: a probe tree is registered separately,
    // then its root or parent is replaced by a new object at the same path
    // holding a sentinel. Guarded deletion must delete nothing and the
    // sentinel must keep its identity. All objects stay in the main registry
    // and are removed by the main cleanup through their own identities.
    static void CleanupProbes()
    {
        string ownerOnly = Sddl("");
        // Root replacement.
        string rootB = P("probe-root");
        if (!Setup("create:probe_root", CreateDir(rootB, ownerOnly))) return;
        string rootBId = IdentityAt(rootB);
        var probeB = new List<Entry>();
        if (!Setup("create:probe_root_item", CreateFile(rootB + "\\item.lock", ownerOnly))) return;
        Register(probeB, "file", rootB + "\\item.lock");
        if (!Setup("rename:probe_root", Rename(rootB, rootB + ".moved"))) return;
        if (!Setup("create:probe_root_replacement", CreateDir(rootB, ownerOnly))) return;
        if (!Setup("create:probe_root_sentinel", CreateFile(rootB + "\\item.lock", ownerOnly))) return;
        Probe("cleanup:replaced_root", rootB, rootBId, probeB, rootB + "\\item.lock", rootB + ".moved\\item.lock");

        // Parent replacement.
        string rootA = P("probe-parent");
        if (!Setup("create:probe_parent_root", CreateDir(rootA, ownerOnly))) return;
        string rootAId = IdentityAt(rootA);
        string parent = rootA + "\\parent";
        if (!Setup("create:probe_parent", CreateDir(parent, ownerOnly))) return;
        if (!Setup("create:probe_parent_item", CreateFile(parent + "\\item.lock", ownerOnly))) return;
        var probeA = new List<Entry>();
        Register(probeA, "dir", parent);
        Register(probeA, "file", parent + "\\item.lock");
        if (!Setup("rename:probe_parent", Rename(parent, parent + ".moved"))) return;
        if (!Setup("create:probe_parent_replacement", CreateDir(parent, ownerOnly))) return;
        if (!Setup("create:probe_parent_sentinel", CreateFile(parent + "\\item.lock", ownerOnly))) return;
        Probe("cleanup:replaced_parent", rootA, rootAId, probeA, parent + "\\item.lock", parent + ".moved\\item.lock");
    }

    static void Probe(string name, string root, string rootId, List<Entry> entries, string sentinelPath, string originalPath)
    {
        string sentinelId = IdentityAt(sentinelPath);
        string originalId = entries[entries.Count - 1].Identity;
        int removed;
        string reason = GuardedDelete(null, root, rootId, entries, out removed);
        bool sentinelIntact = sentinelId != null && IdentityAt(sentinelPath) == sentinelId;
        bool originalIntact = originalId != null && IdentityAt(originalPath) == originalId;
        Emit("cleanup_probe", name, "cleanup", "\"obs\":{\"ok\":true,\"preserved\":" + B(reason != null) + ",\"removed\":" + removed +
            ",\"reason\":" + J(reason) + ",\"sentinelIntact\":" + B(sentinelIntact) + ",\"originalIntact\":" + B(originalIntact) + "}," +
            Expect("preserved", null));
    }

    // ---- Cleanup --------------------------------------------------------------

    public static string Cleanup()
    {
        ReleaseAll();
        foreach (var h in Held.Values) h.Dispose();
        Held.Clear();
        int registered = Created.Count + 1, removed = 0;
        string reason;
        if (Root == null) reason = "no_root";
        else if (ChildrenStillRunning > 0) reason = "children_running";
        else
        {
            // The run-long hold has no DELETE access, so it is released and the
            // root is reopened for deletion; the reopened handle is verified
            // against the recorded identity, which detects a replacement in
            // that window (the window itself is not closed).
            RootHold.Dispose();
            RootHold = null;
            reason = GuardedDelete(null, Root, RootIdentity, Created, out removed);
        }
        CleanupOk = reason == null && removed == registered;
        return "{\"kind\":\"cleanup\",\"case\":\"cleanup\",\"track\":\"cleanup\",\"ok\":" + B(CleanupOk) +
            ",\"preserved\":" + B(!CleanupOk) + ",\"registered\":" + registered + ",\"removed\":" + removed +
            ",\"reason\":" + J(reason) + ",\"childrenStillRunning\":" + ChildrenStillRunning + ",\"safeToUnlock\":false}";
    }

    public static string SuiteError(string message)
    {
        return "{\"kind\":\"suite_error\",\"case\":\"suite_error\",\"track\":\"setup\",\"fault\":" + J(Fault) +
            ",\"message\":" + J(message) + ",\"safeToUnlock\":false}";
    }

    public static string Refused(string reason)
    {
        if (RootHold != null) { RootHold.Dispose(); RootHold = null; }
        return "{\"kind\":\"refused\",\"case\":\"refused\",\"track\":\"setup\",\"reason\":" + J(reason) +
            ",\"preservedScratch\":" + J(ScratchAttemptPath) + ",\"scratchIdentity\":" + J(ScratchAttemptIdentity) + ",\"safeToUnlock\":false}";
    }
}
