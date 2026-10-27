// Research for #149 and #150: source-only check of the upstream citations in
// docs/windows-recovery-contract.md. Reads git blobs and runs `git grep` at the
// pinned commit of a caller-provided openai/codex clone. Also checks the
// cited Rust std Windows file. It never builds or runs Codex, opens a Codex
// home, takes locks, connects to Codex endpoints, or signals Codex processes.
// Git may lazily fetch missing blobs in a caller-supplied promisor clone.
// Caller repository/configuration is trusted. Not part of npm test or npm files.
//
// Usage:
//   node experimental/windows-release-contract/verify-upstream.mjs <openai/codex clone> <rust std sys/fs/windows.rs>
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import console from 'node:console'
import process from 'node:process'

const PIN = {
  tag: 'rust-v0.163.0',
  commit: '83086188ae0614bd882818ff1aa23f3194962012',
}

// Rust 1.95.0 (codex-rs/rust-toolchain.toml at PIN.commit), tag 1.95.0^{} =
// 59807616e1fa2540724bfbac14d7976d7e4a3860, file library/std/src/sys/fs/windows.rs.
const RUST_STD = {
  sha256: 'e26633635161814b3e9bd75a50cf0bbe2d90d55c9342e3adcbced16d6b024099',
  anchors: [
    [206, 'share_mode: c::FILE_SHARE_READ | c::FILE_SHARE_WRITE | c::FILE_SHARE_DELETE,'],
    [209, 'inherit_handle: false,'],
    [357, 'if opts.inherit_handle { &sa } else { ptr::null() },'],
    [417, 'let lock_result = cvt(c::LockFileEx('],
    [421, 'u32::MAX,'],
    [422, 'u32::MAX,'],
    [458, 'pub fn try_lock(&self) -> Result<(), TryLockError> {'],
    [463, 'c::LOCKFILE_EXCLUSIVE_LOCK | c::LOCKFILE_FAIL_IMMEDIATELY,'],
    [465, 'u32::MAX,'],
    [1288, 'pub fn unlink(path: &WCStr) -> io::Result<()> {'],
    [1289, 'c::DeleteFileW(path.as_ptr())'],
  ],
}

// sha256 is over the blob at PIN.commit; anchors are 1-based line numbers.
const CITATIONS = [
  {
    path: 'codex-rs/rust-toolchain.toml',
    sha256: '570656042681cfd8795403a455baf9a33035331a07db0645e866bbcea89a3d64',
    anchors: [[2, 'channel = "1.95.0"']],
  },
  {
    path: 'codex-rs/rollout/src/writer_lock.rs',
    sha256: 'e9a49bef7540dc688de8243d6df1ee9a24cf328c082934b1352d8bebef857468',
    anchors: [
      [43, 'pub fn acquire(self: &Arc<Self>, thread_id: ThreadId)'],
      [44, 'let _coordination_lock = self.lock_coordination()?;'],
      [52, 'let file = OpenOptions::new()'],
      [65, 'match file.try_lock() {'],
      [67, 'Err(std::fs::TryLockError::WouldBlock) => {'],
      [116, 'file.lock().map_err'],
      [124, 'fn remove_stale_thread_locks(&self)'],
      [174, 'impl Drop for WriterLockGuard {'],
      [176, 'let coordination_lock = match self.coordinator.lock_coordination() {'],
      [180, 'return;'],
      [185, 'drop(self.file.take());'],
      [186, 'fs::remove_file(&self.path)'],
      [194, 'drop(coordination_lock);'],
    ],
  },
  {
    path: 'codex-rs/rollout/src/recorder.rs',
    sha256: '42a973710d6eb7e6731b3774cdf30dba89f56fd7685cdeac2857825c08b83612',
    anchors: [
      [148, '_writer_lock: Option<Arc<crate::WriterLockGuard>>,'],
      [1018, 'let writer_task = Arc::new(RolloutWriterTask::new(writer_lock));'],
    ],
  },
  {
    path: 'codex-rs/thread-store/src/local/live_writer.rs',
    sha256: '68d2a59ac134e2d85e9c1393e8ee958091d11c1cd37606cba5f88fe176d55560',
    anchors: [
      [169, 'pub(super) async fn shutdown_thread('],
      [207, 'store.live_recorders.lock().await.remove(&thread_id);'],
    ],
  },
  {
    path: 'codex-rs/core/src/session/handlers.rs',
    sha256: '3e49bf0ca6f2d725df3bb424da1040bfff7eb0e32f20429a7fe0a95d1c67310e',
    anchors: [
      [350, 'pub async fn shutdown(sess: &Arc<Session>, sub_id: String) -> bool {'],
      [716, 'Op::Shutdown => shutdown(&sess, sub.id.clone()).await,'],
    ],
  },
  {
    path: 'codex-rs/app-server/src/request_processors/thread_lifecycle.rs',
    sha256: '9878fc3f652ad2d916891de8c4c377c8290510e19a178b1951e1c520d77270eb',
    anchors: [
      [59, 'fn unloading_target(&self)'],
      [61, '((false, has_no_subscribers_since), (false, is_inactive_since))'],
      [62, 'checked_add(self.delay)'],
      [405, 'AgentStatus::Running'],
      [559, 'pub(super) async fn unload_thread_without_subscribers('],
      [573, '.cancel_requests_for_thread(thread_id, /*error*/ None)'],
      [580, 'let shutdown = thread.shutdown_and_wait();'],
      [582, 'Duration::from_secs(/*secs*/ 10)'],
      [591, 'shutdown.await'],
      [599, '.remove_thread_if_matches(&thread_id, &thread)'],
      [614, 'ServerNotification::ThreadClosed(notification)'],
    ],
  },
  {
    path: 'codex-rs/app-server/src/request_processors/thread_processor.rs',
    sha256: 'f98fdad7df37ad720e63b75488ffab99ae88f7de4578b280ab957a09f0a98153',
    anchors: [
      [1034, 'async fn thread_unsubscribe_response_inner('],
      [1051, 'unsubscribe_connection_from_thread(thread_id, connection_id)'],
      [1069, 'pub(super) async fn prepare_thread_for_removal('],
      [1297, 'pub(crate) async fn shutdown_threads(&self)'],
      [1300, '.shutdown_all_threads_bounded(Duration::from_secs(10))'],
      [2887, 'async fn thread_loaded_list_response_inner('],
      [2894, '.list_thread_ids()'],
    ],
  },
  {
    path: 'codex-rs/app-server/src/thread_state.rs',
    sha256: 'cbdf09ad65d0c67e37ca78fbc4707d49031cb313619819d5344705cec2350002',
    anchors: [
      [557, 'pub(crate) async fn unsubscribe_connection_from_thread('],
      [571, '.is_some_and(|thread_ids| thread_ids.contains(&thread_id))'],
      [583, 'thread_entry.connection_ids.remove(&connection_id);'],
    ],
  },
  {
    path: 'codex-rs/core/src/config/mod.rs',
    sha256: 'cbd8dd6d50cb7d61183d309cbefa95cd368de87bf44d2ac60e83c3a2aff59658',
    anchors: [[4032, 'thread_unload_delay_secs.unwrap_or(/*default*/ 1800)']],
  },
  {
    path: 'codex-rs/app-server-protocol/src/protocol/common.rs',
    sha256: 'ee03e7b76763ac658f4af3d36c0c1a26c00dff6ee9256d474dd85fa740143cc3',
    anchors: [
      [506, '#[experimental("server/diagnostics")]'],
      [508, 'ServerDiagnostics => "server/diagnostics" {'],
      [580, 'ThreadUnsubscribe => "thread/unsubscribe" {'],
      [853, 'ThreadLoadedList => "thread/loaded/list" {'],
      [1958, 'ThreadClosed => "thread/closed"'],
    ],
  },
  {
    path: 'codex-rs/app-server-protocol/src/protocol/v2/diagnostics.rs',
    sha256: 'da8b2b284727c14b6166e2c88d71b74c8bbcf27216ca06921859625168496e31',
    anchors: [
      [22, 'pub struct ServerDiagnosticsProcess {'],
      [23, 'pub id: u32,'],
    ],
  },
  {
    path: 'codex-rs/app-server/src/request_processors/diagnostics.rs',
    sha256: '750eb6c1ffe91a200770caf4ecaba526b69e266cf1d53bcd5a670dcadb868a9e',
    anchors: [[10, 'id: diagnostics.process.id,']],
  },
  {
    path: 'codex-rs/app-server/src/lib.rs',
    sha256: 'e00b242cde1234ae62cbc420ceefe86a23b93d34115ead6cc02bad454970aa9b',
    anchors: [
      [218, 'async fn shutdown_signal() -> IoResult<ShutdownSignal> {'],
      [233, '#[cfg(windows)]'],
      [236, 'if tokio::signal::ctrl_c().await.is_err() {'],
      [242, 'Ok(ShutdownSignal::Forceable)'],
      [263, 'if matches!(signal, ShutdownSignal::Forceable) {'],
      [264, 'self.forced = true;'],
      [1126, 'TransportEvent::DaemonShutdown => {'],
      [1127, 'shutdown_state.on_signal(ShutdownSignal::Forceable'],
      [1338, 'if !shutdown_state.forced() {'],
      [1347, 'processor.shutdown_threads().await;'],
      [1349, 'connection_cleanup_tasks.abort();'],
    ],
  },
  {
    path: 'codex-rs/app-server/src/in_process.rs',
    sha256: 'f676d9a932866a6aee763013648a163356468a2ab052b773f2b208c37bc7f651',
    anchors: [
      [595, '.connection_closed(IN_PROCESS_CONNECTION_ID, &session)'],
      [599, 'processor.shutdown_threads().await;'],
    ],
  },
  {
    path: 'codex-rs/core/src/thread_manager.rs',
    sha256: '6888f63946839c28d375e1514d1fe938db728aed6a7ffd694daf41b90aeed3fb',
    anchors: [
      [1435, 'pub async fn shutdown_all_threads_bounded(&self, timeout: Duration)'],
      [1447, 'tokio::time::timeout(timeout, thread.shutdown_and_wait())'],
    ],
  },
  {
    path: 'codex-rs/app-server-transport/src/transport/unix_socket.rs',
    sha256: 'de12b0f1f844b1d5d50a9632d432dc3c9555ac7b8203e915ccc7ffcae84bd038',
    anchors: [
      [88, '#[cfg(windows)]'],
      [91, 'codex_uds::prepare_private_socket_directory(parent).await?;'],
      [93, 'codex_uds::validate_private_socket_path(socket_path.as_path())?;'],
      [180, 'request.uri().path() == "/daemon/shutdown"'],
      [181, 'DaemonShutdownAccess::Managed'],
      [211, 'run_websocket_connection(websocket_writer, websocket_reader, transport_event_tx).await;'],
      [221, 'let pid = std::process::id().to_string();'],
      [222, 'if request == pid'],
      [443, '#[cfg(not(unix))]'],
      [444, 'async fn set_control_socket_permissions(_socket_path: &Path) -> IoResult<()> {'],
    ],
  },
  {
    path: 'codex-rs/app-server-transport/src/transport/websocket.rs',
    sha256: 'e1a5fe9b1bb865daa376bac587b3afdec0e791e4d83926a4432ecb3b046a98dd',
    anchors: [
      [70, 'if addr.ip().is_loopback() {'],
      [111, 'authorize_upgrade(&headers, state.auth_policy.as_ref())'],
      [135, 'is_unauthenticated_non_loopback_listener(bind_address, &auth_policy)'],
      [172, 'pub(crate) async fn run_websocket_connection'],
      [189, 'origin: ConnectionOrigin::WebSocket,'],
      [190, 'auth: None,'],
    ],
  },
  {
    path: 'codex-rs/app-server-transport/src/connection_auth.rs',
    sha256: 'fc259d2476224aa626af310638f335ceb303838bee05d26c07f4a927735ee3db',
    anchors: [
      [1, 'Binds a transport connection to the authentication owner'],
      [41, 'owner_generation == self.owner_generation'],
    ],
  },
  {
    path: 'codex-rs/app-server-transport/src/daemon_shutdown.rs',
    sha256: '0be3c79b2258db0c3b01ca0fc820d23de5014ef5a4f2f661838ecf4a8f75d8d3',
    anchors: [
      [1, 'The detached Windows updater has no control socket'],
      [14, 'pub const DAEMON_SHUTDOWN_FILE_ENV: &str = "CODEX_DAEMON_SHUTDOWN_FILE";'],
      [40, 'if contents != pid.to_string().as_bytes() {'],
    ],
  },
  {
    path: 'codex-rs/uds/src/windows_peer.rs',
    sha256: '44c4ba4690d1930b40e4a5da9f283e2e17453d81692b73ff5e7c366832b2831b',
    anchors: [
      [25, 'pub(super) fn ensure_non_elevated_peer(socket: RawSocket)'],
      [31, 'SIO_AF_UNIX_GETPEERPID,'],
      [53, 'PROCESS_QUERY_LIMITED_INFORMATION,'],
      [75, 'EqualSid('],
      [95, 'if !same_user || elevation.TokenIsElevated != 0 {'],
    ],
  },
  {
    path: 'codex-rs/uds/src/windows_security.rs',
    sha256: 'dc4c5a2e06e5c49dd170b14302fd1bc99b05c2af5aa30ca497846c889606d021',
    anchors: [[38, 'format!("O:{sid}D:P(A;OICI;FA;;;{sid})")']],
  },
  {
    path: 'codex-rs/uds/src/windows_socket_validation.rs',
    sha256: 'b6639ba2b1d287be3bd75a084805232f0f55e738c28c8b0901916d3040d0d619',
    anchors: [
      [47, 'pub fn validate_private_socket_path(socket_path: &Path)'],
      [69, 'FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,'],
      [117, 'control & SE_DACL_PROTECTED != 0'],
      [119, '(*dacl).AceCount == 1'],
    ],
  },
  {
    path: 'codex-rs/app-server-client/src/remote.rs',
    sha256: '2722a22cca44b6befce054a04de6b6ee6a59f14e87f10a953c8b27e52a5b7f50',
    anchors: [
      [174, 'enum SocketPeerPolicy {'],
      [188, 'pub async fn connect_local_daemon(args: RemoteAppServerConnectArgs)'],
      [809, 'SocketPeerPolicy::ExplicitEndpoint => {}'],
      [811, 'SocketPeerPolicy::NonElevatedCurrentUser => stream.ensure_non_elevated_peer()?,'],
    ],
  },
  {
    path: 'codex-rs/tui/src/lib.rs',
    sha256: '40c04eae3155b8a115bd5a69e0ef3a55dd7873b4844504779b63be6f37682ff0',
    anchors: [
      [523, 'async fn maybe_probe_default_daemon_socket(codex_home: &Path)'],
      [542, '_stream.ensure_non_elevated_peer().ok()?;'],
    ],
  },
  {
    path: 'codex-rs/app-server-daemon/src/backend/pid.rs',
    sha256: 'c7dd9b424381c98c62268ac5119ebf992426446de0e1436745f7136f70803bf6',
    anchors: [
      [162, 'pub(crate) async fn stop_with_grace'],
      [199, 'crate::client::request_shutdown(socket_path.as_path(), pid)'],
      [205, 'fs::write(self.pid_file.with_extension("shutdown"), pid.to_string())'],
      [235, 'process.terminate()?;'],
    ],
  },
  {
    path: 'codex-rs/app-server-daemon/src/backend/windows.rs',
    sha256: 'ce7d90e8a7b0b0f65ea975abecec002c407e1b5fb595d069efe95672bfe66886',
    anchors: [
      [77, 'SetHandleInformation(handle, HANDLE_FLAG_INHERIT, /*dwflags*/ 0)'],
      [196, 'pub(super) fn start_time(&self)'],
      [221, 'WaitForSingleObject'],
      [247, 'TerminateProcess('],
    ],
  },
]

// Literal `git grep -F` searches over codex-rs Rust sources at PIN.commit.
// A zero count is "not found in targeted search", never proof of absence.
// Positive controls guard against a search that silently matches nothing.
const SEARCHES = [
  { text: '"thread/unsubscribe"', expect: 'present' },
  { text: '"thread/loaded/list"', expect: 'present' },
  { text: 'SIO_AF_UNIX_GETPEERPID', expect: 'present' },
  { text: 'thread/release', expect: 'absent' },
  { text: 'thread/handoff', expect: 'absent' },
  { text: 'thread/unload', expect: 'absent' },
  { text: '"thread/close"', expect: 'absent' },
  { text: 'thread/writer', expect: 'absent' },
  { text: 'writerLock', expect: 'absent' },
  { text: 'RmGetList', expect: 'absent' },
  { text: 'RmStartSession', expect: 'absent' },
  { text: 'GenerateConsoleCtrlEvent', expect: 'absent' },
  { text: 'AttachConsole', expect: 'absent' },
]

function git(repo, args) {
  return execFileSync('git', ['-C', repo, ...args], { maxBuffer: 64 * 1024 * 1024 })
}

function grepCount(repo, text) {
  try {
    const out = git(repo, ['grep', '-c', '-F', '-e', text, PIN.commit, '--', 'codex-rs/*.rs']).toString()
    return out.split('\n').filter(Boolean).reduce((sum, line) => sum + Number(line.slice(line.lastIndexOf(':') + 1)), 0)
  } catch (err) {
    if (err.status === 1) return 0
    throw err
  }
}

function checkAnchors(label, blob, sha256, anchors, failures) {
  const actual = createHash('sha256').update(blob).digest('hex')
  if (actual !== sha256) failures.push(`${label}: sha256 ${actual}`)
  const lines = blob.toString('utf8').split('\n')
  for (const [line, text] of anchors) {
    if (!(lines[line - 1] ?? '').includes(text)) failures.push(`${label}:${line}: missing ${JSON.stringify(text)}`)
  }
}

function verify(repo, rustStd) {
  const failures = []
  const tagCommit = git(repo, ['rev-parse', '--verify', `${PIN.tag}^{commit}`]).toString().trim()
  if (tagCommit !== PIN.commit) failures.push(`tag ${PIN.tag} is ${tagCommit}, expected ${PIN.commit}`)
  for (const { path, sha256, anchors } of CITATIONS) {
    checkAnchors(path, git(repo, ['cat-file', 'blob', `${PIN.commit}:${path}`]), sha256, anchors, failures)
  }
  const searches = SEARCHES.map(({ text, expect }) => {
    const count = grepCount(repo, text)
    const ok = expect === 'present' ? count > 0 : count === 0
    if (!ok) failures.push(`search ${JSON.stringify(text)}: expected ${expect}, count ${count}`)
    return { text, expect, count }
  })
  checkAnchors('rust-std sys/fs/windows.rs', readFileSync(rustStd), RUST_STD.sha256, RUST_STD.anchors, failures)
  return { failures, searches }
}

{
  const [repo, rustStd] = process.argv.slice(2)
  if (process.argv.length !== 4 || !repo || !rustStd) {
    console.error('usage: verify-upstream.mjs <openai/codex clone containing the pinned commit> <rust std sys/fs/windows.rs>')
    process.exit(2)
  }
  const { failures, searches } = verify(repo, rustStd)
  const anchors = CITATIONS.reduce((sum, c) => sum + c.anchors.length, 0)
  console.log(JSON.stringify({
    tag: PIN.tag,
    commit: PIN.commit,
    files: CITATIONS.length,
    anchors,
    searches,
    rustStd: { anchors: RUST_STD.anchors.length },
    ok: failures.length === 0,
    failures,
    note: 'source citations only; no holder attribution, release authorization or runtime claim',
  }, null, 2))
  process.exit(failures.length === 0 ? 0 : 1)
}
