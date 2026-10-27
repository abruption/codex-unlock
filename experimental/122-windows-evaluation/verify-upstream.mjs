// Research for #122: source-only check of the upstream citations in
// docs/windows-rust-evaluation.md. Reads git blobs at the pinned commit from a
// caller-provided upstream openai/codex clone. It never runs Codex, opens a
// Codex home, takes locks, or signals processes. Not part of npm test or npm files.
//
// Usage: node experimental/122-windows-evaluation/verify-upstream.mjs <openai/codex clone>
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import console from 'node:console'
import process from 'node:process'

const PIN = {
  tag: 'rust-v0.163.0',
  commit: '83086188ae0614bd882818ff1aa23f3194962012',
}

// sha256 is over the blob at PIN.commit; anchors are 1-based line numbers.
const CITATIONS = [
  {
    path: 'codex-rs/rollout/src/writer_lock.rs',
    sha256: 'e9a49bef7540dc688de8243d6df1ee9a24cf328c082934b1352d8bebef857468',
    anchors: [
      [27, 'pub struct WriterLockGuard {'],
      [43, 'pub fn acquire(self: &Arc<Self>, thread_id: ThreadId)'],
      [65, 'match file.try_lock() {'],
      [116, 'file.lock().map_err'],
      [174, 'impl Drop for WriterLockGuard {'],
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
      [1193, 'pub async fn shutdown(&self)'],
      [1218, 'pub async fn discard(&self)'],
      [1226, 'async fn wait_for_exit(&self)'],
    ],
  },
  {
    path: 'codex-rs/thread-store/src/local/mod.rs',
    sha256: '677a6cc9de3fb543db11d222e99b5bc6ced5f8b004c4445d4ac985f5c163c7f0',
    anchors: [
      [171, 'writer_lock: WriterLockGuard,'],
      [342, 'fn acquire_writer_lock'],
      [373, 'async fn insert_live_recorder('],
      [565, 'fn shutdown_thread(&self, thread_id: ThreadId)'],
    ],
  },
  {
    path: 'codex-rs/thread-store/src/local/live_writer.rs',
    sha256: '68d2a59ac134e2d85e9c1393e8ee958091d11c1cd37606cba5f88fe176d55560',
    anchors: [
      [33, 'let writer_lock = store.acquire_writer_lock(thread_id)?;'],
      [46, 'let writer_lock = store.acquire_writer_lock(params.thread_id)?;'],
      [169, 'pub(super) async fn shutdown_thread('],
      [178, 'recorder.shutdown().await'],
      [207, 'store.live_recorders.lock().await.remove(&thread_id);'],
      [215, 'pub(super) async fn discard_thread('],
    ],
  },
  {
    path: 'codex-rs/thread-store/src/live_thread.rs',
    sha256: 'f7230ea314fe03f91fbfc204839b8e8e5907a701ae30dd0cf29cc1bee7bd4287',
    anchors: [
      [296, 'pub async fn shutdown(&self)'],
      [300, 'self.thread_store.shutdown_thread(self.thread_id).await;'],
      [312, 'pub async fn discard(&self)'],
    ],
  },
  {
    path: 'codex-rs/core/src/session/handlers.rs',
    sha256: '3e49bf0ca6f2d725df3bb424da1040bfff7eb0e32f20429a7fe0a95d1c67310e',
    anchors: [
      [350, 'pub async fn shutdown(sess: &Arc<Session>, sub_id: String) -> bool {'],
      [367, '&& let Err(e) = live_thread.shutdown().await'],
      [716, 'Op::Shutdown => shutdown(&sess, sub.id.clone()).await,'],
      [738, 'if !shutdown_received {'],
      [741, 'live_thread.shutdown().await'],
    ],
  },
  {
    path: 'codex-rs/core/src/session/mod.rs',
    sha256: 'd9399180169ea30f01efc07279cd071bd14f4600129364020edf7e90df300be9',
    anchors: [
      [1156, 'pub(crate) async fn shutdown_and_wait(&self)'],
      [1158, 'self.submit(Op::Shutdown).await'],
    ],
  },
  {
    path: 'codex-rs/core/src/codex_thread.rs',
    sha256: 'de8c0c62510c6c5144bf48ec40039a75b5f05d0eb4d515afcc436caece2795ac',
    anchors: [[319, 'pub async fn shutdown_and_wait(&self)']],
  },
  {
    path: 'codex-rs/app-server/src/request_processors/thread_lifecycle.rs',
    sha256: '9878fc3f652ad2d916891de8c4c377c8290510e19a178b1951e1c520d77270eb',
    anchors: [
      [59, 'fn unloading_target(&self)'],
      [61, '((false, has_no_subscribers_since), (false, is_inactive_since))'],
      [405, 'AgentStatus::Running'],
      [527, 'unload_thread_without_subscribers('],
      [559, 'pub(super) async fn unload_thread_without_subscribers('],
      [580, 'let shutdown = thread.shutdown_and_wait();'],
      [614, 'ServerNotification::ThreadClosed(notification)'],
    ],
  },
  {
    path: 'codex-rs/app-server/src/request_processors/thread_processor.rs',
    sha256: 'f98fdad7df37ad720e63b75488ffab99ae88f7de4578b280ab957a09f0a98153',
    anchors: [
      [1034, 'async fn thread_unsubscribe_response_inner('],
      [1051, 'unsubscribe_connection_from_thread(thread_id, connection_id)'],
      [1297, 'pub(crate) async fn shutdown_threads(&self)'],
      [1300, 'shutdown_all_threads_bounded'],
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
      [580, 'ThreadUnsubscribe => "thread/unsubscribe" {'],
      [1958, 'ThreadClosed => "thread/closed"'],
    ],
  },
  {
    path: 'codex-rs/app-server-transport/src/transport/unix_socket.rs',
    sha256: 'de12b0f1f844b1d5d50a9632d432dc3c9555ac7b8203e915ccc7ffcae84bd038',
    anchors: [
      [180, 'request.uri().path() == "/daemon/shutdown"'],
      [181, 'DaemonShutdownAccess::Managed'],
      [231, 'TransportEvent::DaemonShutdown'],
    ],
  },
  {
    path: 'codex-rs/app-server-daemon/src/backend/pid.rs',
    sha256: 'c7dd9b424381c98c62268ac5119ebf992426446de0e1436745f7136f70803bf6',
    anchors: [
      [162, 'pub(crate) async fn stop_with_grace'],
      [199, 'crate::client::request_shutdown(socket_path.as_path(), pid)'],
      [235, 'process.terminate()?;'],
    ],
  },
  {
    path: 'codex-rs/app-server-daemon/src/backend/windows.rs',
    sha256: 'ce7d90e8a7b0b0f65ea975abecec002c407e1b5fb595d069efe95672bfe66886',
    anchors: [
      [196, 'pub(super) fn start_time(&self)'],
      [221, 'WaitForSingleObject'],
      [247, 'TerminateProcess('],
    ],
  },
  {
    path: 'codex-rs/app-server/src/lib.rs',
    sha256: 'e00b242cde1234ae62cbc420ceefe86a23b93d34115ead6cc02bad454970aa9b',
    anchors: [
      [1338, 'if !shutdown_state.forced() {'],
      [1347, 'processor.shutdown_threads().await;'],
      [1349, 'connection_cleanup_tasks.abort();'],
    ],
  },
  {
    path: 'codex-rs/app-server/README.md',
    sha256: 'd8e489c92adeb9d33bcbbcc5ff78431e839fdb2d6cefccb16812316bc22f5573',
    anchors: [[65, 'thread/unsubscribe or disconnect stops delivery.']],
  },
]

function git(repo, args) {
  return execFileSync('git', ['-C', repo, ...args], { maxBuffer: 64 * 1024 * 1024 })
}

function verify(repo) {
  const failures = []
  const tagCommit = git(repo, ['rev-parse', '--verify', `${PIN.tag}^{commit}`]).toString().trim()
  if (tagCommit !== PIN.commit) failures.push(`tag ${PIN.tag} is ${tagCommit}, expected ${PIN.commit}`)
  for (const { path, sha256, anchors } of CITATIONS) {
    const blob = git(repo, ['cat-file', 'blob', `${PIN.commit}:${path}`])
    const actual = createHash('sha256').update(blob).digest('hex')
    if (actual !== sha256) failures.push(`${path}: sha256 ${actual}`)
    const lines = blob.toString('utf8').split('\n')
    for (const [line, text] of anchors) {
      if (!(lines[line - 1] ?? '').includes(text)) failures.push(`${path}:${line}: missing ${JSON.stringify(text)}`)
    }
  }
  return failures
}

{
  const repo = process.argv[2]
  if (!repo) {
    console.error('usage: verify-upstream.mjs <openai/codex clone containing the pinned commit>')
    process.exit(2)
  }
  const failures = verify(repo)
  const anchors = CITATIONS.reduce((sum, c) => sum + c.anchors.length, 0)
  console.log(JSON.stringify({
    tag: PIN.tag,
    commit: PIN.commit,
    files: CITATIONS.length,
    anchors,
    ok: failures.length === 0,
    failures,
    note: 'source citations only; no owner attribution or safe-unlock authorization',
  }, null, 2))
  process.exit(failures.length === 0 ? 0 : 1)
}
