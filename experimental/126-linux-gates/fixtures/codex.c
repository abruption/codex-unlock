/*
 * Synthetic native holder named `codex` (#126 research, Linux gates G1).
 *
 * SYNTHETIC. This is not Codex and says nothing about a deployed Codex
 * binary. It exists only so that the product's executable/argv checks see a
 * native image whose argv[0] basename is `codex`, with no arguments.
 *
 * Behaviour mirrors ../../126-guard-liveness/f2-linux-nondumpable/codex:
 * refuse root and differing real/effective UIDs, set and verify the requested
 * dumpable value with prctl, take `.coordination.lock` then the thread lock
 * with bounded nonblocking polling, release coordination, print one ready
 * JSON line, then hold until stdin EOF (exit 0) or the lifetime (exit 3).
 *
 * Environment: FIXTURE_LOCK_PATH, FIXTURE_DUMPABLE (0 or 1),
 * FIXTURE_LIFETIME_SECONDS (1-120, default 20).
 *
 * It sends no signal to any process. Build: cc -std=c11 -O1 -Wall -Wextra.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

static double now_s(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int fail(const char *what) {
  fprintf(stderr, "codex fixture: %s: %s\n", what, errno ? strerror(errno) : "invalid");
  return 1;
}

static int acquire(int fd, double deadline) {
  double until = now_s() + 2.0;
  if (until > deadline) until = deadline;
  for (;;) {
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) return 0;
    if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) return -1;
    if (now_s() >= until) { errno = ETIMEDOUT; return -1; }
    struct timespec pause = { 0, 10 * 1000 * 1000 };
    nanosleep(&pause, NULL);
  }
}

static long parse_long(const char *text, long lo, long hi, long fallback) {
  if (!text) return fallback;
  char *end = NULL;
  errno = 0;
  long value = strtol(text, &end, 10);
  if (errno || !end || *end || end == text || value < lo || value > hi) return LONG_MIN;
  return value;
}

int main(void) {
#ifndef __linux__
  errno = 0;
  return fail("Linux only");
#else
  if (getuid() == 0 || getuid() != geteuid()) { errno = 0; return fail("unprivileged same-UID process required"); }
  const char *lock_path = getenv("FIXTURE_LOCK_PATH");
  long want = parse_long(getenv("FIXTURE_DUMPABLE"), 0, 1, LONG_MIN);
  long lifetime = parse_long(getenv("FIXTURE_LIFETIME_SECONDS"), 1, 120, 20);
  if (!lock_path || lock_path[0] != '/' || want == LONG_MIN || lifetime == LONG_MIN) { errno = 0; return fail("environment"); }
  double deadline = now_s() + (double)lifetime;
  if (prctl(PR_SET_DUMPABLE, (unsigned long)want, 0UL, 0UL, 0UL) != 0) return fail("prctl(PR_SET_DUMPABLE)");
  int dumpable = prctl(PR_GET_DUMPABLE, 0UL, 0UL, 0UL, 0UL);
  if (dumpable < 0) return fail("prctl(PR_GET_DUMPABLE)");
  if (dumpable != (int)want) { errno = 0; return fail("dumpable mismatch"); }

  char guard_path[PATH_MAX];
  const char *slash = strrchr(lock_path, '/');
  size_t dir_len = (size_t)(slash - lock_path);
  if (dir_len == 0 || dir_len + sizeof("/.coordination.lock") > sizeof(guard_path)) { errno = 0; return fail("lock path"); }
  memcpy(guard_path, lock_path, dir_len);
  memcpy(guard_path + dir_len, "/.coordination.lock", sizeof("/.coordination.lock"));

  int guard = open(guard_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (guard < 0) return fail("open coordination");
  if (acquire(guard, deadline) != 0) { int saved = errno; close(guard); errno = saved; return fail("acquire coordination"); }
  int thread = open(lock_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (thread < 0) { int saved = errno; close(guard); errno = saved; return fail("open thread lock"); }
  if (acquire(thread, deadline) != 0) { int saved = errno; close(thread); close(guard); errno = saved; return fail("acquire thread lock"); }
  flock(guard, LOCK_UN);
  close(guard);
  printf("{\"ready\":true,\"pid\":%ld,\"fd\":%d,\"dumpable\":%d,\"uid\":%ld,\"euid\":%ld,\"lifetime_seconds\":%ld,\"fixture\":\"native_c_synthetic\"}\n",
    (long)getpid(), thread, dumpable, (long)getuid(), (long)geteuid(), lifetime);
  fflush(stdout);

  int eof = 0;
  char buffer[4096];
  while (!eof) {
    double left = deadline - now_s();
    if (left <= 0) break;
    struct pollfd p = { STDIN_FILENO, POLLIN, 0 };
    int ready = poll(&p, 1, (int)(left * 1000.0) + 1);
    if (ready < 0 && errno == EINTR) continue;
    if (ready < 0) break;
    if (ready == 0) continue;
    ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));
    if (count == 0) eof = 1;
    else if (count < 0 && errno != EINTR && errno != EAGAIN) break;
  }
  close(thread);
  /* Exit 0 on stdin EOF, 3 when the lifetime ended first or stdin failed. */
  return eof ? 0 : 3;
#endif
}
