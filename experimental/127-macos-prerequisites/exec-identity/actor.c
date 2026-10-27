#include <sys/file.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <libproc.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

/* Synthetic only: deliberately keep the lock FD across exec. No signals. */
int main(int argc, char **argv) {
  int fd;
  if (argc == 4 && strcmp(argv[1], "before") == 0) {
    fd = open(argv[2], O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0) return 2;
  } else if (argc == 3 && strcmp(argv[1], "after") == 0) {
    char *end = NULL;
    long n = strtol(argv[2], &end, 10);
    if (!end || *end || n < 3 || n > 1024) return 2;
    fd = (int)n;
    struct stat s;
    if (fstat(fd, &s) != 0 || !S_ISREG(s.st_mode)) return 2;
  } else return 2;
  struct proc_bsdinfo info;
  if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return 2;
  printf("%s %d %llu %llu\n", argv[1], getpid(),
         (unsigned long long)info.pbi_start_tvsec,
         (unsigned long long)info.pbi_start_tvusec);
  fflush(stdout);
  struct timespec began, now;
  clock_gettime(CLOCK_MONOTONIC, &began);
  for (;;) {
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec - began.tv_sec >= 15) { close(fd); return 3; }
    struct pollfd p = {STDIN_FILENO, POLLIN | POLLHUP, 0};
    int ready = poll(&p, 1, 100);
    if (ready < 0 && errno != EINTR) return 2;
    if (ready > 0) {
      char command;
      ssize_t size = read(STDIN_FILENO, &command, 1);
      if (size == 0) { close(fd); return 0; }
      if (size != 1) return 2;
      if (command == 'x' && strcmp(argv[1], "before") == 0) {
        char descriptor[32];
        snprintf(descriptor, sizeof(descriptor), "%d", fd);
        execl(argv[3], argv[3], "after", descriptor, (char *)NULL);
        close(fd); return 2;
      }
      close(fd); return 2;
    }
  }
}
