/*
 * #127 research actor (macOS only). Same-user synthetic fixtures only.
 *
 * Every role is started by visibility.py or its tests. Long-lived roles serve
 * newline commands on stdin, close their descriptors and exit 0 on stdin EOF.
 * ACTOR_LIFETIME_MS is checked only while waiting for a command: it does not
 * interrupt a blocking write, file syscall or bootstrap RPC. mach_msg send and
 * receive have their own timeouts. When the lifetime passes at a command
 * boundary the role exits 3. One-shot roles print one event and exit.
 * Nothing here sends a signal to any process.
 *
 * Output: one JSON object per line on stdout. Only integers, booleans, fixed
 * strings and validated service names are emitted, so no escaping is needed.
 *
 * Roles:
 *   holder <path>          flock(LOCK_EX|LOCK_NB) and keep the descriptor
 *   former <path>          flock, then LOCK_UN, and keep the descriptor
 *   opener <path>          open without locking and keep the descriptor
 *   sender <path>          holder, plus commands `send <service>` and
 *                          `close_own_fd`
 *   receiver <path>        bootstrap_check_in a fresh name, then commands
 *                          `receive`, `makefd` and `fileports`
 *   probe <path>           one-shot independent nonblocking flock probe
 *   listfileports <pid> <path>
 *                          one-shot libproc PROC_PIDLISTFILEPORTS for <pid>
 *   lookup <service>       one-shot bootstrap_look_up (removal check)
 *   makeports <n> <path>   test role: make n fileports of one descriptor and
 *                          report its own fileports (saturation check)
 */

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <poll.h>
#include <stdarg.h>
#include <servers/bootstrap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fileport.h>
#include <sys/file.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define ACTOR_LIFETIME_MS 20000
#define SEND_TIMEOUT_MS 2000
#define RECEIVE_TIMEOUT_MS 3000
#define LINE_LIMIT 256
#define MESSAGE_ID 0x127
#define FWASLOCKED_BIT 0x4000u
#define MAX_FILEPORTS 64

typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t port;
} port_message_t;

typedef struct {
    port_message_t message;
    mach_msg_trailer_t trailer;
} port_receive_t;

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void emit(const char *format, ...) __attribute__((format(printf, 1, 2)));

static void emit(const char *format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    int length = vsnprintf(buffer, sizeof buffer - 1, format, args);
    va_end(args);
    if (length < 0 || length >= (int)sizeof buffer - 1) {
        length = snprintf(buffer, sizeof buffer, "{\"event\":\"failed\",\"reason\":\"emit_overflow\"}");
    }
    buffer[length++] = '\n';
    const char *cursor = buffer;
    while (length > 0) {
        ssize_t written = write(1, cursor, (size_t)length);
        if (written < 0) {
            if (errno == EINTR) continue;
            _exit(4);
        }
        cursor += written;
        length -= (int)written;
    }
}

static const char *error_name(int number) {
    switch (number) {
    case EWOULDBLOCK: return "EWOULDBLOCK";
    case EPERM: return "EPERM";
    case EACCES: return "EACCES";
    case ENOENT: return "ENOENT";
    case EBADF: return "EBADF";
    case ELOOP: return "ELOOP";
    case ESRCH: return "ESRCH";
    case EINVAL: return "EINVAL";
    default: return "other";
    }
}

static int open_fixture(const char *path, int flags) {
    return open(path, flags | O_CLOEXEC | O_NOFOLLOW);
}

static int same_file(int fd, const char *path) {
    struct stat a, b;
    if (fstat(fd, &a) != 0 || stat(path, &b) != 0) return 0;
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static int valid_service(const char *name) {
    size_t length = strlen(name);
    if (length == 0 || length >= 128) return 0;
    for (size_t i = 0; i < length; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-' || c == '_')) return 0;
    }
    return 1;
}

/*
 * Read one command line before the deadline.
 * Returns 1 for a line, 0 for EOF, -1 for deadline, -2 for a framing failure
 * (overlong line or a partial line at EOF).
 */
static int read_command(char *line, int64_t deadline) {
    static char buffer[LINE_LIMIT * 2];
    static size_t used = 0;
    static int eof = 0;
    for (;;) {
        char *newline = memchr(buffer, '\n', used);
        if (newline) {
            size_t length = (size_t)(newline - buffer);
            if (length >= LINE_LIMIT) return -2;
            memcpy(line, buffer, length);
            line[length] = '\0';
            memmove(buffer, newline + 1, used - length - 1);
            used -= length + 1;
            return 1;
        }
        if (used >= LINE_LIMIT) return -2;
        if (eof) return used ? -2 : 0;
        int64_t remaining = deadline - now_ms();
        if (remaining <= 0) return -1;
        struct pollfd item = {.fd = 0, .events = POLLIN};
        int ready = poll(&item, 1, (int)remaining);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) continue;
        ssize_t got = read(0, buffer + used, sizeof buffer - used);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) {
            eof = 1;
            continue;
        }
        used += (size_t)got;
    }
}

/* Serve commands for a role that has none: EOF -> 0, anything else -> 3. */
static int serve_none(int64_t deadline) {
    char line[LINE_LIMIT];
    for (;;) {
        int status = read_command(line, deadline);
        if (status == 0) return 0;
        if (status < 0) return 3;
        emit("{\"event\":\"error\",\"error\":\"unknown command\"}");
    }
}

static int role_keep(const char *path, const char *kind, int64_t deadline) {
    int lock = strcmp(kind, "opener") != 0;
    int fd = open_fixture(path, O_RDWR);
    if (fd < 0) {
        emit("{\"event\":\"failed\",\"reason\":\"open:%s\"}", error_name(errno));
        return 3;
    }
    if (lock && flock(fd, LOCK_EX | LOCK_NB) != 0) {
        emit("{\"event\":\"failed\",\"reason\":\"flock:%s\"}", error_name(errno));
        close(fd);
        return 3;
    }
    if (strcmp(kind, "former") == 0 && flock(fd, LOCK_UN) != 0) {
        emit("{\"event\":\"failed\",\"reason\":\"unlock:%s\"}", error_name(errno));
        close(fd);
        return 3;
    }
    emit("{\"event\":\"ready\",\"pid\":%d,\"kind\":\"%s\"}", getpid(), kind);
    int code = serve_none(deadline);
    close(fd);
    return code;
}

static int role_sender(const char *path, int64_t deadline) {
    int fd = open_fixture(path, O_RDWR);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0) {
        emit("{\"event\":\"failed\",\"reason\":\"lock:%s\"}", error_name(errno));
        if (fd >= 0) close(fd);
        return 3;
    }
    emit("{\"event\":\"ready\",\"pid\":%d,\"kind\":\"sender\"}", getpid());
    char line[LINE_LIMIT];
    for (;;) {
        int status = read_command(line, deadline);
        if (status == 0) break;
        if (status < 0) {
            if (fd >= 0) close(fd);
            return 3;
        }
        if (strncmp(line, "send ", 5) == 0 && valid_service(line + 5)) {
            mach_port_t service = MACH_PORT_NULL;
            kern_return_t kr = bootstrap_look_up(bootstrap_port, line + 5, &service);
            if (kr != KERN_SUCCESS) {
                emit("{\"event\":\"failed\",\"reason\":\"look_up\",\"kr\":%d}", kr);
                continue;
            }
            fileport_t port = FILEPORT_NULL;
            if (fd < 0 || fileport_makeport(fd, &port) != 0) {
                emit("{\"event\":\"failed\",\"reason\":\"makeport:%s\"}", error_name(errno));
                mach_port_deallocate(mach_task_self(), service);
                continue;
            }
            port_message_t message;
            memset(&message, 0, sizeof message);
            message.header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
            message.header.msgh_remote_port = service;
            message.header.msgh_local_port = MACH_PORT_NULL;
            message.header.msgh_size = sizeof message;
            message.header.msgh_id = MESSAGE_ID;
            message.body.msgh_descriptor_count = 1;
            message.port.name = port;
            message.port.disposition = MACH_MSG_TYPE_MOVE_SEND;
            message.port.type = MACH_MSG_PORT_DESCRIPTOR;
            kr = mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof message, 0,
                          MACH_PORT_NULL, SEND_TIMEOUT_MS, MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) {
                /* The send right was not moved; drop it so the sender keeps none. */
                mach_port_deallocate(mach_task_self(), port);
            }
            mach_port_deallocate(mach_task_self(), service);
            emit("{\"event\":\"sent\",\"kr\":%d}", kr);
        } else if (strcmp(line, "close_own_fd") == 0 && fd >= 0) {
            close(fd);
            fd = -1;
            emit("{\"event\":\"closed\",\"who\":\"sender\"}");
        } else {
            emit("{\"event\":\"error\",\"error\":\"unknown command\"}");
        }
    }
    if (fd >= 0) close(fd);
    return 0;
}

typedef struct {
    int count;
    int vnode;
    int non_vnode;
    int matching;
    int matching_locked;
    uint32_t flags;
    const char *error; /* NULL when the enumeration is complete */
} fileport_scan_t;

/*
 * Enumerate a task's fileports. Any step that cannot be completed sets
 * `error` instead of reporting zero: list failure, a list length that is not
 * a whole number of entries, a full buffer (more entries may exist), the
 * fixture identity (stat) failing, or a vnode query failing or returning a
 * short record. Fileports whose type is not a vnode are counted in
 * `non_vnode` and not queried: the fixture is a regular file, so only a vnode
 * fileport can name it. That exclusion is limited to this fixture.
 */
static fileport_scan_t scan_fileports(int pid, const char *path) {
    fileport_scan_t scan = {0, 0, 0, 0, 0, 0, NULL};
    struct proc_fileportinfo items[MAX_FILEPORTS];
    struct stat expected;
    if (stat(path, &expected) != 0) {
        scan.error = "identity";
        return scan;
    }
    errno = 0;
    int bytes = proc_pidinfo(pid, PROC_PIDLISTFILEPORTS, 0, items, (int)sizeof items);
    /* proc_pidinfo returns 0 both for "none" and for failures; errno decides. */
    if (bytes < 0 || (bytes == 0 && errno != 0)) {
        scan.error = errno == ESRCH ? "list_esrch" : "list";
        return scan;
    }
    if (bytes % (int)PROC_PIDLISTFILEPORTS_SIZE != 0) {
        scan.error = "list_length";
        return scan;
    }
    scan.count = bytes / (int)PROC_PIDLISTFILEPORTS_SIZE;
    if (scan.count >= MAX_FILEPORTS) {
        scan.error = "saturated";
        return scan;
    }
    for (int i = 0; i < scan.count; i++) {
        if (items[i].proc_fdtype != PROX_FDTYPE_VNODE) {
            scan.non_vnode++;
            continue;
        }
        scan.vnode++;
        struct vnode_fdinfowithpath info;
        errno = 0;
        int got = proc_pidfileportinfo(pid, items[i].proc_fileport, PROC_PIDFILEPORTVNODEPATHINFO,
                                       &info, (int)sizeof info);
        if (got <= 0) {
            scan.error = "query";
            return scan;
        }
        if (got != (int)sizeof info) {
            scan.error = "short_read";
            return scan;
        }
        if ((dev_t)info.pvip.vip_vi.vi_stat.vst_dev == expected.st_dev &&
            info.pvip.vip_vi.vi_stat.vst_ino == expected.st_ino) {
            scan.matching++;
            scan.flags = info.pfi.fi_openflags;
            if (info.pfi.fi_openflags & FWASLOCKED_BIT) scan.matching_locked++;
        }
    }
    return scan;
}

static void emit_fileports(int pid, const char *path) {
    fileport_scan_t scan = scan_fileports(pid, path);
    if (scan.error) {
        emit("{\"event\":\"fileports\",\"pid\":%d,\"ok\":false,\"error\":\"%s\",\"count\":%d}",
             pid, scan.error, scan.count);
        return;
    }
    emit("{\"event\":\"fileports\",\"pid\":%d,\"ok\":true,\"count\":%d,\"vnode\":%d,\"non_vnode\":%d,"
         "\"matching\":%d,\"matching_was_locked\":%d,\"flags\":\"0x%x\"}",
         pid, scan.count, scan.vnode, scan.non_vnode, scan.matching, scan.matching_locked, scan.flags);
}

/* Test role: make `n` fileports of one fixture descriptor, then report self. */
static int role_makeports(const char *count_text, const char *path) {
    char *end = NULL;
    long n = strtol(count_text, &end, 10);
    if (!end || *end || n < 0 || n > 4 * MAX_FILEPORTS) {
        emit("{\"event\":\"failed\",\"reason\":\"count\"}");
        return 3;
    }
    int fd = open_fixture(path, O_RDONLY);
    if (fd < 0) {
        emit("{\"event\":\"failed\",\"reason\":\"open:%s\"}", error_name(errno));
        return 3;
    }
    for (long i = 0; i < n; i++) {
        fileport_t port = FILEPORT_NULL;
        if (fileport_makeport(fd, &port) != 0) {
            emit("{\"event\":\"failed\",\"reason\":\"makeport:%s\"}", error_name(errno));
            close(fd);
            return 3;
        }
    }
    close(fd);
    emit_fileports(getpid(), path);
    return 0;
}

static int role_receiver(const char *path, int64_t deadline) {
    char service_name[128];
    snprintf(service_name, sizeof service_name, "dev.codex-unlock.research.127v.%d.%08x",
             getpid(), arc4random());
    mach_port_t service = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_check_in(bootstrap_port, service_name, &service);
    if (kr != KERN_SUCCESS) {
        emit("{\"event\":\"failed\",\"reason\":\"check_in\",\"kr\":%d}", kr);
        return 3;
    }
    emit("{\"event\":\"ready\",\"pid\":%d,\"kind\":\"receiver\",\"service\":\"%s\"}", getpid(), service_name);
    fileport_t port = FILEPORT_NULL;
    int fd = -1;
    int code = 0;
    char line[LINE_LIMIT];
    for (;;) {
        int status = read_command(line, deadline);
        if (status == 0) break;
        if (status < 0) {
            code = 3;
            break;
        }
        if (strcmp(line, "receive") == 0 && port == FILEPORT_NULL && fd < 0) {
            port_receive_t buffer;
            memset(&buffer, 0, sizeof buffer);
            kr = mach_msg(&buffer.message.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof buffer,
                          service, RECEIVE_TIMEOUT_MS, MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) {
                emit("{\"event\":\"failed\",\"reason\":\"receive\",\"kr\":%d}", kr);
                continue;
            }
            mach_msg_header_t *header = &buffer.message.header;
            /*
             * Only the fixed sender's message is supported: id, complex bit,
             * no reply port, one moved send right. Anything else is
             * destroyed and reported as failed.
             */
            int shape = header->msgh_id == MESSAGE_ID && (header->msgh_bits & MACH_MSGH_BITS_COMPLEX) &&
                        header->msgh_remote_port == MACH_PORT_NULL &&
                        MACH_MSGH_BITS_REMOTE(header->msgh_bits) == 0 &&
                        header->msgh_size >= sizeof(port_message_t) &&
                        buffer.message.body.msgh_descriptor_count == 1 &&
                        buffer.message.port.type == MACH_MSG_PORT_DESCRIPTOR &&
                        buffer.message.port.disposition == MACH_MSG_TYPE_PORT_SEND &&
                        buffer.message.port.name != MACH_PORT_NULL;
            if (!shape) {
                mach_msg_destroy(header);
                emit("{\"event\":\"failed\",\"reason\":\"message_shape\"}");
                continue;
            }
            port = buffer.message.port.name;
            emit("{\"event\":\"received\",\"ports\":1}");
        } else if (strcmp(line, "makefd") == 0 && port != FILEPORT_NULL && fd < 0) {
            fd = fileport_makefd(port);
            int saved = errno;
            kern_return_t release_kr = mach_port_deallocate(mach_task_self(), port);
            if (release_kr == KERN_SUCCESS) port = FILEPORT_NULL;
            if (fd < 0) {
                emit("{\"event\":\"failed\",\"reason\":\"makefd:%s\"}", error_name(saved));
                continue;
            }
            fcntl(fd, F_SETFD, FD_CLOEXEC);
            emit("{\"event\":\"made_fd\",\"matches\":%s,\"port_released\":%s,\"release_kr\":%d}",
                 same_file(fd, path) ? "true" : "false", release_kr == KERN_SUCCESS ? "true" : "false", release_kr);
        } else if (strcmp(line, "fileports") == 0) {
            emit_fileports(getpid(), path);
        } else {
            emit("{\"event\":\"error\",\"error\":\"unknown command\"}");
        }
    }
    if (fd >= 0) close(fd);
    if (port != FILEPORT_NULL) mach_port_deallocate(mach_task_self(), port);
    mach_port_mod_refs(mach_task_self(), service, MACH_PORT_RIGHT_RECEIVE, -1);
    return code;
}

static int role_probe(const char *path) {
    int fd = open_fixture(path, O_RDONLY);
    if (fd < 0) {
        emit("{\"event\":\"probe\",\"result\":\"error:open:%s\"}", error_name(errno));
        return 0;
    }
    int locked = flock(fd, LOCK_EX | LOCK_NB);
    int saved = errno;
    close(fd);
    if (locked == 0) {
        emit("{\"event\":\"probe\",\"result\":\"free\"}");
    } else if (saved == EWOULDBLOCK) {
        emit("{\"event\":\"probe\",\"result\":\"held\"}");
    } else {
        emit("{\"event\":\"probe\",\"result\":\"error:flock:%s\"}", error_name(saved));
    }
    return 0;
}

static int role_lookup(const char *name) {
    if (!valid_service(name)) {
        emit("{\"event\":\"failed\",\"reason\":\"service_name\"}");
        return 3;
    }
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, name, &port);
    if (kr == KERN_SUCCESS) mach_port_deallocate(mach_task_self(), port);
    emit("{\"event\":\"lookup\",\"kr\":%d}", kr);
    return 0;
}

static int parse_pid(const char *text) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno || !end || *end || value <= 0 || value > 99999999) return -1;
    return (int)value;
}

int main(int argc, char **argv) {
    int64_t deadline = now_ms() + ACTOR_LIFETIME_MS;
    if (argc == 3 && (strcmp(argv[1], "holder") == 0 || strcmp(argv[1], "former") == 0 ||
                      strcmp(argv[1], "opener") == 0))
        return role_keep(argv[2], argv[1], deadline);
    if (argc == 3 && strcmp(argv[1], "sender") == 0) return role_sender(argv[2], deadline);
    if (argc == 3 && strcmp(argv[1], "receiver") == 0) return role_receiver(argv[2], deadline);
    if (argc == 3 && strcmp(argv[1], "probe") == 0) return role_probe(argv[2]);
    if (argc == 3 && strcmp(argv[1], "lookup") == 0) return role_lookup(argv[2]);
    if (argc == 4 && strcmp(argv[1], "makeports") == 0) return role_makeports(argv[2], argv[3]);
    if (argc == 4 && strcmp(argv[1], "listfileports") == 0) {
        int pid = parse_pid(argv[2]);
        if (pid < 0) {
            emit("{\"event\":\"failed\",\"reason\":\"pid\"}");
            return 3;
        }
        emit_fileports(pid, argv[3]);
        return 0;
    }
    emit("{\"event\":\"failed\",\"reason\":\"usage\"}");
    return 2;
}
