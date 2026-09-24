/* 仅供 macOS 合成设备子进程：真实系统调用失败，不模拟磁盘 EIO 或断电。 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

/* DYLD 不替换本 image 内对原符号的直接引用；dlsym 返回值会再次被替换。 */
#define real_write write
#define real_fsync fsync
#define real_rename rename
#define real_fcntl fcntl
static char target[PATH_MAX], parent[PATH_MAX], selected[PATH_MAX], skipped[PATH_MAX];
static const char *fault;
static int trace_fd = -1, skip_writes, enabled, finished, renamed;

static void trace(const char *stage, long result, int error, const char *mechanism,
                  size_t bytes) {
    char line[512];
    int length = snprintf(line, sizeof(line),
        "{\"stage\":\"%s\",\"ret\":%ld,\"errno\":%d,\"mechanism\":\"%s\",\"bytes\":%zu}\n",
        stage, result, error, mechanism, bytes);
    if (length < 0 || (size_t)length >= sizeof(line) || trace_fd < 0) _exit(122);
    size_t offset = 0;
    while (offset < (size_t)length) {
        ssize_t wrote = real_write(trace_fd, line + offset, (size_t)length - offset);
        if (wrote <= 0) _exit(122);
        offset += (size_t)wrote;
    }
}

static void fatal(const char *stage, int error) {
    trace(stage, -1, error, "fault_harness_failed", 0);
    _exit(122);
}

__attribute__((constructor)) static void configure(void) {
    fault = getenv("RIM_M06_FAULT");
    if (!fault) return;
    const char *destination = getenv("RIM_M06_TARGET");
    const char *log = getenv("RIM_M06_TRACE");
    const char *skip = getenv("RIM_M06_SKIP_WRITES");
    if (!destination || !log || destination[0] != '/' || log[0] != '/' ||
        strlen(destination) >= sizeof(target)) _exit(122);
    trace_fd = open(log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (trace_fd < 0) _exit(122);
    strcpy(target, destination);
    strcpy(parent, destination);
    char *last = strrchr(parent, '/');
    if (!last || last == parent || strcmp(last + 1, "state.enc")) fatal("target", 0);
    *last = '\0';
    if (strcmp(fault, "write") && strcmp(fault, "file_sync") &&
        strcmp(fault, "rename") && strcmp(fault, "directory_sync")) fatal("fault", 0);
    if (skip) {
        char *end;
        errno = 0;
        long count = strtol(skip, &end, 10);
        if (errno || !*skip || *end || count < 0 || count > INT_MAX) fatal("skip", errno);
        skip_writes = (int)count;
    }
    enabled = 1;
}

static int path_of(int fd, char path[PATH_MAX]) {
    int previous = errno;
    int result = real_fcntl(fd, F_GETPATH, path);
    errno = previous;
    return result == 0;
}

static int select_snapshot(int fd) {
    char path[PATH_MAX];
    if (!path_of(fd, path)) return 0;
    if (*selected) return !strcmp(path, selected);
    size_t prefix = strlen(parent), length = strlen(path);
    if (strncmp(path, parent, prefix) || path[prefix] != '/' ||
        strncmp(path + prefix + 1, ".snapshot-", 10) ||
        length < prefix + 15 || strcmp(path + length - 4, ".tmp")) return 0;
    if (!strcmp(path, skipped)) return 0;
    if (skip_writes) {
        --skip_writes;
        strcpy(skipped, path);
        return 0;
    }
    strcpy(selected, path);
    trace("selected", 0, 0, "private_snapshot_only", 0);
    return 1;
}

static ssize_t limited_write(int fd, const void *buffer, size_t size) {
    struct rlimit original, limited;
    struct sigaction previous, ignored;
    if (getrlimit(RLIMIT_FSIZE, &original)) fatal("getrlimit", errno);
    memset(&ignored, 0, sizeof(ignored));
    ignored.sa_handler = SIG_IGN;
    sigemptyset(&ignored.sa_mask);
    if (sigaction(SIGXFSZ, &ignored, &previous)) fatal("ignore_sigxfsz", errno);
    limited = original;
    if (limited.rlim_cur > 64) limited.rlim_cur = 64;
    if (setrlimit(RLIMIT_FSIZE, &limited)) {
        int error = errno;
        if (sigaction(SIGXFSZ, &previous, NULL)) fatal("restore_signal", errno);
        fatal("setrlimit", error);
    }
    ssize_t result = real_write(fd, buffer, size);
    int error = result < 0 ? errno : 0;
    if (setrlimit(RLIMIT_FSIZE, &original)) fatal("restore_rlimit", errno);
    if (sigaction(SIGXFSZ, &previous, NULL)) fatal("restore_signal", errno);
    trace("write", result, error, "rlimit_fsize_64_real_write", size);
    if (result < 0) {
        finished = 1;
        if (error != EFBIG) fatal("unexpected_write_error", error);
    } else if ((size_t)result == size || result == 0) {
        fatal("unexpected_write_success", 0);
    }
    errno = error;
    return result;
}

static ssize_t m06_write(int fd, const void *buffer, size_t size) {
    if (enabled && !finished && select_snapshot(fd) && !strcmp(fault, "write"))
        return limited_write(fd, buffer, size);
    return real_write(fd, buffer, size);
}

/* 保留相同描述符编号，暂换合法 pipe，真实同步系统调用失败后完整恢复。 */
static int invalid_sync_target(int fd, const char *stage, int command) {
    int flags = real_fcntl(fd, F_GETFD);
    if (flags < 0) fatal("descriptor_flags", errno);
    int original = dup(fd), pipes[2];
    if (original < 0) fatal("duplicate_descriptor", errno);
    if (pipe(pipes)) fatal("create_pipe", errno);
    if (dup2(pipes[1], fd) < 0) fatal("replace_descriptor", errno);
    if (close(pipes[0]) || close(pipes[1])) fatal("close_pipe", errno);
    int result = command ? real_fcntl(fd, command) : real_fsync(fd);
    int error = result < 0 ? errno : 0;
    if (dup2(original, fd) < 0) fatal("restore_descriptor", errno);
    if (real_fcntl(fd, F_SETFD, flags) < 0) fatal("restore_descriptor_flags", errno);
    if (close(original)) fatal("close_duplicate", errno);
    trace(stage, result, error, command ? "pipe_real_fcntl_fullfsync_not_disk_eio"
                                      : "pipe_descriptor_real_fsync_not_disk_eio", 0);
    finished = 1;
    if (result != -1 || !error) fatal("unexpected_sync_result", error);
    errno = error;
    return result;
}

static const char *sync_stage(int fd) {
    char path[PATH_MAX];
    if (enabled && !finished && path_of(fd, path)) {
        if (!strcmp(fault, "file_sync") && *selected && !strcmp(path, selected))
            return "file_sync";
        if (!strcmp(fault, "directory_sync") && renamed && !strcmp(path, parent))
            return "directory_sync";
    }
    return NULL;
}

static int m06_fsync(int fd) {
    const char *stage = sync_stage(fd);
    return stage ? invalid_sync_target(fd, stage, 0) : real_fsync(fd);
}

/* Darwin fcntl 的第三参数类型依命令区分；无参数命令不能读取不存在的 vararg。 */
static int m06_fcntl(int fd, int command, ...) {
    if (command == F_FULLFSYNC || command == F_BARRIERFSYNC) {
        const char *stage = sync_stage(fd);
        return stage ? invalid_sync_target(fd, stage, command) : real_fcntl(fd, command);
    }
    switch (command) {
        case F_GETFD: case F_GETFL: case F_GETOWN: case F_GETNOSIGPIPE:
        case F_CHKCLEAN: case F_FLUSH_DATA: case F_FREEZE_FS: case F_THAW_FS:
        case F_GETPROTECTIONCLASS:
            return real_fcntl(fd, command);
    }
    va_list arguments;
    va_start(arguments, command);
    int result;
    switch (command) {
        case F_DUPFD: case F_DUPFD_CLOEXEC: case F_SETFD: case F_SETFL:
        case F_SETOWN: case F_NOCACHE: case F_RDAHEAD: case F_NODIRECT:
        case F_GLOBAL_NOCACHE: case F_SETNOSIGPIPE: case F_SETPROTECTIONCLASS:
        case F_SETBACKINGSTORE:
            result = real_fcntl(fd, command, va_arg(arguments, int));
            break;
        default:
            result = real_fcntl(fd, command, va_arg(arguments, void *));
    }
    va_end(arguments);
    return result;
}

static int m06_rename(const char *source, const char *destination) {
    int matches = enabled && !finished && *selected &&
        !strcmp(source, selected) && !strcmp(destination, target);
    if (matches && !strcmp(fault, "rename")) {
        struct stat metadata;
        if (lstat(parent, &metadata)) fatal("parent_stat", errno);
        if (!S_ISDIR(metadata.st_mode) || (metadata.st_mode & 0777) != 0700)
            fatal("parent_permissions", 0);
        if (chmod(parent, 0500)) fatal("deny_rename", errno);
        int result = real_rename(source, destination);
        int error = result < 0 ? errno : 0;
        if (chmod(parent, 0700)) fatal("restore_permissions", errno);
        trace("rename", result, error, "private_parent_0500_real_rename", 0);
        finished = 1;
        if (result != -1 || error != EACCES) fatal("unexpected_rename_result", error);
        errno = error;
        return result;
    }
    int result = real_rename(source, destination);
    int error = errno;
    if (matches && result == 0) {
        renamed = 1;
        trace("renamed", 0, 0, "target_rename_completed", 0);
    }
    errno = error;
    return result;
}

#define INTERPOSE(replacement, original) \
    __attribute__((used)) static const struct { const void *new_fn; const void *old_fn; } \
    interpose_##original __attribute__((section("__DATA,__interpose"))) = \
        { (const void *)(replacement), (const void *)(original) }

INTERPOSE(m06_write, write);
INTERPOSE(m06_fsync, fsync);
INTERPOSE(m06_fcntl, fcntl);
INTERPOSE(m06_rename, rename);
