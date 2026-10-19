/* The POSIX adapter's guest probe (cports: posix.* cases). Every line is
   deterministic: "<what>: <result> <errno-name>". Built for ABSD with the
   adapter and for Linux with gcc; the `agree` subcommand must print the
   same bytes on both. Runs from its case directory; every name is relative. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

/* errno by name, never strerror text (Picolibc and glibc differ in wording
   and, for some codes, number). Anything else prints as errno=<n>. */
static const char *errname(int e) {
    static char other[32];
    switch (e) {
    case 0: return "0";
    case ENOENT: return "ENOENT";
    case EEXIST: return "EEXIST";
    case ENOTDIR: return "ENOTDIR";
    case EISDIR: return "EISDIR";
    case ENOTEMPTY: return "ENOTEMPTY";
    case EACCES: return "EACCES";
    case EROFS: return "EROFS";
    case EPERM: return "EPERM";
    case EINVAL: return "EINVAL";
    case ENOSYS: return "ENOSYS";
    case EAGAIN: return "EAGAIN";
    case EBADF: return "EBADF";
    case ENOTTY: return "ENOTTY";
    case ECHILD: return "ECHILD";
    case ERANGE: return "ERANGE";
    case EIO: return "EIO";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    case ENOMEM: return "ENOMEM";
    case EPIPE: return "EPIPE";
    default: snprintf(other, sizeof other, "errno=%d", e); return other;
    }
}
/* result < 0: "-1 <errno>"; otherwise the value and errno 0. */
static void line(const char *what, long result) {
    if (result < 0) printf("%s: -1 %s\n", what, errname(errno)); else printf("%s: %ld 0\n", what, result);
}
/* A call whose success value is not portable (a descriptor number): 0 on success. */
static void ok(const char *what, long result) { line(what, result < 0 ? -1 : 0); }
static int cmp(const void *a, const void *b) { return strcmp(*(const char *const *)a, *(const char *const *)b); }
/* Sorted entry names and their count, or the opendir errno. More than 64
   entries, or a failed copy, prints its own line instead of a short list. */
#define LIST_MAX 64
static void list(const char *what, const char *dir) {
    DIR *d = opendir(dir);
    if (!d) { line(what, -1); return; }
    char *names[LIST_MAX]; int n = 0, over = 0, nomem = 0; struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (n == LIST_MAX) { over = 1; continue; }
        if ((names[n] = strdup(e->d_name)) == NULL) { nomem = 1; continue; }
        n++;
    }
    closedir(d);
    if (over || nomem) {
        printf("%s: %s 0\n", what, over ? "more than 64 entries" : "strdup failed");
        for (int i = 0; i < n; i++) free(names[i]);
        return;
    }
    qsort(names, n, sizeof *names, cmp);
    printf("%s:", what);
    for (int i = 0; i < n; i++) { printf(" %s", names[i]); free(names[i]); }
    printf(" (%d)\n", n);
}
/* Cleanup prints nothing when it succeeds, and a line naming the step when
   it fails, so a pin never hides a leftover. */
static void quiet(const char *what, int result) { if (result < 0) line(what, -1); }
static void stat_print(const char *what, const struct stat *st, int show) {   /* show: 0 kind, 1 size, 2 mode */
    if (show == 0) printf("%s: %s 0\n", what, S_ISDIR(st->st_mode) ? "dir" : S_ISREG(st->st_mode) ? "file" : "other");
    else if (show == 1) printf("%s: size=%ld 0\n", what, (long)st->st_size);
    else printf("%s: mode=0%03o 0\n", what, (unsigned)(st->st_mode & 07777));
}
static void stat_line(const char *what, const char *path, int show) {
    struct stat st;
    if (stat(path, &st) < 0) { line(what, -1); return; }
    stat_print(what, &st, show);
}
static void lstat_line(const char *what, const char *path, int show) {
    struct stat st;
    if (lstat(path, &st) < 0) { line(what, -1); return; }
    stat_print(what, &st, show);
}
static void fstat_line(const char *what, int fd, int show) {
    struct stat st;
    if (fstat(fd, &st) < 0) { line(what, -1); return; }
    stat_print(what, &st, show);
}
static int create(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t n = strlen(data);
    long w = write(fd, data, n);
    close(fd);
    return w == (long)n ? 0 : -1;
}

static int agree(void) {
    char cwd[PATH_MAX], rp[PATH_MAX];
    line("mkdir d 0777", mkdir("d", 0777));
    stat_line("stat d", "d", 0);
    line("mkdir d again", mkdir("d", 0777));
    int fd = open("d/f", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ok("open d/f create", fd);
    if (fd >= 0) { line("write d/f 5", write(fd, "hello", 5)); line("close d/f", close(fd)); }
    stat_line("stat d/f", "d/f", 1);
    stat_line("stat d/f/x", "d/f/x", 0);
    line("rename d/f d/g", rename("d/f", "d/g"));
    stat_line("stat d/f", "d/f", 0);
    if (getcwd(cwd, sizeof cwd) == NULL) { line("getcwd", -1); cwd[0] = '\0'; }
    if (realpath("d/g", rp) == NULL) line("realpath d/g", -1);
    else {
        size_t n = strlen(cwd); const char *rel = rp;
        if (n == 1 && cwd[0] == '/' && rp[0] == '/') rel = rp + 1;
        else if (n && strncmp(rp, cwd, n) == 0 && rp[n] == '/') rel = rp + n + 1;
        else { printf("realpath d/g: not under getcwd: %s 0\n", rp); rel = NULL; }  /* named, never hidden */
        if (rel) printf("realpath d/g: %s 0\n", rel);
    }
    if (realpath(".", rp) == NULL) line("getcwd == realpath(.)", -1);
    else printf("getcwd == realpath(.): %s 0\n", strcmp(cwd, rp) ? "differ" : "same");
    lstat_line("lstat d/g", "d/g", 0);
    line("chdir d", chdir("d"));
    if (getcwd(rp, sizeof rp) == NULL) line("getcwd in d", -1);
    else { const char *last = strrchr(rp, '/'); printf("getcwd in d: %s 0\n", last ? last + 1 : rp); }
    line("chdir ..", chdir(".."));
    list("readdir d", "d");
    DIR *dir = opendir("d/g");
    ok("opendir d/g", dir ? 0 : -1);
    if (dir) closedir(dir);
    dir = opendir("d");
    ok("opendir d", dir ? 0 : -1);
    if (dir) line("closedir d", closedir(dir));
    line("access d/g F_OK", access("d/g", F_OK));
    line("access d/g R_OK", access("d/g", R_OK));
    line("access d/g W_OK", access("d/g", W_OK));
    line("access d F_OK", access("d", F_OK));
    line("access d R_OK", access("d", R_OK));
    line("access d X_OK", access("d", X_OK));
    line("chmod d/g 0444", chmod("d/g", 0444));
    stat_line("stat d/g", "d/g", 2);
    fd = open("d/g", O_WRONLY);
    ok("open d/g write", fd);
    if (fd >= 0) close(fd);
    line("chmod d/g 0644", chmod("d/g", 0644));
    stat_line("stat d/g", "d/g", 2);
    char buf[64];
    line("readlink d/g", readlink("d/g", buf, sizeof buf));
    fd = open("d/g", O_RDWR);
    ok("open d/g rdwr", fd);
    if (fd >= 0) {
        line("fchmod d/g 0444", fchmod(fd, 0444));
        fstat_line("fstat d/g", fd, 2);
        line("fchmod d/g 0644", fchmod(fd, 0644));
        fstat_line("fstat d/g", fd, 2);
    }
    if (fd >= 0) {
        unsigned char ws[64];
        line("ioctl d/g TIOCGWINSZ", ioctl(fd, TIOCGWINSZ, (void *)ws));
        close(fd);
    }
    line("unlink d/g", unlink("d/g"));
    line("rmdir d", rmdir("d"));
    line("rmdir d again", rmdir("d"));
    printf("getuid == geteuid: %s 0\n", getuid() == geteuid() ? "same" : "differ");
    printf("getegid == getgid: %s 0\n", getegid() == getgid() ? "same" : "differ");
    return 0;
}

static int modes(void) {
    /* each object is cleaned up only if this run created it */
    int f = create("f", ""), d, r, m;
    line("create f", f);
    line("access f X_OK", access("f", X_OK));
    line("chmod f 0600", chmod("f", 0600));
    line("chmod f 0755", chmod("f", 0755));
    line("mkdir d 0777", d = mkdir("d", 0777));
    line("chmod d 0700", chmod("d", 0700));
    line("mkdir r 0555", r = mkdir("r", 0555));
    stat_line("stat r", "r", 0);
    line("mkdir m 0777", m = mkdir("m", 0777));
    stat_line("stat m", "m", 2);
    if (r == 0) quiet("cleanup rmdir r", rmdir("r"));
    if (m == 0) quiet("cleanup rmdir m", rmdir("m"));
    if (d == 0) quiet("cleanup rmdir d", rmdir("d"));
    if (f == 0) quiet("cleanup unlink f", unlink("f"));
    return 0;
}

static int dirwrite(void) {
    line("access . W_OK", access(".", W_OK));
    int d = mkdir("d", 0777);
    line("mkdir d 0777", d);
    list("opendir d before", "d");
    line("access d W_OK", access("d", W_OK));
    list("opendir d after", "d");
    if (d == 0) quiet("cleanup rmdir d", rmdir("d"));
    return 0;
}

static int setlk(int fd, int cmd, short type, long start, long len) {
    struct flock l;
    memset(&l, 0, sizeof l);
    l.l_type = type; l.l_whence = SEEK_SET; l.l_start = start; l.l_len = len;
    return fcntl(fd, cmd, &l);
}
static int lock(void) {
    int a = open("l", O_RDWR | O_CREAT, 0644), b = open("l", O_RDWR);
    ok("open l a", a);
    ok("open l b", b);
    if (a < 0 || b < 0) return 1;
    line("a F_WRLCK whole", setlk(a, F_SETLK, F_WRLCK, 0, 0));
    line("b F_RDLCK whole", setlk(b, F_SETLK, F_RDLCK, 0, 0));
    line("a F_UNLCK whole", setlk(a, F_SETLK, F_UNLCK, 0, 0));
    line("a F_RDLCK 1..1", setlk(a, F_SETLK, F_RDLCK, 1, 1));
    line("a F_GETLK whole", setlk(a, F_GETLK, F_WRLCK, 0, 0));
    line("a F_SETLKW whole", setlk(a, F_SETLKW, F_WRLCK, 0, 0));
    /* nothing the refused rows asked for was locked: another descriptor's
       whole-file exclusive lock is granted (Review Focus 1, A10) */
    line("b F_WRLCK whole", setlk(b, F_SETLK, F_WRLCK, 0, 0));
    line("b F_UNLCK whole", setlk(b, F_SETLK, F_UNLCK, 0, 0));
    line("a F_WRLCK 0x40000002+510", setlk(a, F_SETLK, F_WRLCK, 0x40000002L, 510));
    line("b F_RDLCK whole", setlk(b, F_SETLK, F_RDLCK, 0, 0));
    close(b); close(a); quiet("cleanup unlink l", unlink("l"));
    return 0;
}

static int refusals(void) {
    line("system(NULL)", system(NULL));
    line("system(true)", system("true"));
    FILE *p = popen("true", "r");
    ok("popen true", p ? 0 : -1);
    if (p) pclose(p);
    ok("signal SIGINT SIG_IGN", signal(SIGINT, SIG_IGN) == SIG_ERR ? -1 : 0);
    struct rusage ru;
    line("getrusage", getrusage(RUSAGE_SELF, &ru));
    line("utimes in.txt", utimes("in.txt", NULL));
    char host[256];
    line("gethostname", gethostname(host, sizeof host));
    int rc = symlink("in.txt", "s");
    line("symlink in.txt s", rc);
    if (rc == 0) unlink("s");
    int fd = open("in.txt", O_RDONLY);
    ok("open in.txt", fd);
    if (fd >= 0) { line("fchown fd uid gid", fchown(fd, getuid(), getgid())); close(fd); }
    line("chown in.txt uid gid", chown("in.txt", getuid(), getgid()));
    line("lchown in.txt uid gid", lchown("in.txt", getuid(), getgid()));
    line("setuid getuid", setuid(getuid()));
    line("seteuid geteuid", seteuid(geteuid()));
    line("setgid getgid", setgid(getgid()));
    line("setegid getegid", setegid(getegid()));
    return 0;
}

/* Task 12's lock-contention scenario: A holds, B tries. */
static int hold(const char *path) {
    char buf[64];
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { line("hold open", -1); return 1; }
    if (setlk(fd, F_SETLK, F_WRLCK, 0, 0) < 0) { line("hold F_WRLCK", -1); return 1; }
    printf("HELD\n"); fflush(stdout);
    while (fgets(buf, sizeof buf, stdin) != NULL) {}
    setlk(fd, F_SETLK, F_UNLCK, 0, 0);
    printf("RELEASED\n"); fflush(stdout);
    close(fd);
    return 0;
}
static int try_lock(const char *path) {
    int fd = open(path, O_RDWR);
    if (fd < 0) { line("try open", -1); return 1; }
    line("try shared", setlk(fd, F_SETLK, F_RDLCK, 0, 0));
    line("try exclusive", setlk(fd, F_SETLK, F_WRLCK, 0, 0));
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: posixprobe agree|modes|dirwrite|lock|refusals|hold FILE|try FILE\n"); return 2; }
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!strcmp(argv[1], "agree")) return agree();
    if (!strcmp(argv[1], "modes")) return modes();
    if (!strcmp(argv[1], "dirwrite")) return dirwrite();
    if (!strcmp(argv[1], "lock")) return lock();
    if (!strcmp(argv[1], "refusals")) return refusals();
    if (!strcmp(argv[1], "hold") && argc == 3) return hold(argv[2]);
    if (!strcmp(argv[1], "try") && argc == 3) return try_lock(argv[2]);
    fprintf(stderr, "posixprobe: unknown subcommand %s\n", argv[1]);
    return 2;
}
