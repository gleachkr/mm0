/* Runtime oracle for the OS-layer exit tests. For each row in gen/cases.inc it
 * forks a child that performs the raw `exit(rdi)` syscall, then checks that the
 * parent observes exactly the exit code the model predicts (`rdi & 0xff`, the
 * value `execExit k (rdi & 0xff)` asserts). A disagreement means the model and a
 * real kernel differ about exit-status masking.
 *
 *   cc -O2 harness.c -o harness && ./harness
 *
 * The harness applies expectations, it never recomputes them: `code` is baked
 * into gen/cases.inc by gen.py, so a recomputation here could not reproduce a
 * masking bug independently. */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

struct exit_case { const char *name; unsigned long long rdi; int code; };
static const struct exit_case cases[] = {
#include "gen/cases.inc"
};

/* A fault-exit test executes a faulting instruction (the exact bytes the model
 * decodes) and checks the child dies by the predicted signal -- the parent sees
 * `$? = 128 + signo`, the nonzero exit code `execExit` asserts. */
struct fault_case { const char *name; unsigned char code[16]; int len; int exit_code; };
static const struct fault_case fault_cases[] = {
#include "gen/fault_cases.inc"
};

/* An mmap test makes the raw syscall in-process and reads the kernel's return
 * straight out of RAX -- the value the model calls `readReg (ksCfg ks2) RAX`.
 * We must bypass glibc's mmap/syscall wrappers, which fold `-errno` into
 * `MAP_FAILED` + errno and would hide the very value under test. */
struct mmap_case {
    const char *name;
    unsigned long long addr, length, prot, flags;
    long fd;
    unsigned long long off;
    long ret;                 /* expected raw RAX: -errno */
};
static const struct mmap_case mmap_cases[] = {
#include "gen/mmap_cases.inc"
};

/* An mmap-ok test maps a writable region and then WRITES to it (via inline asm so
 * the store is not optimized away) in a forked child. The model says the returned
 * buffer supports a write without faulting; the harness confirms the child does
 * not die by a signal -- the converse of the segv test. */
struct mmap_ok_case {
    const char *name;
    unsigned long long addr, length, prot, flags;
    long fd;
    unsigned long long off;
};
static const struct mmap_ok_case mmap_ok_cases[] = {
#include "gen/mmap_ok_cases.inc"
};

/* A write test writes `data` with a raw fd whose high 32 bits are set. We route
 * fd 1 through a pipe first, so the write's destination is observable: if the
 * kernel truncates the fd to `int` (as the model claims) the bytes land in the
 * pipe, and the raw RAX is the count. */
struct write_case {
    const char *name;
    unsigned long long fd;
    unsigned char data[64];
    int count;
};
static const struct write_case write_cases[] = {
#include "gen/write_cases.inc"
};

/* A read test feeds bytes to stdin through a pipe and reads them back, checking
 * both the delivered bytes and the count in RAX -- the read really moved data. */
struct read_case {
    const char *name;
    unsigned char data[64];
    int count;
};
static const struct read_case read_cases[] = {
#include "gen/read_cases.inc"
};

static long raw_read(int fd, void *buf, long count) {
    register long rax __asm__("rax") = 0;               /* sys_read */
    register long rdi __asm__("rdi") = fd;
    register long rsi __asm__("rsi") = (long) buf;
    register long rdx __asm__("rdx") = count;
    __asm__ volatile("syscall"
        : "+r"(rax)
        : "r"(rdi), "r"(rsi), "r"(rdx)
        : "rcx", "r11", "memory");
    return rax;
}

/* A write-errno test: write to a bad fd and read the raw -errno from RAX. */
struct write_errno_case { const char *name; unsigned long long fd; int count; long ret; };
static const struct write_errno_case write_errno_cases[] = {
#include "gen/write_errno_cases.inc"
};

/* A read-errno test: read from a bad fd and read the raw -errno from RAX. */
struct read_errno_case { const char *name; unsigned long long fd; int count; long ret; };
static const struct read_errno_case read_errno_cases[] = {
#include "gen/read_errno_cases.inc"
};

/* An open-errno test: open a nonexistent path and read the raw -errno from RAX. */
struct open_errno_case { const char *name; const char *path; long ret; };
static const struct open_errno_case open_errno_cases[] = {
#include "gen/open_errno_cases.inc"
};

/* An open-ok test: open a path and confirm the return is a valid (non-error) fd. */
struct open_ok_case { const char *name; const char *path; };
static const struct open_ok_case open_ok_cases[] = {
#include "gen/open_ok_cases.inc"
};

static long raw_open(const char *path, long flags, long mode) {
    register long rax __asm__("rax") = 2;               /* sys_open */
    register long rdi __asm__("rdi") = (long) path;
    register long rsi __asm__("rsi") = flags;
    register long rdx __asm__("rdx") = mode;
    __asm__ volatile("syscall"
        : "+r"(rax)
        : "r"(rdi), "r"(rsi), "r"(rdx)
        : "rcx", "r11", "memory");
    return rax;
}

/* An fstat-errno test: fstat a bad fd and read the raw -errno from RAX. */
struct fstat_errno_case { const char *name; unsigned long long fd; long ret; };
static const struct fstat_errno_case fstat_errno_cases[] = {
#include "gen/fstat_errno_cases.inc"
};

/* An fstat-ok test: fstat a valid fd and confirm RAX is 0 (success). */
struct fstat_ok_case { const char *name; unsigned long long fd; };
static const struct fstat_ok_case fstat_ok_cases[] = {
#include "gen/fstat_ok_cases.inc"
};

static long raw_fstat(unsigned long long fd, void *statbuf) {
    register long rax __asm__("rax") = 5;               /* sys_fstat */
    register long rdi __asm__("rdi") = (long) fd;
    register long rsi __asm__("rsi") = (long) statbuf;
    __asm__ volatile("syscall"
        : "+r"(rax)
        : "r"(rdi), "r"(rsi)
        : "rcx", "r11", "memory");
    return rax;
}

static long raw_write(unsigned long long fd, const void *buf, long count) {
    register long rax __asm__("rax") = 1;               /* sys_write */
    register long rdi __asm__("rdi") = (long) fd;
    register long rsi __asm__("rsi") = (long) buf;
    register long rdx __asm__("rdx") = count;
    __asm__ volatile("syscall"
        : "+r"(rax)
        : "r"(rdi), "r"(rsi), "r"(rdx)
        : "rcx", "r11", "memory");
    return rax;
}

static long raw_mmap(const struct mmap_case *c) {
    register long rax __asm__("rax") = 9;              /* sys_mmap */
    register long rdi __asm__("rdi") = (long) c->addr;
    register long rsi __asm__("rsi") = (long) c->length;
    register long rdx __asm__("rdx") = (long) c->prot;
    register long r10 __asm__("r10") = (long) c->flags;
    register long r8  __asm__("r8")  = c->fd;
    register long r9  __asm__("r9")  = (long) c->off;
    __asm__ volatile("syscall"
        : "+r"(rax)
        : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return rax;
}

int main(void) {
    int fails = 0;
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 2; }
        if (pid == 0) {
            /* child: raw exit(2) syscall, number 60, argument in RDI. */
            register long rax __asm__("rax") = 60;
            register long rdi __asm__("rdi") = (long) cases[i].rdi;
            __asm__ volatile("syscall" : : "r"(rax), "r"(rdi) : "rcx", "r11");
            _exit(123); /* unreachable */
        }
        int st;
        if (waitpid(pid, &st, 0) < 0) { perror("waitpid"); return 2; }
        int got = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        int ok = got == cases[i].code;
        printf("%-16s exit(%#llx) -> WEXITSTATUS=%d (model: %d) %s\n",
               cases[i].name, cases[i].rdi, got, cases[i].code, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    for (unsigned i = 0; i < sizeof fault_cases / sizeof fault_cases[0]; i++) {
        const struct fault_case *f = &fault_cases[i];
        void *page = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int got = -1;
        if (page != MAP_FAILED) {
            memcpy(page, f->code, f->len);
            pid_t pid = fork();
            if (pid == 0) { ((void (*)(void)) page)(); _exit(0); }  /* faults, never returns */
            int st;
            if (waitpid(pid, &st, 0) >= 0)
                got = WIFSIGNALED(st) ? 128 + WTERMSIG(st)
                    : WIFEXITED(st)   ? WEXITSTATUS(st) : -1;
            munmap(page, 4096);
        }
        int ok = got == f->exit_code;
        printf("%-16s fault -> $?=%d (model: %d) %s\n",
               f->name, got, f->exit_code, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    for (unsigned i = 0; i < sizeof mmap_cases / sizeof mmap_cases[0]; i++) {
        long got = raw_mmap(&mmap_cases[i]);
        int ok = got == mmap_cases[i].ret;
        printf("%-16s mmap -> RAX=%ld (model: %ld) %s\n",
               mmap_cases[i].name, got, mmap_cases[i].ret, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    for (unsigned i = 0; i < sizeof mmap_ok_cases / sizeof mmap_ok_cases[0]; i++) {
        const struct mmap_ok_case *o = &mmap_ok_cases[i];
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 2; }
        if (pid == 0) {
            register long rax __asm__("rax") = 9;            /* sys_mmap */
            register long rdi __asm__("rdi") = (long) o->addr;
            register long rsi __asm__("rsi") = (long) o->length;
            register long rdx __asm__("rdx") = (long) o->prot;
            register long r10 __asm__("r10") = (long) o->flags;
            register long r8  __asm__("r8")  = o->fd;
            register long r9  __asm__("r9")  = (long) o->off;
            __asm__ volatile("syscall" : "+r"(rax)
                : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
                : "rcx", "r11", "memory");
            if (rax < 0 && rax >= -4095) _exit(2);           /* mmap itself failed */
            /* write a byte to the mapped buffer via inline asm, so the store is
             * not optimized away; a non-writable buffer would SIGSEGV here. */
            __asm__ volatile("movb $0, (%0)" :: "r"(rax) : "memory");
            _exit(0);
        }
        int st;
        if (waitpid(pid, &st, 0) < 0) { perror("waitpid"); return 2; }
        int ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
        printf("%-16s mmap+write -> %s (model: buffer supports a write) %s\n",
               o->name, WIFSIGNALED(st) ? "CRASHED (signal)" :
                        WIFEXITED(st) && WEXITSTATUS(st) == 2 ? "mmap failed" : "wrote ok",
               ok ? "ok" : "FAIL");
        fails += !ok;
    }
    for (unsigned i = 0; i < sizeof write_cases / sizeof write_cases[0]; i++) {
        const struct write_case *w = &write_cases[i];
        int pipefd[2], saved, ok = 0;
        long got = -1;
        unsigned char back[64] = {0};
        fflush(stdout);                      /* don't let buffered output leak into the pipe */
        if (pipe(pipefd) == 0 && (saved = dup(1)) >= 0) {
            dup2(pipefd[1], 1);              /* fd 1 now points at the pipe */
            got = raw_write(w->fd, w->data, w->count);
            dup2(saved, 1); close(saved);    /* restore real stdout */
            close(pipefd[1]);                /* only reader keeps the pipe open */
            long n = (got == w->count) ? read(pipefd[0], back, sizeof back) : -1;
            ok = got == w->count && n == w->count &&
                 memcmp(back, w->data, w->count) == 0;
            close(pipefd[0]);
        }
        printf("%-16s write -> RAX=%ld (model: %d), stream grew by %d bytes %s\n",
               w->name, got, w->count, ok ? w->count : 0, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    for (unsigned i = 0; i < sizeof read_cases / sizeof read_cases[0]; i++) {
        const struct read_case *r = &read_cases[i];
        int pipefd[2], saved, ok = 0;
        long got = -1;
        unsigned char buf[64] = {0};
        if (pipe(pipefd) == 0 && (saved = dup(0)) >= 0) {
            write(pipefd[1], r->data, r->count);   /* preload stdin */
            close(pipefd[1]);
            dup2(pipefd[0], 0);                     /* fd 0 now reads the pipe */
            got = raw_read(0, buf, r->count);
            dup2(saved, 0); close(saved);           /* restore real stdin */
            close(pipefd[0]);
            ok = got == r->count && memcmp(buf, r->data, r->count) == 0;
        }
        printf("%-16s read -> RAX=%ld (model: %d), buffer got %d bytes %s\n",
               r->name, got, r->count, ok ? r->count : 0, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    for (unsigned i = 0; i < sizeof write_errno_cases / sizeof write_errno_cases[0]; i++) {
        const struct write_errno_case *w = &write_errno_cases[i];
        char scratch[8] = {0};
        long got = raw_write(w->fd, scratch, w->count);
        int ok = got == w->ret;
        printf("%-16s write -> RAX=%ld (model: %ld) %s\n",
               w->name, got, w->ret, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    for (unsigned i = 0; i < sizeof read_errno_cases / sizeof read_errno_cases[0]; i++) {
        const struct read_errno_case *r = &read_errno_cases[i];
        char scratch[8] = {0};
        long got = raw_read(r->fd, scratch, r->count);
        int ok = got == r->ret;
        printf("%-16s read -> RAX=%ld (model: %ld) %s\n",
               r->name, got, r->ret, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    for (unsigned i = 0; i < sizeof open_errno_cases / sizeof open_errno_cases[0]; i++) {
        const struct open_errno_case *o = &open_errno_cases[i];
        long got = raw_open(o->path, 0 /* O_RDONLY */, 0);
        int ok = got == o->ret;
        printf("%-16s open -> RAX=%ld (model: %ld) %s\n",
               o->name, got, o->ret, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    for (unsigned i = 0; i < sizeof fstat_errno_cases / sizeof fstat_errno_cases[0]; i++) {
        const struct fstat_errno_case *f = &fstat_errno_cases[i];
        char statbuf[144] = {0};
        long got = raw_fstat(f->fd, statbuf);
        int ok = got == f->ret;
        printf("%-16s fstat -> RAX=%ld (model: %ld) %s\n",
               f->name, got, f->ret, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    for (unsigned i = 0; i < sizeof fstat_ok_cases / sizeof fstat_ok_cases[0]; i++) {
        const struct fstat_ok_case *f = &fstat_ok_cases[i];
        char statbuf[144] = {0};
        long got = raw_fstat(f->fd, statbuf);
        int ok = got == 0;
        printf("%-16s fstat -> RAX=%ld (model: 0) %s\n",
               f->name, got, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    for (unsigned i = 0; i < sizeof open_ok_cases / sizeof open_ok_cases[0]; i++) {
        const struct open_ok_case *o = &open_ok_cases[i];
        long got = raw_open(o->path, 0 /* O_RDONLY */, 0);
        int ok = got >= 0;             /* a valid fd, not an errno (the model: ~isIOError) */
        if (got >= 0) close((int) got);
        printf("%-16s open -> RAX=%ld (model: a good fd, not an error) %s\n",
               o->name, got, ok ? "ok" : "FAIL");
        fails += !ok;
    }
    unsigned total =
        sizeof cases / sizeof cases[0] +
        sizeof fault_cases / sizeof fault_cases[0] +
        sizeof mmap_cases / sizeof mmap_cases[0] +
        sizeof mmap_ok_cases / sizeof mmap_ok_cases[0] +
        sizeof write_cases / sizeof write_cases[0] +
        sizeof read_cases / sizeof read_cases[0] +
        sizeof write_errno_cases / sizeof write_errno_cases[0] +
        sizeof read_errno_cases / sizeof read_errno_cases[0] +
        sizeof open_errno_cases / sizeof open_errno_cases[0] +
        sizeof open_ok_cases / sizeof open_ok_cases[0] +
        sizeof fstat_errno_cases / sizeof fstat_errno_cases[0] +
        sizeof fstat_ok_cases / sizeof fstat_ok_cases[0];
    printf("%u tests, %d disagreements\n", total, fails);
    return fails ? 1 : 0;
}
