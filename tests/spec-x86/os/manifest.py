#!/usr/bin/env python3
r"""Source of truth for the OS-layer spec test suite -- the syscall/ELF analogue
of the instruction suite one directory up.

Where that suite tests `step k k2` on a `Config`, this one tests the Linux
syscall layer of `examples/x86.mm0`: `execExit`, `execIO`, `initialConfig`, on a
`KernelState`. Each row is checked two ways:

  * **in the semantics** -- an MM0 theorem in os_tests.mm1, checked against the
    contract os_tests.mm0 by `mm0-c`;
  * **on hardware** -- a real syscall runs and the observable comes back as the
    model says (the harness reads the same rows from gen/cases.inc).

There is no encoding oracle: the `syscall` opcode `0f 05` is already covered by
the instruction suite; the interesting content is the kernel dispatch, not the
decode.

Unlike the instruction suite, positive facts here *do* catch the audit's bugs.
The model is demonic, so every audit fix enables a successor the buggy model
excluded, and an `E. ks2 (execIO ... /\ observable)` claim (or an `execExit`
claim) pins exactly that. `test_exit_256` is the first example: it holds only
because the C2 exit-status-masking fix takes the low byte of RDI.

`gen.py` turns this file into os_tests.mm0 and gen/cases.inc; `--check` fails if a
committed file is stale.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class MMapErr:
    """A failing `mmap` returns `-errno` in RAX -- an arbitrary error in the
    `(2^64 - 4096, 2^64)` band, not the pinned `-1` the pre-F1 model forced.
    The theorem exhibits `-errno` as a permitted `execIO` successor; the harness
    makes the same raw syscall and reads the same value back from RAX."""
    name: str      # theorem name, and the harness's name for the case
    doc: str       # doc comment on the generated theorem
    errno: int     # the errno the kernel returns (e.g. 22 = EINVAL)
    # the raw mmap(2) argument registers that provoke `-errno` on real Linux.
    addr: int      # RDI  (0; the model requires addr = 0)
    length: int    # RSI  (0 -> EINVAL, before any fd/prot check)
    prot: int      # RDX  (must be a Prot, i.e. < 8)
    flags: int     # R10  (MAP_PRIVATE | MAP_ANONYMOUS = 34)
    fd: int        # R8   (-1 for an anonymous map)
    off: int       # R9   (0)

    @property
    def ret(self) -> int:
        """The raw kernel return in RAX: `-errno` as a 64-bit two's complement."""
        return (1 << 64) - self.errno


@dataclass(frozen=True)
class Read:
    """A `read` from stdin delivers the bytes into the buffer and grows the input
    log by exactly what was read, returning the count (F7). The theorem keeps the
    delivered bytes `l1` abstract (behind a `writeMem` hypothesis); the harness
    preloads stdin and checks the buffer and the return count."""
    name: str      # theorem name, and the harness's name for the case
    doc: str       # doc comment on the generated theorem
    data: bytes    # the bytes the harness feeds to stdin; count = len(data)


@dataclass(frozen=True)
class Write:
    """A `write` whose fd register has nonzero high 32 bits still hits `stdout`:
    the kernel reads the fd as an `int`, so `RDI = 2^32 + 1` truncates to fd 1.
    The bytes reach the output stream and RAX is the count -- both would be wrong
    if the model read the full 64-bit RDI (F6/F8). The theorem keeps the buffer
    abstract; the harness supplies a concrete one and captures fd 1."""
    name: str      # theorem name, and the harness's name for the case
    doc: str       # doc comment on the generated theorem
    fd: int        # RDI: the raw fd, high bits set (0x1_0000_0001)
    data: bytes    # the bytes the harness writes; count = len(data)


@dataclass(frozen=True)
class Exit:
    """`exit(rdi)` from a syscall-pending state is a good exit reporting
    `rdi & 0xff` -- the byte a parent's `waitpid` (`WEXITSTATUS`) observes."""
    name: str      # theorem name, and the harness's name for the case
    doc: str       # doc comment on the generated theorem
    rdi: int       # the value in RDI, i.e. the exit(2) argument

    @property
    def code(self) -> int:
        return self.rdi & 0xff


# In declaration order; os_tests.mm1's proofs must follow it (mm0-c ties the two
# together and its diagnostic for a mismatch points at the *following* theorem).
TESTS = [
    Exit("test_exit_0",   "`exit(0)` is a good exit reporting code 0 (success), "
                          "so the postcondition must hold of the run.", 0),
    Exit("test_exit_1",   "`exit(1)` reports code 1.", 1),
    Exit("test_exit_256", "`exit(256)` reports code 0: only the low byte of RDI "
                          "reaches the parent (`waitpid` sees `RDI & 0xff`), so "
                          "`256` masks to success. This is the C2 "
                          "exit-status-masking fix.", 0x100),
    Exit("test_exit_257", "`exit(257)` reports code 1 (`257 & 0xff = 1`).", 0x101),
    Exit("test_exit_255", "`exit(255)` reports code 255: the whole low byte is "
                          "observable.", 0xff),
]


@dataclass(frozen=True)
class FaultExit:
    """A faulting instruction is a valid *nonzero* exit. Unlike `exit(N)`, the
    fault config is not given: the process decodes and executes an instruction
    that raises a fault, setting the exception, and (no handler installed) dies by
    a signal -- the parent sees `WIFSIGNALED`, `$? = 128 + signo`, never a clean
    0. The theorem is `E. k2 (step k k2 /\\ execExit k2 (128 + signo))`: one
    `step` executes the faulting instruction, and the result is a nonzero
    `execExit`. `execExit`'s fault branch only requires `ret != 0`; pinning
    `ret = 128 + signo` aligns the model's exit code with the shell's `$?`."""
    name: str      # theorem name, and the harness's name for the case
    doc: str       # doc comment on the generated theorem
    instr: bytes   # the faulting instruction's bytes (in memory at RIP)
    exc: str       # the exception the model sets (e.g. "exUD")
    signo: int     # the signal the process dies by (e.g. 4 = SIGILL)
    # A memory-access fault (`#GP`/SIGSEGV) writes to this absolute address, which
    # must be non-writable; the theorem then carries page hypotheses about it. None
    # for a dedicated faulting instruction (`ud2`), whose fault needs no memory.
    fault_addr: "int | None" = None

    @property
    def code(self) -> int:
        """The nonzero exit code: the shell's `$? = 128 + signo` for a signal."""
        return 128 + self.signo


# Fault-exit tests. Declaration order in os_tests.mm0 is the exit rows, then
# these, then mmap.
#   * `ud2` (`#UD` -> SIGILL): a dedicated faulting instruction (`xastUD2` sets
#     `exUD` directly), no memory needed.
#   * `mov [0x7b], rax` (`#GP` -> SIGSEGV): a faulting memory WRITE -- the store to
#     the unmapped low address `0x7b` sets `exGPF` via `writeMemory1`. Assembled
#     through `assembler-new`'s (sorry-axiomatized) `parseMovStore`.
FAULT_TESTS = [
    FaultExit("test_fault_ud",
              "`ud2` (`0f 0b`) raises `#UD` (undefined instruction), which the "
              "model records as `exUD`. With no handler the process dies by "
              "`SIGILL`, observed as `$? = 132` -- a valid nonzero exit, never a "
              "clean 0.",
              instr=b"\x0f\x0b", exc="exUD", signo=4),
    FaultExit("test_fault_segv",
              "`mov [0x7b], rax` (`48 89 04 25 7b 00 00 00`) writes to the unmapped "
              "absolute address `0x7b`, raising `#GP` (`exGPF`). With no handler the "
              "process dies by `SIGSEGV`, observed as `$? = 139` -- a memory fault "
              "is a valid nonzero exit, not a clean 0.",
              instr=b"\x48\x89\x04\x25\x7b\x00\x00\x00", exc="exGPF", signo=11,
              fault_addr=0x7b),
]

# mmap tests. Kept separate from the exit rows because the observable is the
# raw RAX of an in-process syscall, not a forked child's exit status, so the
# harness runs them in a distinct loop. Declaration order in os_tests.mm0 is
# exit rows first, then these.
MMAP_TESTS = [
    MMapErr("test_mmap_einval",
            "`mmap(NULL, 0, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)` fails "
            "with `-EINVAL` (length 0). The model permits *any* `isIOError` "
            "return, so `-EINVAL` (not just the old `-1` = MAP_FAILED) is a "
            "legal `execIO` successor -- this is the F1 errno fix.",
            errno=22, addr=0, length=0, prot=1, flags=2 | 32, fd=-1, off=0),
    MMapErr("test_mmap_enomem",
            "`mmap(NULL, 2^63, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)` fails "
            "with `-ENOMEM` (the length can't be allocated) -- a *different* errno "
            "in the same band, so the model's `isIOError` return is not pinned to "
            "one value.",
            errno=12, addr=0, length=1 << 63, prot=1, flags=2 | 32, fd=-1, off=0),
    MMapErr("test_mmap_einval_file",
            "`mmap(NULL, 0, PROT_READ, MAP_PRIVATE, 0, 0)` -- a *file-backed* map "
            "(`MAP_PRIVATE` without `MAP_ANONYMOUS`, fd 0 = stdin) -- fails with "
            "`-EINVAL` (length 0). Exercises the other submask direction: "
            "`MAP_PRIVATE C_ MAP_PRIVATE` is `ssid`, and `MAP_ANONYMOUS C_ "
            "MAP_PRIVATE` is false so the model's fd = -1 obligation is vacuous. "
            "The fd must be valid (a bad fd would give `-EBADF` before the length "
            "check), so this uses stdin, not -1.",
            errno=22, addr=0, length=0, prot=1, flags=2, fd=0, off=0),
]


@dataclass(frozen=True)
class MMapOk:
    """A successful anonymous `mmap` returns a writable buffer. The address is the
    kernel's choice (nondeterministic), so the theorem asserts a good (`~isIOError`)
    return whose buffer *supports a write without faulting* -- the converse of the
    segv test. The harness maps the region, writes a byte to it via inline asm (so
    the store is not optimized out), and confirms the child does not die by a
    signal. The memory effect (`mapMem`) and the write's success are abstracted in
    the theorem (the hardware oracle exercises the real thing)."""
    name: str
    doc: str
    length: int    # RSI: the map length (a page)
    prot: int      # RDX: PROT_READ | PROT_WRITE
    flags: int     # R10: MAP_PRIVATE | MAP_ANONYMOUS
    fd: int        # R8:  -1 (anonymous)


MMAP_OK_TESTS = [
    MMapOk("test_mmap_ok",
           "`mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, "
           "0)` succeeds with a writable buffer: the return is not an IO error, and "
           "the buffer supports a write (no fault). The harness writes to it and "
           "checks the process does not crash -- the converse of the segv test.",
           length=4096, prot=1 | 2, flags=2 | 32, fd=-1),
]

# write tests. Like the mmap tests these read RAX from an in-process syscall,
# but they also capture fd 1 through a pipe to confirm the output stream grew.
# Declaration order in os_tests.mm0 is exit, then mmap, then these.
WRITE_TESTS = [
    Write("test_write",
          "`write(0x1_0000_0001, buf, count)` writes `buf` to `stdout`: the fd "
          "register's high 32 bits are dropped (the kernel reads it as `int`), so "
          "`2^32 + 1` truncates to fd 1. The output stream grows by `buf` and RAX "
          "is `count` -- both wrong if the model read the full 64-bit RDI (F6/F8).",
          fd=(1 << 32) | 1, data=b"mm0\n"),
]

# The buffer address a test can put in a register argument; the harness swaps in
# a real scratch pointer at runtime (the syscall fails on the fd before it would
# be dereferenced, so its content is irrelevant).
SCRATCH = -1000


@dataclass(frozen=True)
class WriteErrno:
    """A `write` to a bad fd returns `-errno` and leaves the output untouched --
    the shared `execIO_errno` driver's Write disjunct. The buffer is a scratch
    pointer; only the count and (bad) fd matter."""
    name: str
    doc: str
    fd: int        # RDI (the full 64-bit register); truncated to a bad int fd
    count: int     # RDX
    errno: int     # e.g. 9 = EBADF


WRITE_ERRNO_TESTS = [
    WriteErrno("test_write_ebadf",
               "`write(-1, buf, 1)` fails with `-EBADF`: the fd is invalid, so the "
               "write returns `-errno` and the output stream is unchanged.",
               fd=(1 << 64) - 1, count=1, errno=9),
]

# read tests. The harness preloads stdin through a pipe and reads it back.
# Declaration order in os_tests.mm0 is exit, mmap, write, then these.
READ_TESTS = [
    Read("test_read",
         "`read(0, buf, count)` from stdin delivers `count` bytes into the buffer "
         "and grows the input log by them (F7): the read is not a no-op, it writes "
         "the data into process memory and returns the count.",
         data=b"read!\n"),
]


@dataclass(frozen=True)
class ReadErrno:
    """A `read` from a bad fd returns `-errno` and leaves both the input stream
    and process memory untouched -- the shared `execIO_errno` driver's Read
    disjunct (the mirror of `WriteErrno`). The buffer is a scratch pointer; only
    the count and (bad) fd matter."""
    name: str
    doc: str
    fd: int        # RDI (the full 64-bit register); truncated to a bad int fd
    count: int     # RDX
    errno: int     # e.g. 9 = EBADF


READ_ERRNO_TESTS = [
    ReadErrno("test_read_ebadf",
              "`read(-1, buf, 1)` fails with `-EBADF`: the fd is invalid, so the "
              "read returns `-errno` and neither the input stream nor the buffer "
              "changes.",
              fd=(1 << 64) - 1, count=1, errno=9),
]


@dataclass(frozen=True)
class OpenErrno:
    """An `open` of a nonexistent path returns `-errno` directly -- `execOpen`
    has no `isIOError` branch, `ret e. u64` already admits any errno. The
    filename is kept abstract behind a `readCStr` hypothesis; the harness opens a
    concrete path that does not exist. Flags are `O_RDONLY`, mode is 0."""
    name: str
    doc: str
    path: str      # the nonexistent path the harness opens (RDI points at it)
    errno: int     # e.g. 2 = ENOENT


OPEN_ERRNO_TESTS = [
    OpenErrno("test_open_enoent",
              "`open(\"/_nope_\", O_RDONLY, 0)` fails with `-ENOENT`: no error "
              "branch in the model, the errno is just the `execOpen` return in the "
              "`u64` band. The filename is parsed concretely from the "
              "null-terminated bytes in memory (the model's `readCStr`/`toCStr`).",
              path="/_nope_", errno=2),
]


@dataclass(frozen=True)
class OpenOk:
    """A successful `open` returns a fd, which the kernel picks nondeterministically
    (the lowest free descriptor). So the postcondition EXISTS a return that is not
    an IO error (`~isIOError ret`), rather than pinning a fd value; the proof
    witnesses a concrete good fd and the harness confirms the real return is a
    valid (non-error) descriptor."""
    name: str
    doc: str
    path: str      # a path the harness can open (RDI points at it)


OPEN_OK_TESTS = [
    OpenOk("test_open_ok",
           "`open(\"/\", O_RDONLY, 0)` succeeds with a fd (`/` opens as a "
           "directory): the return is not an IO error. The value is the kernel's "
           "choice, so the theorem asserts a good (`~isIOError`) fd exists rather "
           "than a specific number. The filename is parsed concretely from memory.",
           path="/"),
]


@dataclass(frozen=True)
class FStatErrno:
    """An `fstat` of a bad fd returns `-errno`. Unlike the config-preserving
    cases, `execFStat`'s error branch still writes an (abstract) stat buffer, so
    the model's successor config is `setException kw 0`; the harness only checks
    RAX (real Linux leaves the buffer untouched, which the model over-permits).
    The input/output stat buffers are scratch pointers; only the (bad) fd matters."""
    name: str
    doc: str
    fd: int        # RDI (the full 64-bit register); truncated to a bad int fd
    errno: int     # e.g. 9 = EBADF


FSTAT_ERRNO_TESTS = [
    FStatErrno("test_fstat_ebadf",
               "`fstat(-1, &statbuf)` fails with `-EBADF`: the fd is invalid. The "
               "model's error branch may clobber the buffer (`writeMem`), so its "
               "successor is `setException kw 0`, but RAX = `-errno` is what both "
               "the model and the kernel agree on.",
               fd=(1 << 64) - 1, errno=9),
]


@dataclass(frozen=True)
class FStatOk:
    """A successful `fstat` on a valid fd returns 0 and writes the stat buffer --
    `execFStat`'s success branch (`ret = 0 /\\ writeMem … k2 /\\ readException k2
    = 0`). The written stat is abstract; the observable is the deterministic RAX =
    0. The model is demonic: it permits both this success and `-EBADF` for the same
    fd, so a positive `ret = 0` successor pins that success is a permitted step."""
    name: str
    doc: str
    fd: int        # RDI: a valid fd (0 = stdin, always open)


FSTAT_OK_TESTS = [
    FStatOk("test_fstat_ok",
            "`fstat(0, &statbuf)` on stdin succeeds with `0`: the model's success "
            "branch writes the stat buffer and returns 0. The demonic model also "
            "permits `-EBADF` here; this pins that success is a legal successor.",
            fd=0),
]
