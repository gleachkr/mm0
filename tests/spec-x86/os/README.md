# OS-layer spec tests

The syscall/ELF analogue of the instruction suite one directory up. Where that
tests `step k k2` on a `Config`, this tests the Linux syscall layer of
`examples/x86.mm0` — `execExit`, `execIO`, `initialConfig`, on a `KernelState` —
and is the formal half of the probes in `../os-audit/`.

Each row of `manifest.py` is checked two ways:

- **in the semantics** — an MM0 theorem in `os_tests.mm1`, proved and checked
  against the contract `os_tests.mm0` by `mm0-c`;
- **on hardware** — a real syscall runs and the observable comes back as the
  model says (the harness reads the same rows from `gen/cases.inc`).

There is no encoding oracle: the `syscall` opcode `0f 05` is already covered by
the instruction suite; the content here is the kernel dispatch, not the decode.

## Positive facts catch the audit's bugs here

The instruction suite can only state positive facts (`E. k2 (step …)`), and its
README notes the corollary: a bug that makes the model *too permissive* escapes
it. For the OS layer that corollary is largely **inverted**, because the model is
demonic. Every fix from the audit (`os-audit/x86-os-audit-v2.md`) *enables a
successor the buggy model excluded*, so a positive `execExit` / `E. ks2 (execIO
… /\ observable)` claim pins exactly the fix:

| fix | test that holds only with the fix |
|---|---|
| C2 exit masking | `test_exit_256`: `exit(256)` reports code **0**, so `execExit` must take the low byte of `RDI` |
| F1 mmap errno | `test_mmap_einval`: `execIO` can return `-EINVAL` (`bitsNeg 64 22`), not the pinned `-1` = MAP_FAILED the old model forced |
| F8 fd truncation | `test_write`: a `write` with `RDI = 0x1_0000_0001` still tracks stdout, because the fd is read as 32 bits |
| F7 reads deliver data | `test_read`: a `read` grows the input log by the delivered bytes and returns the count |
| exUD | a `ud2` state is a good exit *(planned)* |

The successor tests state their claim as `E. k2 E. m2 (execIO (mkKS i o k m)
(mkKS … k2 m2) /\ readReg k2 RAX = …)`: the `mkKS` exposes exactly which stream
changed (output `o ++ buf` for write, input `i ++ l1` for read, unchanged for
mmap) and existentially quantifies the resulting config and page-mapping.

`test_mmap_einval` is a positive `E. ks2 (execIO … /\ readReg (ksCfg ks2) RAX =
-EINVAL)`: the model *permits* the `-EINVAL` successor. The pre-F1 model pinned
mmap's failure return to exactly `-1`, so it could not prove this. On hardware the
harness makes the same raw `mmap(NULL, 0, …)` syscall — bypassing glibc, which
would fold `-errno` into `MAP_FAILED`+`errno` — and reads `-22` straight out of
`RAX`, the value the theorem names.

`test_write` is the write analogue and also pins a bug: with `RDI = 0x1_0000_0001`
the model reads the fd as `readRegSz k wSz32 RDI` (32-bit), so the high word drops
and the fd is `stdout`; the bytes append to the output stream and RAX is the count.
Reading the full 64-bit RDI would give an invalid fd and drop the write. The
harness routes fd 1 through a pipe, makes the raw `write` syscall with the high-bit
fd, and confirms both the byte count in RAX and that the bytes arrived — i.e. the
kernel really did truncate the fd.

`test_read` is the input direction (F7): the `read` delivers its bytes into the
buffer (`writeMem`, which the model can only do once the exception is cleared) and
the input log grows by exactly them. The harness preloads stdin through a pipe,
makes the raw `read`, and checks the buffer received the bytes and RAX is the
count — the read is not the no-op the pre-fix model allowed.

## Running

```sh
./run.sh            # from this directory; needs mm0-rs, mm0-c, a C compiler
TERSE=1 ./run.sh    # one line per check
```

## Files

| file | |
|---|---|
| `manifest.py` | **the source of truth.** One row per test: syscall args in, observable out |
| `gen.py` | generates the two files below; `--check` fails if a committed one is stale |
| `os_tests.mm0` | *(generated)* the contract — one theorem statement per test |
| `gen/cases.inc` | *(generated)* the same rows as a C table for the harness |
| `os_tests.mm1` | **hand-written.** The proofs |
| `harness.c` | forks a child per case, runs the raw syscall, checks the observable |

## Adding a test

Add a row to `manifest.py`, run `./gen.py`, and add the proof to `os_tests.mm1`
in the same position (declaration order must match — `mm0-c`'s diagnostic for a
mismatch points at the *following* theorem). Literals in the `.mm1` are written
with `,0x…` splices; the `.mm0` needs the elaborated `:x` hex form, which `gen.py`
emits. The MM1 proof loop (LSP hover) is described in the `mm1-proofs` skill.
