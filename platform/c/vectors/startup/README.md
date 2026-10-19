# Startup-record vectors (ABSDSU01)

The startup record crosses the language line: a Rust parent (absd-sh,
`Command`, sshd) encodes it, and the runtime linked into a C program
parses it before `main`. These files pin that format with bytes produced
by the one encoder, `absd_broker::encode_startup` (broker/src/lib.rs).
docs/C-INTERFACE.md section 9 states the format; these are its vectors.

Each case `<name>` has two files:

- `<name>.bin`: the record bytes exactly as the encoder wrote them. Every
  one was also parsed back by `parse_startup` for the same vector size, and
  the test asserts the parsed argv, environment, cwd, name and roles equal
  its inputs byte for byte.
- `<name>.json`: what a C program started with that record must observe:
  `handle_count` (the startup vector's size: startup pipe, five roles,
  console), `roles` (`[role, vector index]` pairs: 1 stdin, 2 stdout,
  3 stderr, 13 file-server request, 14 file-server reply), `argv` (with
  `argv[0]` = the record's program name), `env` (`KEY=VALUE`, in record
  order, as `envp`/`environ` carry them), `cwd`, `name`, `bytes` (record
  length), `argc` (C's argc, counting `argv[0]`) and `envc`.

| case | what it pins |
|---|---|
| empty | no arguments, an empty environment section, cwd `/`, name `prog` |
| args | an argument with a space and an empty argument |
| env | an empty value (`EMPTY=`) and a value containing `=` (`EQ=a=b`) |
| utf8 | non-ASCII bytes in an argument and an environment value |
| maximal-fitting | the largest record of 1024-byte arguments the 8192-byte limit admits with 32 one-character environment entries: the test adds arguments until the encoder refuses and asserts the count it kept is 7 (argc 8, 7377 bytes) |
| maximal | `maximal.json` only: 32 arguments and 32 environment entries of 1024 bytes exceed 8192 bytes, the encoder refuses with `RequestError::TooLarge` (`"refused":true,"error":"TooLarge"`, asserted by the test), so no `.bin` exists |

Regenerate (host only; the files must come out byte-identical):

    R=/path/to/c-kit
    ABSD_EMIT_VECTORS=$R/c/vectors/startup env -u RUSTFLAGS cargo +1.95.0 test \
        --offline --release --manifest-path $R/broker/Cargo.toml \
        --target x86_64-unknown-linux-gnu --target-dir $R/.host-target \
        -p absd-broker emit_startup_vectors

The test `emit_startup_vectors` (broker/src/tests.rs) writes nothing
unless `ABSD_EMIT_VECTORS` is set, so the ordinary host gate
(scripts/check-all.sh) runs it as a no-op.

Consumer: `scripts/c-kit-matrix.py` (Task 12) runs the `c-args` test
program with each vector's argv, environment and cwd and compares the
program's echo of argc, argv, envp and getcwd with the JSON.
