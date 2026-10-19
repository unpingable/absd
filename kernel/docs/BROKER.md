# Init-brokered spawning

A durable workload that must run other programs (Nightshift's writer runs
`nq` and `pulse-support-resolver`) does not get the kernel's spawn
right. It asks init; init decides against a fixed workflow policy,
starts the program as its own child with handles it chooses, and reports
the outcome. This is not fork/exec and not a process manager: the catalog
is still the embedded program table, there is no PATH, no environment, and
no shell parsing. A process that does hold the spawn right starts files
from the filesystem itself with `spawn_image` instead; the startup record
below is shared with that path, whose whole contract is
docs/PROCESS-STARTUP.md.

## Kernel: the spawn right only narrows

Every process carries a spawn right. Init has it. A child has it only if
its parent has it and the spawn did not carry `SPAWN_NO_SPAWN` (bit 33 of
the program word, accepted by both `spawn` and `spawn_many_copy`, and the
flags argument of `spawn_image`). A process without it gets `ERROR_RIGHTS`
from every spawn call. Nothing restores it.

## Handles

In broker mode init starts the durable worker with `SPAWN_NO_SPAWN` and
this startup vector (multi-start ABI):

    [startup, input, block, step, request, reply, slot 0 stdin, slot 0 stdout,
     slot 0 stderr, ..., slot K-1 stderr, console]

`startup` is a read-only pipe carrying the startup record below. `request`
is the write end of a pipe init reads; `reply` the read end of a pipe init
writes. A slot is three pipes made in advance: the worker holds the write
end of the child's stdin and the read ends of its stdout and stderr; init
holds the other ends until it spends the slot. Each slot is used at most
once, so a workload gets at most K brokered processes, where policy sets
K (`slots worker K`, at most 4).

A brokered child starts with `SPAWN_NO_SPAWN` and

    [startup, stdin, stdout, stderr, (block read-only), stdout-as-console]

Its stdout write end is its console, and is also named in the vector so a
child's vector always has five or more entries: it has no handle to the real
console.
Its block handle, only when policy says so, is a read-only duplicate.

When init spends a slot it closes its own copies of the child's ends, so the
worker sees end-of-file on stdout and stderr exactly when the child (the
only remaining writer) exits, and the child sees end-of-file on stdin when
the worker closes its writer.

## Startup record

Programs built on the Rust platform recognise a vector of five or more
handles as this shape (two and four remain the older fixed shapes). The
record is everything on the startup pipe until end-of-file:

    "ABSDSU01"
    u16 role_count, role_count x { u8 role, u8 index }
    u16 argc, argc x { u16 length, bytes }        (argc 0: no runtime argv)
    [u16 envc, envc x { u16 length, "KEY=VALUE" }] (optional; absent = none)
    [u16 length, working directory]                (optional; never written by init)
    [u16 length, program name]                     (optional; never written by init)

Integers are little-endian; `index` is a position in the startup vector.
Roles: 1 stdin, 2 stdout (the console's pipe), 3 stderr, 4 block, 5 step, 6 request, 7 reply,
8 slot stdin, 9 slot stdout, 10 slot stderr (slot roles appear in slot
order), 11 fs (a read-only view to mount; docs/PROCESS-STARTUP.md), 12 nic
(the NIC handle of a `net` boot, docs/NETWORK.md; a worker holding it always
gets a startup record, even without a broker policy, and brokered children
never get it), 13 fs request and 14 fs reply (a file server channel,
docs/PROCESS-STARTUP.md), 15 machine (a stop-only machine handle for a
qualification durable worker), 16 and 17 (the platform's session control
channels, written by sshd, never by init), 18 liveness (a served service's
heartbeat cell, read and write rights; docs/service-lifecycle-20261008/
LIVENESS.md). stdout is always the console. Every vector entry but the first
(the startup pipe) and the last (the console) carries exactly one role;
request and reply come together, and slots need them.

## Requests and replies

A request, written whole to `request`:

    "ABSDBR01" u8 kind=1 u8 slot u16 path_len path u16 argc argc x { u16 len, bytes }

at most 4096 bytes, argc at most 32. Replies on `reply` are 24 bytes:

    "ABSDBP01" u8 kind u8 slot u16 0 u32 code u64 value

- kind 1 STARTED: value = the child's pid;
- kind 2 REFUSED: code = 1 not permitted, 2 slot unavailable, 3 malformed,
  4 could not start (no resources, or an image the kernel refuses);
- kind 3 EXITED: value = the outcome as i64 (exit status; a fault is
  -1000 - vector; killed is -1). A negative exit status cannot be told apart from
  these, so requesters treat every negative value as abnormal.

A slot's STARTED always precedes its EXITED; replies for different slots may
interleave. Init never blocks on a reply: the reply pipe holds 42 whole
replies, and when one does not fit init closes the channel instead (the
requester reads every whole reply, at most a fragment, then end-of-file)
and reads no more requests from it.

## Policy

Init embeds the workflow policy at build time (`BROKER_POLICY`). One line per
permitted edge:

    allow worker <path> <catalog program> <block: none|read> <free args> <fixed arg>...
    env <catalog program> KEY=VALUE

A request is permitted only if its path equals `<path>` exactly and its argv
is the fixed arguments followed by exactly `<free args>` more. Everything
else is refused. The requester's identity is the channel the request came
on, never a claim inside it. `env` lines give a program its whole
environment: nothing is inherited and a requester cannot set any.

## Lifetime

- The worker exits, dies, or is ended by init (deadline, a failed
  collection): init reads nothing more from its channel, kills
  every brokered child still running for it, reaps them, and closes every
  slot handle, before the reader or a replacement worker starts.
- A child exits or faults: init reaps it and replies EXITED.
- A refused request spends nothing and leaves init holding nothing. A
  request for a spent slot is refused.
- init's shutdown is the end of the durable boot; nothing brokered
  outlives it.
