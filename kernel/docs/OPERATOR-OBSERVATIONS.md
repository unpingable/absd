# Operator observations (experimental development profile)

`ps -A` and `interfaces` query the kernel directly, through an explicit inherited
read-only Diagnostics capability. They need neither the SSH
network owner nor a working file server to acquire their observations.
Starting a filesystem executable still needs its executable bytes. A local
maintenance view is composed separately; this slice does not install a
network-independent or storage-independent launcher.

Experimental syscall `0x7fc1(handle, address, query)` writes a 256-byte
little-endian record, version 1. A zero handle resolves an existing read-only Diagnostics capability; a
nonzero handle must name that exact live capability. Only root init may use
its physical Console as a maintenance fallback. Init mints diagnostic read
authority and explicitly delegates it through startup role 20; ordinary
children cannot mint it, steal input or write to the physical console. No mutation,
process-control, raw memory, device or network transmit authority is granted.
This is branch-local engineering, not a supported-ABI promotion.

Device queries (256 and 512 through 767) require UP/BSP execution. A caller
on an AP receives ERROR_NOT_IMPLEMENTED before memory or device access,
which interfaces reports as unsupported. Holding Diagnostics does not pin
all operator children to the BSP. Process rows and retained-log reads do
not acquire hardware through these device query paths. This slice makes no
SMP interface-availability claim; a BSP query route is separate #125 work.
The host dispatch fixture executes the real syscall body and grant helpers
with controlled CPU, memory and device boundaries. Its scope excludes real
page-table validation, hardware and scheduler execution.

Queries 0 through 15 read process table positions. Words are version, kind=1,
capture ticks, position, PID, parent PID, image index, state, wait kind, handle
count, signed exit code, fault vector, CPU owner claim or UINT64_MAX, CPU claim
epoch, and spawn permission. Remaining bytes are zero. No command arguments,
fault addresses, kernel pointers or private buffers are exposed. PID identity
is scoped to the boot. Each row is sampled separately, so a list is not an
atomic census. Running and runnable are distinct; waiting names the actual
wait class. CPU percentages and process memory are unavailable.

Query 256 captures the selected NIC: words version, kind=2, start ticks,
driver (1=e1000, 2=i219, 3=rtl8125), initialized, disabled, carrier, reserved,
packed PCI address, end ticks. Reserved word 7 is UINT64_MAX. Bytes 80 through 85
hold its MAC. PCI/MAC identity comes from the boot probe; driver state and
counters use the current driver info sample. Words 11 through 16 hold RX
delivered/refused/missed and TX completed/refused/errors when the sample is
available. An unknown disabled field marks an unavailable sample; counter
words then contain unused zero placeholders, which consumers report as unknown.
Words 17 and 18 are UINT64_MAX until speed and duplex are established.
Carrier is unknown after a failed read or disable, never an older UP value.
Readout uses the existing driver's info method, which can detect and settle
a device fault; it cannot clear quarantine or reprobe the device.

Queries 512 through 767 enumerate Ethernet-class PCI functions by position.
Words version, kind=3, ticks, position, packed PCI address, vendor, device,
selected, revision are followed by zeroes. Enumeration uses configuration
reads only and grants no DMA or admission. A physical jack's position is
unknown until an operator observes its mapping; PCI order is insufficient.
An absent position returns -2. Packed addresses are bus<<8 | device<<3 |
function. Unknown is UINT64_MAX, never zero substituted for a failed read.

`interfaces` supplies current device observations. `net-status` separately
supplies the SSH owner's boot/recovery-bound retained address/route sample.
The latter is historical evidence with an explicit age, not current owner
liveness or peer reachability. Use a real exchange to establish reachability.

The accepted hardware_fixture RTL8125 driver is preserved byte for byte by this slice.
Its existing containment and receive behavior remains attached to that
accepted source and evidence. This slice adds readout, without importing an
older driver implementation or establishing new physical results. Cable
reconnection does not clear device quarantine.

The kernel's pure encoders and the real platform runtime/CLI consumers share
`tests/fixtures/observation-*-v1.hex` vectors for process, selected NIC,
unavailable NIC, and selected/inactive PCI-candidate records. The platform
host checks compile actual ps/interfaces against a controlled transport;
the kernel checks its actual encoders. These establish layout correspondence,
not device correctness, syscall authority or coherent whole-machine snapshots.
The separate grant/handle tests and exact-pair guest checks cover their own
scope. Claude git-0a owns candidate acceptance.

Replacement constraints: process PIDs and NIC selection are boot-local, and
observation records contain no transferable authority. A replacement kernel
would need an explicit versioned conversion of diagnostic and selection
state plus separately established device quiescence and authority transfer.
These snapshots do not implement or prove live replacement or rollback.


## Bounded physical Console input loss

The kernel physical Console FIFO retains up to 8192 bytes, preserving enqueue
order and dropping new bytes beyond that bound. UART receive work remains at
most sixteen bytes per interrupt; input is serialized on the BSP. This is
bounded queue headroom, not physical flow control or an end-to-end delivery
claim for an arbitrary burst or consumer schedule. This slice installs no init
local-console relay, authentication or maintenance path.

At the Console read boundary, new serial/keyboard loss counts produce a
count-only `console-input` warning in the volatile kernel ring. No entered
bytes are included. Publication is attempted at most once per 1000 ticks;
a busy ring defers the count until a later read, and ordinary ring loss and
retention bounds still apply. No reader means no independent loss supervisor.
The warning identifies an incomplete input stream; it cannot recover a suffix
or establish that the consumer canceled the incomplete command.

The retained 393-byte reproduction, 4096-byte terminated line and two coalesced
4096-byte lines exercise the actual FIFO and readout in host tests. Wrap,
source order, over-capacity drop-newest behavior, count-only warnings and busy
publication are also checked. Init relay and actual UART/worker scheduling are
outside those tests. A later local-console slice must carry the matching relay
headroom separately and recheck its complete installed path. Claude git-0a
owns candidate acceptance; the original parent guest's coalesced-line outcome
remains unknown. Private input state is not a live-transfer schema, and this
change makes no replacement or post-effect rollback claim.
