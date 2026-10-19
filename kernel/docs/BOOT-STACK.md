# BSP bootstrap stack and ACPI

The x86 bootstrap stack is 32 KiB, with a separate 4 KiB painted canary
immediately below it. Neither is a process allocation. Both remain inside the
kernel's reserved image range. This costs 20 KiB more static RAM than the old
16 KiB stack; the exact linked section and frame-availability deltas belong in
the qualification receipt.

## The demonstrated defect

On kernel 8 (`929a8efd`), a debugger write watchpoint caught
`acpi::push_cpu` writing a MADT entry into `sched::STATS`. RSP was 0x4b7c20,
below the bootstrap stack bottom 0x4b9000. CPU1 was still firmware-halted.
`kernel_main`, the inlined root/MADT reporting path and `parse_madt` together
used 21,472 bytes. Their fixed arrays and by-value results exceeded the old
16 KiB stack. MADT entry count does not determine these frame sizes.

The defect dates to the executable ACPI report in `efa067b`, before kernel5.
Direct one-CPU debugger observations reproduce it at that source and at
kernel5, kernel6, kernel7b and kernel7c. Later frame/layout changes altered
which globals were overwritten. Some historical default boots printed
`RT WORKLOAD OK` because the overflow changed `BOOT_MODE`. A successful exit
therefore did not establish that the requested suite had run.

Plain one-CPU default boots without ACPI passed at exact kernel6 and kernel7b
in the diagnosis. This does not requalify every historical served workload.

## Mechanism and boundary

Assembly paints the canary and usable stack before the first Rust call, with
interrupts disabled, preserving the Multiboot pointer and call alignment.
After ACPI returns and before AP startup, `report_boot_stack` checks every
canary qword and scans the usable stack for its lowest changed qword. It
prints usable capacity, observed use, remaining margin and canary size. An
altered canary or margin below 2 KiB reports failure and halts through the
existing boot-failure path. No scheduler, frame-admission interface or
supported ABI changes.

The canary is outside usable capacity and spans one compiler stack-probe
interval. It can detect writes below the stack that a touched-byte margin
alone might miss. It is not an unmapped guard page and cannot prevent an
out-of-bounds write before the check. An arbitrary jump beyond the canary,
different probing behavior or later boot path needs separate qualification.
Paint measures changed bytes, not an exact maximum RSP depth. Non-ACPI boots
are not measured by this check. The boot stacks and task/AP stacks are
different allocations.

The smaller alternative was to change the ACPI parser to fill caller-provided
storage and avoid its large returned aggregates. That is a useful follow-on,
but enlarging this fixed early stack fixes the observed defect without a new
parser storage lifetime or page-table mechanism. A hardware guard would need
a split of the current 2 MiB bootstrap identity mapping.

## Qualification

`make acpi-test` checks stack capacity, canary size and margin on every case,
including expected ACPI refusals. Its full-default SMP case also requires
default frame/counter summaries and rejects alternate-mode success receipts.
Every `BOOT STACK` record counts, including malformed or failure records.
CRLF normalization retains changed raw serial bytes alongside the normalized
log. Exact binaries, commands, negative controls, source identities and
independent review are retained in the `smp2-suite-diagnosis-20261017` lane.

The initial 32 KiB source `26363d65` passed all 13 canonical ACPI cases and
additional full-default repeats, with 21,472 observed bytes used and 11,296
bytes of margin. Its actual 16 KiB negative build refused before AP startup.
The later below-stack-canary source requires its own execution evidence;
those earlier results do not qualify a different binary. Independent source
and host review is distinct from guest execution and acceptance.

These claims concern the named compiler profiles, binaries and boot paths.
Practical binary inspection, actual writes/RSP observations and bounded
negative executions are appropriate for this fix. They do not prove all
future call graphs or universal memory safety.

## Kernel generation replacement

This stack belongs to one kernel generation and has no exported state schema.
An active Rust stack cannot be rebound to a successor image. A future
replacement must establish a successor-owned stack, fence the old execution
and validate its entry before committing; old stack capacity remains reserved
until no CPU can use it. This fix adds no state-transfer or rollback mechanism
and establishes no safe hardware-transfer claim.
