# Exact-peer directed ARP proof successor

Native run ebbd8acf remains FAIL. Its original runner, raw capture, serial,
verdict and every runtime/build input are unchanged. The first rejected frame
was Linux 192.0.2.1 / 52:55:00:00:03:01 requesting guest 192.0.2.100, with
Ethernet destination 52:54:00:12:34:56 and zero ARP target MAC. The same directed
neighbor request repeats in the capture. Native lease acquisition, DNS answer,
child exit and clean boot markers were present; later capture predicates did
not execute, so those markers did not qualify the original case.

`scripts/native-dhcp-directed-arp-matrix.py` is a distinct new runner, copied
with all original boot, DORA, ARP probe/announcement, paired resolver exchange,
DNS, counter, lease, normal-exit and cleanup predicates preserved. Its only
packet-envelope change recognizes Linux ARP requests whose Ethernet source
and ARP sender MAC are the exact configured peer, sender IP is that peer or
zero, target IP is this guest, operation is request, target MAC is zero, and
Ethernet destination is broadcast or this guest. It admits no other unicast
peer, traffic-derived capability or DHCP/runtime change. Directed neighbor
resolution is explained independently of the application grant.

Run identity 08638bdf-dcbc-4925-8575-c32f6441fe1a records exact source and result pointers in
the shared lane registry. Source checks and authored envelope controls are not
native execution. A fresh independently reviewed case is required; old verdicts
cannot change. Native malformed DHCP, exhaustion, conflict, interruption,
lease fencing, renewal/rebind, physical timing and live SSH remain UNRUN.

Formalization consideration: finite exact Ether/ARP tuple checks and negative
substitutions suffice for this qualification-envelope correction. They prove
neither frame delivery nor physical lease accuracy. No runtime object/state
or authority schema changes, handle revival or hardware-transfer claim occurs.
Decision owners are root/integration steward. Existing release/main/U1/ABI holds
remain. Root owns existing source/custody allocation; retain exact commits and
minimal receipts, retire reproducible scratch after review/replay users end;
next review 2026-10-17.
