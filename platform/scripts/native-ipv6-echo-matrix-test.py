#!/usr/bin/env python3
"""Authored deterministic artifact controls; execute only after host admission."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("echo_matrix", Path(__file__).with_name("native-ipv6-echo-matrix.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def wire_sum(data):
    value = 0
    for at in range(0, len(data), 2):
        value += (data[at] << 8) + (data[at + 1] if at + 1 < len(data) else 0)
        value = (value & 65535) + (value >> 16)
    return value ^ 65535


def frame(source, destination, body, outgoing=True, dstmac=None, hop=255):
    body = bytearray(body)
    body[2:4] = bytes(2)
    body[2:4] = wire_sum(source + destination + struct.pack("!I3xB", len(body), 58) + body).to_bytes(2, "big")
    return ((dstmac or (m.HOST_MAC if outgoing else m.GUEST_MAC)) + (m.GUEST_MAC if outgoing else m.HOST_MAC)
            + bytes.fromhex("86dd60000000") + struct.pack("!HBB", len(body), 58, hop) + source + destination + body)


def dad():
    return frame(bytes(16), m.SOL, b"\x87\0" + bytes(6) + m.GUEST, dstmac=bytes.fromhex("3333ff000015"))


def conflict():
    return frame(m.GUEST, m.ALL, b"\x88\0" + bytes(2) + bytes.fromhex("20000000") + m.GUEST
                 + b"\x02\x01" + m.HOST_MAC, False, bytes.fromhex("333300000001"))


def nd():
    ns = frame(m.GUEST, m.original.solicited(m.HOST), b"\x87\0" + bytes(6) + m.HOST + b"\x01\x01" + m.GUEST_MAC,
               dstmac=bytes.fromhex("3333ff000002"))
    na = frame(m.HOST, m.GUEST, b"\x88\0" + bytes(2) + bytes.fromhex("60000000") + m.HOST + b"\x02\x01" + m.HOST_MAC, False)
    return [ns, na]


def echo(outgoing=True, identifier=0x1234, sequence=0x5678, instance=1, epoch=1, nonce=0x0102030405060708):
    # ICMPv6 8-byte header plus the existing product's literal 32-byte body.
    body = struct.pack("!BBHHH", 128 if outgoing else 129, 0, 0, identifier, sequence)
    body += b"ABSDPNG6" + struct.pack("!QQQ", instance, epoch, nonce)
    return frame(m.GUEST if outgoing else m.HOST, m.HOST if outgoing else m.GUEST, body, outgoing, hop=64)


def mld():
    # Literal normal MLDv2 envelope from retained 67b03770 frame 1; no fixture
    # injection is performed by the native runner. This vector is parser-only.
    return (bytes.fromhex("33330000001652550000020286dd6000000000380001") + bytes(16)
            + bytes.fromhex("ff020000000000000000000000000016")
            + bytes.fromhex("3a000502000001008f006b6c0000000204000000ff0200000000000000000001ff00020204000000ff0200000000000000000001ff000002"))


def capture(frames):
    raw = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1)
    for at, packet in enumerate(frames):
        raw += struct.pack("<IIII", 1, at, len(packet), len(packet)) + packet
    return raw


def peer(case="positive"):
    tap = "echo6-tap0"
    addresses = [{"family": "inet6", "local": m.HOST_IP, "prefixlen": 64}]
    if case == "preassigned-conflict":
        addresses.append({"family": "inet6", "local": m.GUEST_IP, "prefixlen": 64})
    return {"case": case, "transport": "Linux kernel ICMPv6; no userspace responder or packet injection",
            "namespace_inode": 7, "tap": tap, "sysctls": m.peer_settings(tap, case),
            "links": [{"ifname": tap, "mtu": 1500, "address": m.HOST_MAC.hex(":"), "flags": ["UP"]}],
            "addresses": [{"ifname": tap, "addr_info": addresses}],
            "routes": [{"dst": "fd00:ab5d::/64", "dev": tap}], "sockets": ""}


def serial(case="positive", text=None):
    if text is None:
        if case == "preassigned-conflict":
            text = "PING6 SERVICE ERROR DAD acquisition refused Dad(Conflict)\n"
        else:
            text = ("PING6 OWNER invocation_start_ms=100 invocation_until_ms=12100 stop_ms=9000 current_ms=1002\n"
                    "PING6 DAD CLEAR local=fd00:ab5d::15 scope=1 auth=none uniqueness=unproven\n"
                    "PING6 SERVICE READY scope=1 peer=fd00:ab5d::2 requests=1\n")
            if case == "positive":
                text += ("PING6 CLIENT AUTHORITY PASS nic=0 denied=1\n"
                         "PING6 OBSERVED peer=fd00:ab5d::2 scope=1 identifier=4660 sequence=22136 instance=1 epoch=1 nonce=0102030405060708 boot_elapsed_ms=9 auth=none requests=1\n")
            text += ("PING6 SUBMISSION before_ms=1010 after_ms=1011 result=0 frame=" + echo().hex() + "\n"
                     "PING6 TERMINAL boot_ms=" + ("1020" if case == "positive" else "9000") + " attempts=1\n")
            if case == "positive":
                text += "PING6 SERVICE PASS child=exited sockets=0 probes=1 defenses=0 received=2 malformed=0\n"
            else:
                text += "PING6 SERVICE ERROR DAD after result read Expired\n"
    output = text.encode()
    raw = (b"NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n"
           b"EXTERNAL OUTPUT CHUNK offset=0000000000000000 data=" + output.hex().encode() + b"\n")
    if case != "preassigned-conflict":
        raw += b"SPAWN OK pid=3 parent=2 program=image\n"
        raw += b"USER EXIT pid=3 status=0\n" if case == "positive" else b"USER KILLED pid=3 by=2\n"
    success = case == "positive"
    raw += b"USER EXIT pid=2 status=" + (b"0" if success else b"1") + b"\n"
    raw += b"DURABLE WORKER OUTCOME generation=1 pid=2 status=" + (b"0" if success else b"1") + b"\n"
    if success:
        value = 0x811c9dc5
        for byte in output:
            value = ((value ^ byte) * 0x01000193) & 0xffffffff
        raw += b"EXTERNAL OUTPUT END bytes=" + str(len(output)).encode() + b" digest=" + f"{value:08x}".encode() + b"\n"
    else:
        raw += b"init: FAILED at durable worker outcome\n"
    raw += (b"DURABLE status=" + (b"0" if success else b"99")
            + b" frames=0 processes=0 cells=0 pipes=0 block_reads=0 block_writes=0 block_flushes=0 block_errors=0 block_waits=0 block_irqs=0 ticks=10000\n")
    raw += b"NIC STATS rx_frames=2 rx_refused=0 rx_missed=0 tx_frames=3 tx_refused=0 tx_errors=0 flags=1\n"
    raw += b"DURABLE WORKLOAD OK\nABSD BOOT OK\n" if success else b"DURABLE WORKLOAD FAILED\n"
    return raw


def artifacts(case="positive"):
    packets = [dad(), conflict()] if case == "preassigned-conflict" else [dad(), *nd(), echo()]
    if case == "positive":
        packets.append(echo(False))
    return packets, m.native_output(serial(case), m.CASES[case]["qemu_exit"], case), peer(case)


def elf(tag, inside=b""):
    body = tag + inside
    header = bytearray(120)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", header, 18, 62)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HH", header, 54, 56, 1)
    struct.pack_into("<IIQQQQQQ", header, 64, 1, 4, 120, 0, 0, len(body), len(body), 1)
    return bytes(header) + body


def build_fixture():
    child = elf(b"unique-child")
    parent = elf(b"unique-parent", child)
    kernel = elf(b"unique-kernel", parent)
    buffers = {"child": child, "parent": parent, "kernel": kernel}
    pointer = lambda path, data: {"path": path, **m.digest(data)}
    external = {"parent": pointer("parent.elf", parent), "input": pointer("empty-input", b""), "expected": pointer("empty-expected", b"")}
    receipt = {"schema": "absd-native-ipv6-echo-build/1",
               "platform": {"revision": m.PRODUCT, "tree": m.PRODUCT_TREE, "clean": True,
                            "archive": {"bytes": m.PRODUCT_BYTES, "sha256": m.PRODUCT_ARCHIVE}},
               "kernel": {"revision": m.KERNEL, "tree": m.KERNEL_TREE, "clean": True,
                          "archive": {"bytes": m.KERNEL_BYTES, "sha256": m.KERNEL_ARCHIVE}},
               "commands": [["sh", "scripts/build-native-ipv6-echo.sh"], ["make", "external-build", "EXTERNAL_USER_ELF=parent.elf", "EXTERNAL_INPUT=empty-input", "EXTERNAL_EXPECTED=empty-expected"]],
               "external": external, "logs": [m.digest(b"build-log")], "toolchain_receipt": m.digest(b"toolchain"),
               "outputs": {k: m.digest(v) for k, v in buffers.items()}}
    return receipt, buffers


def iso(kernel, config):
    # Minimal extent fixture for the same critical ISO9660/Rock Ridge names.
    def record(name, sector, size, directory=False):
        rock_ridge = name == b"absd-kernel"
        if rock_ridge:
            name = b"ABSD_KER.;1"
        n = len(name)
        entry = bytearray(33 + n + (n % 2 == 0))
        struct.pack_into("<I", entry, 2, sector)
        struct.pack_into(">I", entry, 6, sector)
        struct.pack_into("<I", entry, 10, size)
        struct.pack_into(">I", entry, 14, size)
        entry[25], entry[32] = 2 if directory else 0, n
        entry[33:33+n] = name
        if rock_ridge:
            entry.extend(b"NM\x10\x01\0absd-kernel")
        entry[0] = len(entry)
        return entry
    data = bytearray(25 * 2048)
    pvd = memoryview(data)[16 * 2048:17 * 2048]
    pvd[:7] = b"\x01CD001\x01"
    struct.pack_into("<H", pvd, 128, 2048)
    struct.pack_into(">H", pvd, 130, 2048)
    root = record(b"\0", 18, 2048, True)
    pvd[156:156+len(root)] = root
    for sector, entries in [(18, [record(b"boot", 19, 2048, True)]),
                            (19, [record(b"absd-kernel", 21, len(kernel)), record(b"grub", 20, 2048, True)]),
                            (20, [record(b"grub.cfg", 23, len(config))])]:
        at = sector * 2048
        for entry in entries:
            data[at:at+len(entry)] = entry
            at += len(entry)
    data[21*2048:21*2048+len(kernel)] = kernel
    data[23*2048:23*2048+len(config)] = config
    return bytes(data)


class ArtifactControls(unittest.TestCase):
    def inspect(self, case="positive", change=None):
        frames, native, setup = artifacts(case)
        if change:
            change(frames, native, setup)
        return m.inspect(capture(frames), native, setup, case)

    def refuse(self, case, change):
        with self.assertRaises((AssertionError, ValueError, KeyError)):
            self.inspect(case, change)

    def test_fixed_three_case_manifest_and_boolean_types(self):
        raw = Path(__file__).with_name("native-ipv6-echo-cases.json").read_bytes()
        self.assertEqual(set(m.manifest(raw)["cases"]), {"positive", "preassigned-conflict", "no-reply"})
        for key, value in [("runtime", "0"*40), ("kernel", "0"*40)]:
            changed = json.loads(raw);changed[key] = value
            with self.assertRaises(AssertionError):m.manifest(json.dumps(changed).encode())
        changed = json.loads(raw);changed["cases"]["positive"]["preassigned_candidate"] = 0
        with self.assertRaises(AssertionError):m.manifest(json.dumps(changed).encode())
        duplicate = raw.replace(b'"runtime":',b'"runtime":"'+m.PRODUCT.encode()+b'", "runtime":',1)
        with self.assertRaises(AssertionError):m.manifest(duplicate)

    def test_linux_positive_requires_exact_dad_nd_request_reply_and_observation(self):
        result = self.inspect()
        self.assertEqual(result["by_kind"]["echo-request"], [4])
        self.assertEqual(result["by_kind"]["echo-reply"], [5])

    def test_preassigned_conflict_requires_actual_na_and_no_child_or_application(self):
        self.assertEqual(self.inspect("preassigned-conflict")["by_kind"]["linux-conflict-na"], [2])
        self.refuse("preassigned-conflict", lambda f,n,p:f.pop())
        self.refuse("preassigned-conflict", lambda f,n,p:f.append(echo()))

    def test_no_reply_requires_one_request_and_actual_ignore_sysctl(self):
        self.assertEqual(self.inspect("no-reply")["by_kind"]["echo-reply"], [])
        self.refuse("no-reply", lambda f,n,p:p["sysctls"].update({"net.ipv6.icmp.echo_ignore_all":"0"}))
        self.refuse("no-reply", lambda f,n,p:f.append(echo(False)))
        self.refuse("no-reply", lambda f,n,p:f.pop())

    def test_ordinary_candidate_traffic_before_tentative_probe_refuses(self):
        self.refuse("positive", lambda f,n,p:f.__setitem__(slice(0,2), [f[1],f[0]]))
        self.refuse("preassigned-conflict", lambda f,n,p:f.insert(0, nd()[0]))

    def test_missing_nd_or_reply_before_request_refuses(self):
        self.refuse("positive", lambda f,n,p:f.pop(1))
        self.refuse("positive", lambda f,n,p:f.__setitem__(slice(3,5), [f[4],f[3]]))

    def test_duplicate_request_reply_and_extra_frame_never_pass(self):
        for packet in (echo(), echo(False), bytes(60)):
            self.refuse("positive", lambda f,n,p:f.append(packet))

    def test_all_original_checksums_are_checked_before_correlation(self):
        for index in range(5):
            def change(f,n,p):
                data = bytearray(f[index]);data[56] ^= 1;f[index] = bytes(data)
            self.refuse("positive", change)

    def test_valid_checksum_wrong_peer_reply_never_becomes_explained(self):
        wrong = bytearray(m.HOST);wrong[-1] = 3
        packet = frame(bytes(wrong), m.GUEST, echo(False)[54:], False, hop=64)
        self.refuse("positive", lambda f,n,p:f.__setitem__(-1, packet))

    def test_valid_checksum_identifier_sequence_body_and_generation_substitution_refuse(self):
        for keyword, value in [("identifier",1),("sequence",1),("instance",2),("epoch",2),("nonce",2)]:
            self.refuse("positive", lambda f,n,p:f.__setitem__(-1, echo(False, **{keyword:value})))

    def test_native_observation_must_match_actual_wire_fields(self):
        self.refuse("positive", lambda f,n,p:n["observation"].update(nonce=1))
        self.refuse("positive", lambda f,n,p:n.update(observation=None))

    def test_zero_correlation_fragment_extension_padding_and_truncation_refuse(self):
        for packet in (echo(False, nonce=0), echo(False)[:-1], echo(False)+bytes(1)):
            self.refuse("positive", lambda f,n,p:f.__setitem__(-1, packet))
        for nh in (0,44):
            changed = bytearray(echo(False));changed[20] = nh
            self.refuse("positive", lambda f,n,p:f.__setitem__(-1, bytes(changed)))

    def test_preassigned_address_must_be_exact_usable_and_only_in_conflict_case(self):
        self.refuse("preassigned-conflict", lambda f,n,p:p["addresses"][0]["addr_info"][-1].update(tentative=True))
        self.refuse("positive", lambda f,n,p:p["addresses"][0]["addr_info"].append({"family":"inet6","local":m.GUEST_IP,"prefixlen":64}))

    def test_peer_mtu_mac_routes_socket_and_configuration_substitutions_refuse(self):
        changes = [lambda p:p["links"][0].update(mtu=1280), lambda p:p["links"][0].update(address="00:00:00:00:00:00"),
                   lambda p:p["routes"].append({"dst":"default","dev":p["tap"],"gateway":m.HOST_IP}),
                   lambda p:p.update(sockets="udp socket"),lambda p:p["sysctls"].update({"net.ipv6.conf.echo6-tap0.accept_ra":"1"})]
        for change in changes:self.refuse("positive",lambda f,n,p:change(p))

    def test_complete_capture_and_monotone_order_are_required(self):
        frames,native,setup = artifacts()
        with self.assertRaises(AssertionError):m.inspect(capture(frames)[:-1],native,setup,"positive")
        raw = bytearray(capture(frames));struct.pack_into("<I",raw,24,2)
        with self.assertRaises(AssertionError):m.inspect(bytes(raw),native,setup,"positive")

    def test_literal_linux_mld_retains_whole_census_and_bad_checksum_refuses(self):
        self.assertEqual(self.inspect(change=lambda f,n,p:f.insert(0,mld()))["census"][0]["kind"],"linux-mldv2")
        bad = bytearray(mld());bad[-1] ^= 1
        self.refuse("positive",lambda f,n,p:f.insert(0,bytes(bad)))

    def test_serial_exact_output_checksum_offsets_resources_and_exit_are_required(self):
        baseline = serial()
        for old,new in [(b"offset=0000000000000000",b"offset=0000000000000001"),
                        (b"frames=0",b"frames=1"),(b"USER EXIT pid=3 status=0",b"USER EXIT pid=3 status=1")]:
            with self.assertRaises(AssertionError):m.native_output(baseline.replace(old,new),3,"positive")
        with self.assertRaises(AssertionError):m.native_output(baseline,7,"positive")
        broken = baseline.replace(b"EXTERNAL OUTPUT END bytes=",b"EXTERNAL OUTPUT END bytes=9")
        with self.assertRaises(AssertionError):m.native_output(broken,3,"positive")

    def test_serial_authority_time_and_socket_labels_are_code_bound(self):
        text = m.native_output(serial(),3,"positive")["output"]
        for old,new in [("denied=1","denied=0"),("nic=0","nic=1"),("auth=none requests=1","auth=verified requests=1"),
                        ("sockets=0","sockets=1"),("boot_elapsed_ms=9","boot_elapsed_ms=8000")]:
            with self.assertRaises(AssertionError):m.native_output(serial(text=text.replace(old,new)),3,"positive")

    def test_negative_cases_require_exact_refusal_and_child_construction_scope(self):
        raw = serial("preassigned-conflict")
        with self.assertRaises(AssertionError):m.native_output(raw.replace(b"USER EXIT pid=2",b"SPAWN OK pid=3 parent=2 program=image\nUSER EXIT pid=2"),7,"preassigned-conflict")
        with self.assertRaises(AssertionError):m.native_output(serial("no-reply").replace(b"USER KILLED pid=3 by=2",b"USER EXIT pid=3 status=0"),7,"no-reply")
        wrong = "PING6 SERVICE ERROR DAD acquisition refused Dad(Link)\n"
        with self.assertRaises(AssertionError):m.native_output(serial("preassigned-conflict",wrong),7,"preassigned-conflict")

    def test_build_receipt_pins_source_archives_compiler_outputs_and_empty_input(self):
        receipt,buffers = build_fixture();m.build_binding(receipt,buffers)
        for key in ("platform","kernel"):
            changed = copy.deepcopy(receipt);changed[key]["revision"] = "0"*40
            with self.assertRaises(AssertionError):m.build_binding(changed,buffers)
        changed = copy.deepcopy(receipt);changed["external"]["input"].update(m.digest(b"not empty"))
        with self.assertRaises(AssertionError):m.build_binding(changed,buffers)
        changed = dict(buffers);changed["child"] += b"different"
        with self.assertRaises(AssertionError):m.build_binding(receipt,changed)

    def test_iso_requires_critical_file_extents_not_substring_presence(self):
        _,buffers = build_fixture();kernel = buffers["kernel"];boot = b"exact grub configuration\n"
        image = iso(kernel,boot);m.iso_binding(image,kernel,boot)
        changed = bytearray(image);changed[23*2048] ^= 1
        with self.assertRaises(AssertionError):m.iso_binding(bytes(changed),kernel,boot)
        changed = bytearray(image);changed[21*2048] ^= 1;changed.extend(kernel)
        with self.assertRaises(AssertionError):m.iso_binding(bytes(changed),kernel,boot)

    def test_evaluated_peer_cleanup_and_raw_content_mutation_refuse_final_seal(self):
        for name in ("LINUX-PEER-BEFORE.json","LINUX-PEER-AFTER.json","LOCAL-CLEANUP.json","native-ipv6-echo.pcap"):
            with tempfile.TemporaryDirectory(prefix="absd-echo6-artifact-") as directory:
                work = Path(directory);path = work/name;path.write_bytes(b"evaluated bytes")
                result = {"evaluated_artifacts":{name:m.identity(path,b"evaluated bytes")},"evaluated_build_inputs":{},"proof_inputs":{}}
                path.write_bytes(b"changed content")
                with self.assertRaises(AssertionError):m.seal_artifacts(work,result)

    def test_terminal_cleanup_fact_is_shared_with_returned_evaluated_mapping(self):
        with tempfile.TemporaryDirectory(prefix="absd-echo6-artifact-") as directory:
            work = Path(directory);evaluated = {};result = {"evaluated_artifacts":evaluated,"evaluated_build_inputs":{},"proof_inputs":{}}
            path = work/"LOCAL-CLEANUP.json";data = m.write(path,{"disposition":"PASS"});evaluated[path.name] = m.identity(path,data)
            self.assertIn(path.name,m.seal_artifacts(work,result))
            path.write_text('{"disposition":"FAIL"}\n')
            with self.assertRaises(AssertionError):m.seal_artifacts(work,result)

    def reasons(self, count=2, logs=2, mutate=None):
        frames,native,setup = artifacts()
        raw = capture([mld()]*count+frames)
        census = m.inspect(raw,native,setup,"positive")["census"]
        serial_bytes = serial().replace(b"rx_refused=0",b"rx_refused="+str(count).encode())
        serial_bytes = (b"NIC RX FILTERED dst=33:33:00:00:00:16\n"*logs)+serial_bytes
        annotation = {"schema":"absd-ipv6-ready-capture-sidecar/1","policy":m.original.POLICY,
                      "capture":m.digest(raw),"serial":m.digest(serial_bytes),"previous_absent":None,
                      "observation":{"serial_bytes":len(serial_bytes),"serial_sha256":m.digest(serial_bytes)["sha256"],
                                     "capture_before_serial_read":{"bytes":len(raw),"sha256":m.digest(raw)["sha256"]},
                                     "capture_after_serial_read":{"bytes":len(raw),"sha256":m.digest(raw)["sha256"]}}}
        fields = dict(native["NIC_counters"]);fields["rx_refused"] = str(count)
        if mutate:mutate(annotation,fields,census)
        return m.reason_accounting(raw,serial_bytes,json.dumps(annotation).encode(),annotation,fields,census)

    def test_first_four_reason_profile_preserves_mld_and_compatible_destinations(self):
        result = self.reasons()
        self.assertEqual(result["disposition"],"PASS")
        self.assertEqual(result["driver_reasons"][0]["compatible_capture_indices"],[1,2])

    def test_reason_budget_cardinality_and_missed_tx_errors_fail(self):
        self.assertEqual(self.reasons(5,5)["disposition"],"FAIL")
        self.assertEqual(self.reasons(2,1)["disposition"],"FAIL")
        for key in ("rx_missed","tx_refused","tx_errors"):
            self.assertEqual(self.reasons(mutate=lambda a,f,c:f.update({key:"1"}))["disposition"],"FAIL")

    def test_sidecar_prefix_and_policy_content_substitutions_refuse(self):
        self.assertEqual(self.reasons(mutate=lambda a,f,c:a["observation"].update(serial_sha256="0"*64))["disposition"],"FAIL")
        self.assertEqual(self.reasons(mutate=lambda a,f,c:a["observation"]["capture_after_serial_read"].update(bytes=10**9))["disposition"],"FAIL")
        with self.assertRaises(AssertionError):self.reasons(mutate=lambda a,f,c:a.update(policy={}))

    def test_exited_leader_does_not_skip_owned_group_termination(self):
        process = Mock(pid=12345);process.poll.return_value = 0
        with patch.object(m,"group_live",side_effect=[True,False,False,False]),patch.object(m.os,"killpg") as kill:
            result = m.stop_owned(process)
        kill.assert_called_once_with(12345,m.signal.SIGTERM)
        self.assertTrue(result["group_absent"])


    def test_no_reply_refuses_every_generic_early_channel_death(self):
        text = m.native_output(serial("no-reply"), 7, "no-reply")["output"]
        for cause in ("child status 1", "channel retired before child exit", "original invocation budget", "DAD wait Link"):
            with self.assertRaises(AssertionError):
                m.native_output(serial("no-reply", text.replace("DAD after result read Expired", cause)), 7, "no-reply")

    def test_no_reply_accepts_only_the_four_expiry_causes_after_owner_stop(self):
        self.assertEqual(m.NO_REPLY_ERRORS, {"DAD wait Expired", "DAD after result read Expired", "DAD after wait Expired", "DAD during terminal drain Expired"})
        text = m.native_output(serial("no-reply"), 7, "no-reply")["output"]
        for cause in m.NO_REPLY_ERRORS:
            result = m.native_output(serial("no-reply", text.replace("DAD after result read Expired", cause)), 7, "no-reply")
            self.assertEqual(result["guest_clock_trace"]["terminal_boot_ms"], 9000)
        with self.assertRaises(AssertionError):
            m.native_output(serial("no-reply", text + "PING6 SERVICE ERROR DAD wait Expired\n"), 7, "no-reply")

    def test_no_reply_refuses_early_terminal_and_converted_tick_boundary(self):
        baseline = serial("no-reply")
        # Raw ticks already reach 9000, but the pinned floored boot clock is 8998.
        self.assertEqual(9000 * 1193 * 3000 // 3579545, 8998)
        with self.assertRaises(AssertionError):
            m.native_output(baseline.replace(b"ticks=10000", b"ticks=9000"), 7, "no-reply")
        text = m.native_output(baseline, 7, "no-reply")["output"]
        for old, new in (("boot_ms=9000", "boot_ms=8999"), ("before_ms=1010", "before_ms=1012"),
                         ("boot_ms=9000", "boot_ms=12100")):
            with self.assertRaises(AssertionError):
                m.native_output(serial("no-reply", text.replace(old, new)), 7, "no-reply")

    def test_no_reply_submission_must_precede_expiry_by_more_than_frame_ms(self):
        text = m.native_output(serial("no-reply"), 7, "no-reply")["output"]
        changed = text.replace("before_ms=1010 after_ms=1011", "before_ms=8748 after_ms=8749")
        m.native_output(serial("no-reply", changed), 7, "no-reply")
        for after in (8750, 8999, 9000):
            changed = text.replace("before_ms=1010 after_ms=1011", f"before_ms=8748 after_ms={after}")
            with self.assertRaises(AssertionError):m.native_output(serial("no-reply", changed), 7, "no-reply")

    def test_owner_trace_bounds_and_untruncated_active_window_are_required(self):
        text = m.native_output(serial("no-reply"), 7, "no-reply")["output"]
        for old, new in (("invocation_until_ms=12100", "invocation_until_ms=12101"),
                         ("stop_ms=9000", "stop_ms=12100"), ("stop_ms=9000", "stop_ms=8000"),
                         ("current_ms=1002", "current_ms=999"), ("after_ms=1011", "after_ms=9223372036854775808")):
            with self.assertRaises(AssertionError):m.native_output(serial("no-reply", text.replace(old, new)), 7, "no-reply")
        with self.assertRaises(AssertionError):
            m.native_output(serial("no-reply").replace(b"ticks=10000", b"ticks=18446744073709551616"), 7, "no-reply")

    def test_submission_success_count_and_complete_captured_frame_are_bound(self):
        text = m.native_output(serial("no-reply"), 7, "no-reply")["output"]
        for old, new in (("result=0", "result=-5"), ("attempts=1", "attempts=0"), ("attempts=1", "attempts=2"),
                         ("frame=" + echo().hex(), "frame=" + echo()[:-1].hex())):
            with self.assertRaises(AssertionError):m.native_output(serial("no-reply", text.replace(old, new)), 7, "no-reply")
        self.refuse("no-reply", lambda f,n,p:f.__setitem__(-1, echo(nonce=2)))
        self.refuse("positive", lambda f,n,p:n["guest_clock_trace"]["submission"].update(frame=echo(nonce=2).hex()))

    def test_missing_or_duplicate_probe_clock_records_never_pass(self):
        text = m.native_output(serial("no-reply"), 7, "no-reply")["output"]
        for prefix in ("PING6 OWNER ", "PING6 SUBMISSION ", "PING6 TERMINAL "):
            lines = text.splitlines(keepends=True)
            line = next(line for line in lines if line.startswith(prefix))
            for changed in (text.replace(line, ""), text + line):
                with self.assertRaises(AssertionError):m.native_output(serial("no-reply", changed), 7, "no-reply")


if __name__ == "__main__":
    unittest.main()
