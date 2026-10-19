#!/usr/bin/env python3
"""Artifact controls for a single positive native responder case, not guest tests."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch
spec=importlib.util.spec_from_file_location("responder",Path(__file__).with_name("native-ipv6-echo-responder.py"))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)



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


def elf(tag, inside=b""):
    body = tag + inside
    header = bytearray(120)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", header, 18, 62)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HH", header, 54, 56, 1)
    struct.pack_into("<IIQQQQQQ", header, 64, 1, 4, 120, 0, 0, len(body), len(body), 1)
    return bytes(header) + body


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


def nd():
    ns=frame(m.HOST,m.original.solicited(m.GUEST),b"\x87\0"+bytes(6)+m.GUEST+b"\x01\x01"+m.HOST_MAC,False,bytes.fromhex("3333ff000015"))
    na=frame(m.GUEST,m.HOST,b"\x88\0"+bytes(2)+bytes.fromhex("60000000")+m.GUEST+b"\x02\x01"+m.GUEST_MAC)
    return [ns,na]


def echo(outgoing=False, identifier=0x1234, sequence=1, data=bytes(range(56))):
    body=struct.pack("!BBHHH",129 if outgoing else 128,0,0,identifier,sequence)+data
    return frame(m.GUEST if outgoing else m.HOST,m.HOST if outgoing else m.GUEST,body,outgoing,hop=64)


def peer():
    tap="resp6-tap0"
    return {"case":"positive","transport":"Linux kernel IPv6 with installed ping; no synthetic packet injection","namespace_inode":7,"tap":tap,
            "sysctls":m.peer_settings(tap,"positive"),"links":[{"ifname":tap,"mtu":1500,"address":m.HOST_MAC.hex(":"),"flags":["UP"]}],
            "addresses":[{"ifname":tap,"addr_info":[{"family":"inet6","local":m.HOST_IP,"prefixlen":64}]}],
            "routes":[{"dst":"fd00:ab5d::/64","dev":tap}],"sockets":""}


READY="PING6 RESPONDER READY local=fd00:ab5d::15 peer=fd00:ab5d::2 scope=1 replies=1 max_icmp_bytes=1240 stop_ms=9100\n"
PASS="PING6 RESPONDER PASS peer=fd00:ab5d::2 scope=1 identifier=4660 sequence=1 icmp_bytes=64 submitted_at_ms=1200 possible_effects=1 sockets=0 auth=none\n"
PING=b"PING fd00:ab5d::15(fd00:ab5d::15) from fd00:ab5d::2 : 56 data bytes\n64 bytes from fd00:ab5d::15: icmp_seq=1 ttl=64 time=2.10 ms\n\n--- fd00:ab5d::15 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\nrtt min/avg/max/mdev = 2.100/2.100/2.100/0.000 ms\n"


def chunk(text, offset=0):
    return b"EXTERNAL OUTPUT CHUNK offset="+f"{offset:016x}".encode()+b" data="+text.encode().hex().encode()+b"\n"


def serial(text=READY+PASS):
    data=text.encode();value=0x811c9dc5
    for b in data:value=((value^b)*0x01000193)&0xffffffff
    first, rest = text.split("\n", 1)
    first += "\n"
    return (b"NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n"+chunk(first)+chunk(rest,len(first.encode()))
            +b"USER EXIT pid=2 status=0\nDURABLE WORKER OUTCOME generation=1 pid=2 status=0\n"
            +b"EXTERNAL OUTPUT END bytes="+str(len(data)).encode()+b" digest="+f"{value:08x}".encode()+b"\n"
            +b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 block_reads=0 block_writes=0 block_flushes=0 block_errors=0 block_waits=0 block_irqs=0 ticks=1400\n"
            +b"NIC STATS rx_frames=2 rx_refused=0 rx_missed=0 tx_frames=3 tx_refused=0 tx_errors=0 flags=1\nDURABLE WORKLOAD OK\nABSD BOOT OK\n")


def inputs():
    return [dad(),*nd(),echo(),echo(True)],m.native_output(serial(),3),peer()


def build_fixture():
    parent=elf(b"unique-parent");kernel=elf(b"unique-kernel",parent);buffers={"parent":parent,"kernel":kernel}
    pointer=lambda p,b:{"path":p,**m.digest(b)}
    external={"parent":pointer("parent.elf",parent),"input":pointer("empty-input",b""),"expected":pointer("empty-expected",b"")}
    receipt={"schema":"absd-native-ipv6-echo-responder-build/1",
             "platform":{"revision":m.PRODUCT,"tree":m.PRODUCT_TREE,"clean":True,"archive":{"bytes":m.PRODUCT_BYTES,"sha256":m.PRODUCT_ARCHIVE}},
             "kernel":{"revision":m.KERNEL,"tree":m.KERNEL_TREE,"clean":True,"archive":{"bytes":m.KERNEL_BYTES,"sha256":m.KERNEL_ARCHIVE}},
             "commands":[["sh","scripts/build-native-ipv6-echo-responder.sh"],["make","external-build","EXTERNAL_USER_ELF=parent.elf","EXTERNAL_INPUT=empty-input","EXTERNAL_EXPECTED=empty-expected"]],
             "external":external,"logs":[m.digest(b"build-log")],"toolchain_receipt":m.digest(b"toolchain"),"outputs":{k:m.digest(v) for k,v in buffers.items()}}
    return receipt,buffers


class Controls(unittest.TestCase):
    def inspect(self,change=None):
        frames,native,p=inputs()
        if change:change(frames,native,p)
        return m.inspect(capture(frames),native,p)
    def refuse(self,change):
        with self.assertRaises((AssertionError,ValueError,KeyError)):self.inspect(change)

    def test_positive_full_census_linux_direction_and_native_correlation(self):
        self.assertEqual(self.inspect()["by_kind"],{"guest-dad-ns":[1],"echo-request":[4],"echo-reply":[5]})
        self.assertEqual(m.ping_output(PING,0)["status"],0)

    def test_missing_dad_nd_request_or_reply_refuses(self):
        for index in range(5):self.refuse(lambda f,n,p:f.pop(index))

    def test_dad_before_candidate_traffic_and_nd_before_request(self):
        self.refuse(lambda f,n,p:f.__setitem__(slice(0,2),[f[1],f[0]]))
        self.refuse(lambda f,n,p:f.__setitem__(slice(2,4),[f[3],f[2]]))

    def test_request_before_reply_and_duplicate_or_unexplained_frames_refuse(self):
        self.refuse(lambda f,n,p:f.__setitem__(slice(3,5),[f[4],f[3]]))
        for extra in (echo(),echo(True),bytes(60)):self.refuse(lambda f,n,p:f.append(extra))

    def test_all_packet_checksums_and_exact_lengths_are_required(self):
        for index in range(5):
            def bad(f,n,p):
                b=bytearray(f[index]);b[56]^=1;f[index]=bytes(b)
            self.refuse(bad)
        for packet in (echo(True)[:-1],echo(True)+b"x",echo(True,data=bytes(55))):self.refuse(lambda f,n,p:f.__setitem__(-1,packet))

    def test_reply_must_mirror_all_id_sequence_and_data_bytes(self):
        for packet in (echo(True,identifier=1),echo(True,sequence=2),echo(True,data=bytes([1])*56)):
            self.refuse(lambda f,n,p:f.__setitem__(-1,packet))
        self.refuse(lambda f,n,p:n.update(identifier=1))

    def test_valid_checksum_wrong_peer_and_extension_are_not_explained(self):
        bad=bytearray(m.HOST);bad[-1]=3
        packet=frame(m.GUEST,bytes(bad),echo(True)[54:],True,hop=64)
        self.refuse(lambda f,n,p:f.__setitem__(-1,packet))
        for nh in (0,44):
            b=bytearray(echo(True));b[20]=nh
            self.refuse(lambda f,n,p:f.__setitem__(-1,bytes(b)))

    def test_usable_peer_mac_mtu_routes_and_sysctls_are_fixed(self):
        changes=[lambda p:p["links"][0].update(mtu=1280),lambda p:p["links"][0].update(address="00:00:00:00:00:00"),
                 lambda p:p["routes"].append({"dst":"default","dev":p["tap"]}),lambda p:p["sysctls"].update({"net.ipv6.icmp.echo_ignore_all":"1"}),
                 lambda p:p["addresses"][0]["addr_info"][0].update(tentative=True)]
        for c in changes:self.refuse(lambda f,n,p:c(p))

    def test_original_mld_is_retained_and_wrong_checksum_refuses(self):
        result=self.inspect(lambda f,n,p:f.insert(0,mld()));self.assertEqual(result["census"][0]["kind"],"linux-mldv2")
        b=bytearray(mld());b[-1]^=1;self.refuse(lambda f,n,p:f.insert(0,bytes(b)))

    def test_truncated_capture_and_nonmonotone_order_refuse(self):
        f,n,p=inputs()
        with self.assertRaises(AssertionError):m.inspect(capture(f)[:-1],n,p)
        b=bytearray(capture(f));struct.pack_into("<I",b,24,2)
        with self.assertRaises(AssertionError):m.inspect(bytes(b),n,p)

    def test_ready_is_actual_complete_prefix_before_ping(self):
        raw=b"NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n"+chunk(READY);ready=m.readiness(raw);self.assertIsNotNone(ready)
        self.assertIsNone(m.readiness(raw[:-1]))
        native=m.native_output(serial(),3)
        m.ready_correspondence(serial(),ready,native)
        with self.assertRaises(AssertionError):m.ready_correspondence(b"x"+raw,ready,native)
        with self.assertRaises(AssertionError):m.readiness(chunk(READY+PASS))

    def test_ready_budget_and_terminal_observation_must_agree(self):
        raw=chunk(READY);ready=m.readiness(raw)
        with self.assertRaises(AssertionError):m.ready_correspondence(raw,ready,{"stop_ms":9101})
        with self.assertRaises(AssertionError):m.native_output(serial((READY+PASS).replace("submitted_at_ms=1200","submitted_at_ms=9100")),3)

    def test_native_status_socket_possible_effect_and_durable_zeros_are_required(self):
        for a,b in (("sockets=0","sockets=1"),("possible_effects=1","possible_effects=0"),("auth=none","auth=verified"),("icmp_bytes=64","icmp_bytes=65")):
            with self.assertRaises(AssertionError):m.native_output(serial((READY+PASS).replace(a,b)),3)
        for raw,status in ((serial(),7),(serial().replace(b"frames=0",b"frames=1"),3),(serial()+b"SPAWN OK pid=3 parent=2 program=image\n",3)):
            with self.assertRaises(AssertionError):m.native_output(raw,status)

    def test_serial_output_chunks_and_digest_must_be_exact(self):
        for raw in (serial().replace(b"offset=0000000000000000",b"offset=0000000000000001"),serial().replace(b"END bytes=",b"END bytes=9")):
            with self.assertRaises(AssertionError):m.native_output(raw,3)

    def test_ping_requires_real_positive_exit_one_received_and_one_sequence(self):
        for raw,status in ((PING,1),(PING.replace(b"1 received",b"0 received"),0),(PING.replace(b"icmp_seq=1",b"icmp_seq=2"),0),(PING+PING,0)):
            with self.assertRaises(AssertionError):m.ping_output(raw,status)

    def test_source_build_outputs_empty_input_and_unique_kernel_embedding(self):
        receipt,buffers=build_fixture();m.build_binding(receipt,buffers)
        for key in ("platform","kernel"):
            changed=copy.deepcopy(receipt);changed[key]["revision"]="0"*40
            with self.assertRaises(AssertionError):m.build_binding(changed,buffers)
        changed=copy.deepcopy(receipt);changed["external"]["input"].update(m.digest(b"not empty"))
        with self.assertRaises(AssertionError):m.build_binding(changed,buffers)
        altered=dict(buffers);altered["parent"]+=b"changed"
        with self.assertRaises(AssertionError):m.build_binding(receipt,altered)

    def test_iso_critical_file_extents_are_required(self):
        _,b=build_fixture();boot=b"exact grub bytes\n";image=iso(b["kernel"],boot);m.iso_binding(image,b["kernel"],boot)
        bad=bytearray(image);bad[21*2048]^=1;bad.extend(b["kernel"])
        with self.assertRaises(AssertionError):m.iso_binding(bytes(bad),b["kernel"],boot)

    def test_evaluated_semantic_facts_and_raw_buffers_refuse_mutation(self):
        for name in ("PING-TOOL.json","READY-OBSERVATION.json","PING-LAUNCH.json","PING-RESULT.json","LINUX-PEER-BEFORE.json","LINUX-PEER-AFTER.json","LOCAL-CLEANUP.json","native-ipv6-echo-responder.pcap"):
            with tempfile.TemporaryDirectory() as d:
                work=Path(d);p=work/name;p.write_bytes(b"observed");result={"evaluated_artifacts":{name:m.identity(p,b"observed")},"evaluated_build_inputs":{},"proof_inputs":{}}
                p.write_bytes(b"different")
                with self.assertRaises(AssertionError):m.seal_artifacts(work,result)

    def test_cleanup_mapping_is_shared_and_exited_leader_still_retires_group(self):
        with tempfile.TemporaryDirectory() as d:
            work=Path(d);evaluated={};result={"evaluated_artifacts":evaluated,"evaluated_build_inputs":{},"proof_inputs":{}}
            raw=m.write(work/"LOCAL-CLEANUP.json",{"disposition":"PASS"});evaluated["LOCAL-CLEANUP.json"]=m.identity(work/"LOCAL-CLEANUP.json",raw)
            m.seal_artifacts(work,result);(work/"LOCAL-CLEANUP.json").write_text('{"disposition":"FAIL"}')
            with self.assertRaises(AssertionError):m.seal_artifacts(work,result)
        process=Mock(pid=12345);process.poll.return_value=0
        with patch.object(m,"group_live",side_effect=[True,False,False,False]),patch.object(m.os,"killpg") as signal:
            result=m.stop_owned(process)
        signal.assert_called_once_with(12345,m.signal.SIGTERM);self.assertTrue(result["group_absent"]);self.assertTrue(result["forced"])

    def reasons(self, count=2, logs=2, change=None):
        frames,native,p=inputs();raw=capture([mld()]*count+frames)
        census=m.inspect(raw,native,p)["census"]
        serial_raw=(b"NIC RX FILTERED dst=33:33:00:00:00:16\n"*logs)+serial()
        fields=dict(native["NIC_counters"]);fields["rx_refused"]=str(count)
        annotation={"schema":"absd-ipv6-ready-capture-sidecar/1","policy":m.original.POLICY,
                    "capture":m.digest(raw),"serial":m.digest(serial_raw),"previous_absent":None,
                    "observation":{"serial_bytes":len(serial_raw),"serial_sha256":m.digest(serial_raw)["sha256"],
                    "capture_before_serial_read":m.digest(raw),"capture_after_serial_read":m.digest(raw)}}
        if change:change(annotation,fields,census)
        return m.reason_accounting(raw,serial_raw,json.dumps(annotation).encode(),annotation,fields,census)

    def test_unchanged_first_four_reason_profile_requires_compatible_full_capture(self):
        result=self.reasons();self.assertEqual(result["disposition"],"PASS")
        self.assertEqual(result["driver_reasons"][0]["compatible_capture_indices"],[1,2])
        self.assertEqual(self.reasons(5,5)["disposition"],"FAIL")
        self.assertEqual(self.reasons(2,1)["disposition"],"FAIL")

    def test_sidecar_content_prefix_policy_and_error_substitutions_refuse(self):
        self.assertEqual(self.reasons(change=lambda a,f,c:a["observation"].update(serial_sha256="0"*64))["disposition"],"FAIL")
        for key in ("rx_missed","tx_errors","tx_refused"):
            self.assertEqual(self.reasons(change=lambda a,f,c:f.update({key:"1"}))["disposition"],"FAIL")
        with self.assertRaises(AssertionError):self.reasons(change=lambda a,f,c:a.update(policy={}))

    def warm_entries(self):
        return [{"dst":m.GUEST_IP,"dev":"resp6-tap0","lladdr":m.GUEST_MAC.hex(":"),"state":["REACHABLE"]}]

    def test_explicit_nd_warm_requires_reachable_state_and_complete_prior_nd(self):
        frames,_,_=inputs();prefix=capture(frames[:3]);entries=self.warm_entries()
        snapshot=m.neighbor_warm_snapshot(prefix,entries,"resp6-tap0")
        self.assertEqual(snapshot["compatible_NS_NA_pairs"],[[2,3]])
        record={"snapshot":snapshot,"neighbor_json":json.dumps(entries)}
        m.warm_correspondence(capture(frames),record)
        self.assertEqual(json.loads(json.dumps(snapshot)),snapshot)

    def test_configured_mac_without_fresh_neighbor_state_cannot_prove_warming(self):
        frames,_,_=inputs();raw=capture(frames[:3])
        self.assertIsNone(m.neighbor_warm_snapshot(raw,[],"resp6-tap0"))
        pending=self.warm_entries();pending[0].pop("lladdr");pending[0]["state"]=["INCOMPLETE"]
        self.assertIsNone(m.neighbor_warm_snapshot(raw,pending,"resp6-tap0"))
        for field,value in (("dst",m.HOST_IP),("dev","other0"),("lladdr",m.HOST_MAC.hex(":")),("state",["PERMANENT"]),("state",["FAILED"])):
            rows=self.warm_entries();rows[0][field]=value
            with self.assertRaises(AssertionError):m.neighbor_warm_snapshot(raw,rows,"resp6-tap0")

    def test_neighbor_warm_missing_partial_reversed_or_early_application_refuses(self):
        frames,_,_=inputs();entries=self.warm_entries()
        for wire in (capture(frames[:2]),capture(frames[:3])[:-4],capture([frames[0],frames[2],frames[1]])):
            self.assertIsNone(m.neighbor_warm_snapshot(wire,entries,"resp6-tap0"))
        with self.assertRaises(AssertionError):m.neighbor_warm_snapshot(capture(frames[:4]),entries,"resp6-tap0")

    def test_warm_observation_prefix_raw_json_and_pending_fact_are_bound(self):
        frames,_,_=inputs();prefix=capture(frames[:3]);entries=self.warm_entries()
        record={"snapshot":m.neighbor_warm_snapshot(prefix,entries,"resp6-tap0"),"neighbor_json":json.dumps(entries)}
        changed=bytearray(capture(frames));changed[60]^=1
        with self.assertRaises(AssertionError):m.warm_correspondence(bytes(changed),record)
        changed=copy.deepcopy(record);changed["neighbor_json"]="[]"
        with self.assertRaises(AssertionError):m.warm_correspondence(capture(frames),changed)
        with tempfile.TemporaryDirectory() as d:
            work=Path(d);path=work/"LINUX-NEIGHBOR-WARM.json";raw=m.write(path,record)
            result={"evaluated_artifacts":{path.name:m.identity(path,raw)},"evaluated_build_inputs":{},"proof_inputs":{}}
            path.write_text("{}")
            with self.assertRaises(AssertionError):m.seal_artifacts(work,result)


if __name__=="__main__":unittest.main()
