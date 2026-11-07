#!/usr/bin/env python3
"""Bounded actual-record/capture controls; no guest execution by this file."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location("responder",Path(__file__).with_name("native-ipv6-echo-boundary.py"))
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
    na=frame(m.GUEST,m.HOST,b"\x88\0"+bytes(2)+bytes.fromhex("40000000")+m.GUEST+b"\x02\x01"+m.GUEST_MAC)
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


def base_serial(text=READY+PASS):
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


def boundary_output():
    frames=m.boundary_frames()
    text=READY+f"PING6 RESPONDER WARM v=1 ns_rx=2 na_tx=3 na_after_rx=2 ns={frames['warm-ns'].hex()} na={frames['warm-na'].hex()}\n"
    for ordinal,name in enumerate(m.BOUNDARY_NAMES,3):
        text+=f"PING6 RESPONDER NEG v=1 case={name} rx={ordinal} frame={frames[name].hex()} effects=0 observation=Again\n"
    return text+"PING6 RESPONDER NEG COMPLETE v=1 cases=4 effects=0 observation=Again sockets=0\n"+"PING6 RESPONDER STATE v=1 observe=Spent activate=Exhausted retired=Stale sockets=0\n"+PASS


def serial(text=None):return base_serial(boundary_output() if text is None else text)


def inputs():
    frames=m.boundary_frames()
    rows=[dad(),*nd(),frames['warm-ns'],frames['warm-na'],*[frames[n] for n in m.BOUNDARY_NAMES],echo(),echo(True)]
    p=peer();p['transport']="Linux kernel positive ping plus disclosed bounded raw negative-input fixture"
    return rows,m.native_output(serial(),3),p


def build_fixture():
    parent=elf(b"unique-parent");kernel=elf(b"unique-kernel",parent);buffers={"parent":parent,"kernel":kernel}
    pointer=lambda p,b:{"path":p,**m.digest(b)}
    external={"parent":pointer("parent.elf",parent),"input":pointer("empty-input",b""),"expected":pointer("empty-expected",b"")}
    metadata=json.dumps({"version":1,"packages":[{"name":"absd-std-probe","targets":[{"name":"ipv6_echo_responder_probe","kind":["bin"],"required-features":["native-ipv6-echo-responder-probe"],"src_path":"/received/src/bin/ipv6_echo_responder_probe.rs"}]}]}).encode()
    receipt={"schema":"absd-native-ipv6-echo-responder-build/2","profile":m.PROFILE_NAME,
             "platform":{"revision":m.PRODUCT,"tree":m.PRODUCT_TREE,"clean":True,"archive":{"bytes":m.PRODUCT_BYTES,"sha256":m.PRODUCT_ARCHIVE}},
             "kernel":{"revision":m.KERNEL,"tree":m.KERNEL_TREE,"clean":True,"archive":{"bytes":m.KERNEL_BYTES,"sha256":m.KERNEL_ARCHIVE}},
             "commands":[["sh","scripts/build-native-ipv6-echo-responder.sh"],["python3","scripts/served_kernel.py","-C","kernel","external-build","EXTERNAL_USER_ELF=parent.elf","EXTERNAL_INPUT=empty-input","EXTERNAL_EXPECTED=empty-expected"]],
             "served_kernel_policy":"frame-admission-v0","served_wrapper_sha256":m.SERVED_WRAPPER,"target":"x86_64-unknown-absd",
             "staged_std":{"sha256":"c35493ccdf6cb87a81767902413ad4487caa1bff401d5ccecb1cce9e7a18760c","files":2251,"bytes":45920288},"cargo_metadata":pointer("metadata.json",metadata),
             "external":external,"logs":[m.digest(b"build-log")],"toolchain_receipt":m.digest(b"toolchain"),"outputs":{k:m.digest(v) for k,v in buffers.items()}}
    return receipt,buffers,metadata


class BoundaryControls(unittest.TestCase):
    def test_peer_setup_keeps_tap_unaddressed_and_refuses_automatic_link_local(self):
            for automatic in (False, True):
                calls=[]
                def checked(argv):
                    calls.append(argv)
                    if "sysctl" in argv and "-n" in argv:
                        text="1\n"
                    elif "show" in argv and "link" in argv:
                        text=json.dumps([{"mtu":1500,"address":m.HOST_MAC.hex(":")}])
                    elif "show" in argv and "addr" in argv:
                        text=json.dumps([{"addr_info":[{"family":"inet6","local":"fe80::1","prefixlen":64}] if automatic else []}])
                    else:text=""
                    return SimpleNamespace(stdout=text)
                if automatic:
                    with self.assertRaises(AssertionError):m.prepare_peer_link("fixture","tap0",execute=checked)
                else:self.assertEqual(m.prepare_peer_link("fixture","tap0",execute=checked)[0]["mtu"],1500)
                self.assertTrue(any("net.ipv6.conf.default.addr_gen_mode=1" in argv for argv in calls))
                self.assertFalse(any("addr" in argv and "add" in argv for argv in calls))

    def test_actual_peer_activation_requires_running_ready_and_exact_address_transition(self):
            ready={"producer_observed_running":True,"serial_ready_line":m.NIC_READY.decode()}
            for observation in (None,{**ready,"producer_observed_running":False},{**ready,"serial_ready_line":"other\n"}):
                checked=Mock()
                with self.assertRaises(AssertionError):m.activate_peer("fixture","tap0",SimpleNamespace(observation=observation),execute=checked)
                checked.assert_not_called()
            peer={"family":"inet6","local":"fd00:ab5d::2","prefixlen":64}
            for before,after,accepted in (([],[peer],True),([peer],[peer],False),([],[{**peer,"local":"fe80::1"}],False),([],[peer,peer],False)):
                calls=[];reads=iter((before,after))
                def checked(argv):
                    calls.append(argv)
                    return SimpleNamespace(stdout=json.dumps([{"addr_info":next(reads)}]) if "show" in argv else "")
                if accepted:
                    result=m.activate_peer("fixture","tap0",SimpleNamespace(observation=ready),execute=checked)
                    self.assertEqual(result["addresses_before"][0]["addr_info"],[])
                    self.assertEqual(result["addresses_after"][0]["addr_info"],[peer])
                else:
                    with self.assertRaises(AssertionError):m.activate_peer("fixture","tap0",SimpleNamespace(observation=ready),execute=checked)
                additions=[a for a in calls if "addr" in a and "add" in a]
                self.assertEqual(len(additions),0 if before else 1)
                if additions:self.assertIn("fd00:ab5d::2/64",additions[0])

    def test_kernel_readiness_is_raw_observation_and_worker_uses_echo_decoder(self):
        ready={"producer_observed_running":True,"serial_ready_line":m.NIC_READY.decode()}
        with patch.object(m,"decode_output") as decoded:
            self.assertFalse(m.readiness_observed(m.NIC_READY,Path("unused"),SimpleNamespace(observation=None)))
            self.assertTrue(m.readiness_observed(m.NIC_READY,Path("unused"),SimpleNamespace(observation=ready)))
            for observation in ({**ready,"producer_observed_running":False},{**ready,"serial_ready_line":"other\n"}):
                with self.assertRaises(AssertionError):m.readiness_observed(m.NIC_READY,Path("unused"),SimpleNamespace(observation=observation))
            decoded.assert_not_called()
        with patch.object(m,"bounded",return_value=b"raw"),patch.object(m,"decode_output",return_value=READY):
            self.assertTrue(m.readiness_observed(READY.encode(),Path("unused"),SimpleNamespace(observation=None)))
        with patch.object(m,"bounded",return_value=b"raw"),patch.object(m,"decode_output",return_value=""):
            self.assertFalse(m.readiness_observed(READY.encode(),Path("unused"),SimpleNamespace(observation=ready)))


    def inspect(self,change=None):
        frames,native,peer=inputs()
        if change:change(frames,native,peer)
        return m.inspect(capture(frames),native,peer)
    def refuse(self,change):
        with self.assertRaises(AssertionError):self.inspect(change)

    def test_full_consumed_negative_census_then_real_positive_pair(self):
        result=self.inspect()
        self.assertEqual(result['boundary']['indices'],{'warm-ns':4,'warm-na':5,'bad-checksum':6,'short-icmp':7,'wrong-code':8,'wrong-peer':9})
        self.assertEqual(result['by_kind'],{'guest-dad-ns':[1],'echo-request':[10],'echo-reply':[11]})

    def test_raw_literal_bytes_independently_match_product_fixture(self):
        actual=dict(line.split('=') for line in (m.ROOT/'fixtures/native-ipv6-echo-responder/boundary-v1.txt').read_text().splitlines())
        self.assertEqual({n:f.hex() for n,f in m.boundary_frames().items()},actual)
        for name,f in m.boundary_frames().items():
            check=wire_sum(f[22:54]+struct.pack('!I3xB',len(f)-54,58)+f[54:])
            self.assertEqual(check==0,name!='bad-checksum')
        self.assertEqual(len(m.boundary_frames()['short-icmp']),61)
        self.assertEqual(m.boundary_frames()['warm-na'][58:62],bytes.fromhex('40000000'))
        old_na=frame(m.GUEST,m.OTHER,b'\x88\0'+bytes(2)+bytes.fromhex('60000000')+m.GUEST+b'\x02\x01'+m.GUEST_MAC,True,hop=255)
        self.assertEqual(wire_sum(old_na[22:54]+struct.pack('!I3xB',len(old_na)-54,58)+old_na[54:]),0)
        self.refuse(lambda rows,n,p:rows.__setitem__(4,old_na))

    def test_both_actual_neighbor_priming_exchanges_precede_refusals(self):
        for index in [1,2,3,4]:self.refuse(lambda f,n,p:f.pop(index))
        self.refuse(lambda f,n,p:f.__setitem__(slice(3,5),[f[4],f[3]]))
        self.refuse(lambda f,n,p:f.__setitem__(slice(4,6),[f[5],f[4]]))

    def test_missing_duplicate_reordered_or_changed_negative_input_refuses(self):
        for index in range(5,9):
            self.refuse(lambda f,n,p:f.pop(index))
            self.refuse(lambda f,n,p:f.insert(index,f[index]))
            self.refuse(lambda f,n,p:f.__setitem__(index,f[index][:-1]+bytes([f[index][-1]^1])))
        self.refuse(lambda f,n,p:f.__setitem__(slice(5,7),[f[6],f[5]]))

    def test_negative_reply_or_unresolved_neighbor_probe_cannot_substitute(self):
        for name in m.BOUNDARY_NAMES:
            f=m.boundary_frames()[name];reply=frame(m.GUEST,f[22:38],bytes([129,0])+f[56:],True,hop=64)
            self.refuse(lambda rows,n,p:rows.insert(9,reply))
        probe=frame(m.GUEST,m.original.solicited(m.OTHER),b'\x87\0'+bytes(6)+m.OTHER+b'\x01\x01'+m.GUEST_MAC,True,bytes.fromhex('3333ff000003'))
        self.refuse(lambda rows,n,p:rows.insert(9,probe))

    def test_actual_native_ordinals_are_bound_to_full_incoming_census(self):
        self.refuse(lambda f,n,p:n['boundary']['inputs'][0].update(receive_ordinal=2))
        self.refuse(lambda f,n,p:n['boundary']['warm'].update(na_send_ordinal=2))
        self.refuse(lambda f,n,p:n['boundary']['warm'].update(ns_receive_ordinal=1))
        self.refuse(lambda f,n,p:n['boundary']['inputs'][-1].update(frame=m.digest(b'claimed')))

    def test_native_actual_byte_records_and_owner_zero_effects_are_required(self):
        text=boundary_output()
        for old,new in [('effects=0 observation=Again','effects=1 observation=Again'),('observation=Again','observation=Spent'),('case=wrong-peer','case=wrong-source'),('ns_rx=2','ns_rx=0'),('na_after_rx=2','na_after_rx=3'),('rx=3 frame=','rx=2 frame=')]:
            with self.assertRaises(AssertionError):m.native_output(serial(text.replace(old,new)),3)
        frame_hex=m.boundary_frames()['wrong-code'].hex()
        with self.assertRaises(AssertionError):m.native_output(serial(text.replace(frame_hex,frame_hex[:-2]+'00')),3)

    def test_one_shot_method_and_retired_state_have_no_wire_replay_claim(self):
        for old,new in [('observe=Spent','observe=Again'),('activate=Exhausted','activate=Denied'),('retired=Stale','retired=Spent')]:
            with self.assertRaises(AssertionError):m.native_output(serial(boundary_output().replace(old,new)),3)
        self.assertIn('not production drop telemetry or wire replay',m.native_output(serial(),3)['boundary']['scope'])

    def test_real_ping_full_positive_checksum_body_and_capture_are_still_required(self):
        self.refuse(lambda f,n,p:f.pop())
        self.refuse(lambda f,n,p:f.append(f[-1]))
        self.refuse(lambda f,n,p:f.__setitem__(-1,echo(True,data=bytes([9])*56)))
        self.refuse(lambda f,n,p:f.__setitem__(-1,f[-1][:-1]))
        self.assertEqual(m.ping_output(PING,0)['status'],0)
        for raw,status in [(PING,1),(PING.replace(b'1 received',b'0 received'),0),(PING+PING,0)]:
            with self.assertRaises(AssertionError):m.ping_output(raw,status)

    def test_actual_ready_and_negative_ready_prefixes_precede_positive(self):
        text=boundary_output();negative='\n'.join(text.splitlines()[:7])+'\n'
        original=serial();chunk_marker=b"EXTERNAL OUTPUT CHUNK"
        # Same complete output/FNV and terminal records, segmented at the two
        # observation boundaries rather than replacing raw serial with stdout.
        head=original[:original.index(chunk_marker)]
        tail=original[original.index(b"USER EXIT pid=2 status=0\n"):]
        raw=(head+chunk(READY)+chunk(negative[len(READY):],len(READY.encode()))+
             chunk(text[len(negative):],len(negative.encode()))+tail)
        first_chunk=raw.index(chunk_marker)
        first=raw[:raw.index(b"\n",first_chunk)+1]
        ready=m.readiness(first);native=m.native_output(raw,3)
        m.ready_correspondence(raw,ready,native)
        # Former fixture omitted the kernel prefix; decoded READY alone is not
        # a prefix of the retained terminal serial and must still be refused.
        with self.assertRaises(AssertionError):m.ready_correspondence(raw,m.readiness(chunk(READY)),native)
        second_chunk=raw.index(chunk_marker,first_chunk+1)
        prefix=raw[:raw.index(b"\n",second_chunk)+1]
        observed=m.negative_readiness(prefix)
        self.assertEqual(observed['serial_prefix'],m.digest(raw[:len(prefix)]))
        self.assertLess(len(prefix),len(raw))
        self.assertIsNone(m.negative_readiness(first))
        with self.assertRaises(AssertionError):m.negative_readiness(raw)
        with self.assertRaises(AssertionError):m.ready_correspondence(raw,ready,dict(native,stop_ms=9101))
        before='\n'.join(text.splitlines()[:6])+'\n'
        last=text.splitlines()[6]+'\n'
        live_head=head+chunk(before)
        for end in range(len(last)):
            live=live_head+(chunk(last[:end],len(before.encode())) if end else b'')
            self.assertIsNone(m.negative_readiness(live))
        complete=live_head+chunk(last,len(before.encode()))
        self.assertEqual(m.negative_readiness(complete)['negative_complete_text'],last.rstrip('\n'))
        with self.assertRaises(AssertionError):m.negative_readiness(live_head+chunk(last.replace('cases=4','cases=3'),len(before.encode())))
        with self.assertRaises(AssertionError):m.negative_readiness(head+chunk(negative+'PING6'))

    def test_native_serial_digest_exit_no_child_and_resource_zeros_remain_strict(self):
        for raw,status in [(serial(),7),(serial().replace(b'frames=0',b'frames=1'),3),(serial()+b'SPAWN OK pid=3 parent=2 program=image\n',3),(serial().replace(b'END bytes=',b'END bytes=9'),3)]:
            with self.assertRaises(AssertionError):m.native_output(raw,status)
        for old,new in [('sockets=0','sockets=1'),('possible_effects=1','possible_effects=0'),('auth=none','auth=verified'),('icmp_bytes=64','icmp_bytes=63')]:
            with self.assertRaises(AssertionError):m.native_output(serial(boundary_output().replace(old,new)),3)

    def test_current_source_kernel_wrapper_std_and_actual_bin_metadata_are_pinned(self):
        receipt,buffers,metadata=build_fixture();m.build_binding(receipt,buffers);m.metadata_binding(receipt,metadata)
        for name in ['platform','kernel']:
            bad=copy.deepcopy(receipt);bad[name]['revision']='0'*40
            with self.assertRaises(AssertionError):m.build_binding(bad,buffers)
        for key,value in [('served_wrapper_sha256','0'*64),('served_kernel_policy','other'),('target','host')]:
            bad=copy.deepcopy(receipt);bad[key]=value
            with self.assertRaises(AssertionError):m.build_binding(bad,buffers)
        bad=copy.deepcopy(receipt);bad['staged_std']['files']=0
        with self.assertRaises(AssertionError):m.build_binding(bad,buffers)
        changed=json.loads(metadata);changed['packages'][0]['targets'][0]['required-features']=[];raw=json.dumps(changed).encode();bad=copy.deepcopy(receipt);bad['cargo_metadata'].update(m.digest(raw))
        with self.assertRaises(AssertionError):m.metadata_binding(bad,raw)

    def test_iso_and_exact_embedded_parent_checks_are_retained(self):
        receipt,buffers,metadata=build_fixture();boot=b'exact config\n';image=iso(buffers['kernel'],boot)
        m.iso_binding(image,buffers['kernel'],boot)
        with self.assertRaises(AssertionError):m.iso_binding(image+buffers['kernel'],buffers['kernel'],boot)
        changed=dict(buffers);changed['kernel']=elf(b'other')
        with self.assertRaises(AssertionError):m.build_binding(receipt,changed)

    def test_sender_actual_method_waits_for_actual_na_and_closes_before_receipt(self):
        events=[];frames=m.boundary_frames()
        class Socket:
            def __enter__(self):events.append('open');return self
            def __exit__(self,*a):events.append('close')
            def bind(self,address):self_address=address;events.append(('bind',self_address))
            def settimeout(self,seconds):self_seconds=seconds;events.append(('timeout',self_seconds))
            def send(self,frame):events.append(('send',frame));return len(frame)
            def recv(self,n):events.append('recv');return frames['warm-na']
        def write(path,record):
            self.assertEqual(events[-1],'close');self.assertTrue(record['socket_closed'])
            self.assertEqual([r['case'] for r in record['events'] if r['operation']=='send'],['warm-ns',*m.BOUNDARY_NAMES])
            m.negative_receipt(record,self.inspect())
        with patch.object(m.socket,'socket',return_value=Socket()) as ctor,patch.object(m,'write',side_effect=write):
            m.send_negative_inputs(Path('/unwritten'), 'resp6-tap0')
        ctor.assert_called_once_with(m.socket.AF_PACKET,m.socket.SOCK_RAW,m.socket.htons(0x86dd))
        self.assertEqual([e[1] for e in events if isinstance(e,tuple) and e[0]=='send'],[frames['warm-ns'],*[frames[n] for n in m.BOUNDARY_NAMES]])
        self.assertLess(events.index('recv'),events.index(('send',frames['bad-checksum'])))

    def test_sender_short_send_or_unmatched_na_fails_without_positive_input(self):
        sock=Mock();sock.__enter__=Mock(return_value=sock);sock.__exit__=Mock(return_value=False);sock.send.return_value=1
        with patch.object(m.socket,'socket',return_value=sock),self.assertRaises(AssertionError):m.send_negative_inputs(Path('/unwritten'),'resp6-tap0')
        sock.send.side_effect=lambda frame:len(frame);sock.recv.side_effect=TimeoutError
        with patch.object(m.socket,'socket',return_value=sock),self.assertRaises(TimeoutError):m.send_negative_inputs(Path('/unwritten'),'resp6-tap0')
        self.assertTrue(all(call.args[0]==m.boundary_frames()['warm-ns'] for call in sock.send.call_args_list))

    def test_negative_receipt_missing_na_extra_send_changed_bytes_and_order_refuse(self):
        frames=m.boundary_frames();events=[]
        for operation,name in [('send','warm-ns'),('receive','warm-na'),*[('send',n) for n in m.BOUNDARY_NAMES]]:
            events.append({'ordinal':len(events)+1,'operation':operation,'case':name if operation=='send' else None,'frame':frames[name].hex(),'bytes':len(frames[name]),'monotonic_ns':len(events)+1})
        receipt={'schema':'absd-ipv6-echo-negative-input/1','socket_closed':True,'events':events}
        m.negative_receipt(receipt,self.inspect())
        changes=[lambda r:r.update(socket_closed=False),lambda r:r['events'].pop(1),lambda r:r['events'].append(copy.deepcopy(r['events'][-1])),lambda r:r['events'][2].update(frame='00'),lambda r:r['events'][2].update(ordinal=1),lambda r:r['events'][2].update(monotonic_ns=0)]
        for change in changes:
            bad=copy.deepcopy(receipt);change(bad)
            with self.assertRaises(AssertionError):m.negative_receipt(bad,self.inspect())

    def test_first_four_nic_reason_and_ready_sidecar_contract_is_unchanged(self):
        frames,native,p=inputs();raw=capture([mld()]*2+frames);census=[m.classify(r) for r in m.original.capture_records(raw)[0]]
        serial_raw=b'NIC RX FILTERED dst=33:33:00:00:00:16\n'*2+serial();fields=dict(native['NIC_counters']);fields['rx_refused']='2'
        annotation={'schema':'absd-ipv6-ready-capture-sidecar/1','policy':m.original.POLICY,'capture':m.digest(raw),'serial':m.digest(serial_raw),'previous_absent':None,'observation':{'serial_bytes':len(serial_raw),'serial_sha256':m.digest(serial_raw)['sha256'],'capture_before_serial_read':m.digest(raw),'capture_after_serial_read':m.digest(raw)}}
        check=lambda:m.reason_accounting(raw,serial_raw,json.dumps(annotation).encode(),annotation,fields,census)
        self.assertEqual(check()['disposition'],'PASS')
        fields['rx_missed']='1';self.assertEqual(check()['disposition'],'FAIL');fields['rx_missed']='0'
        annotation['observation']['serial_sha256']='0'*64;self.assertEqual(check()['disposition'],'FAIL')

    def test_evaluated_negative_receipt_and_serial_are_sealed_against_mutation(self):
        for name in ['NEGATIVE-INPUT.json','NEGATIVE-OBSERVATION.json','WARM-INPUT.json','LINUX-NEIGHBOR-WARM.json','native-ipv6-echo-responder.serial.log','native-ipv6-echo-responder.pcap']:
            with tempfile.TemporaryDirectory() as d:
                work=Path(d);path=work/name;path.write_bytes(b'observed')
                result={'evaluated_artifacts':{name:m.identity(path,b'observed')},'evaluated_build_inputs':{},'proof_inputs':{}}
                path.write_bytes(b'changed')
                with self.assertRaises(AssertionError):m.seal_artifacts(work,result)

    def raw_warm_fixture(self):
        frames=m.protocol_warm_frames();events=[]
        for operation,name in [('send','warm-ns'),('receive','warm-na')]:
            events.append({'ordinal':len(events)+1,'operation':operation,'case':name if operation=='send' else None,
                           'frame':frames[name].hex(),'bytes':len(frames[name]),'monotonic_ns':len(events)+11})
        receipt={'schema':'absd-ipv6-echo-raw-neighbor-input/1','socket_closed':True,'interface':'resp6-tap0',
                 'started_monotonic_ns':10,'closed_monotonic_ns':13,'deadline_monotonic_ns':2_000_000_010,'events':events}
        return receipt,capture([dad(),*frames.values()])

    def test_protocol_warm_sender_calls_actual_socket_and_closes_before_receipt(self):
        events=[];frames=m.protocol_warm_frames()
        self.assertEqual(list(frames.values()),nd())
        class Socket:
            def __enter__(self):return self
            def __exit__(self,*args):events.append('close')
            def bind(self,address):self.address=address
            def settimeout(self,seconds):self.seconds=seconds
            def send(self,data):events.append(data);return len(data)
            def recv(self,maximum):events.append('receive');return frames['warm-na']
        def written(path,record):
            self.assertEqual(events[-1],'close');self.assertEqual(path.name,'WARM-INPUT.json')
            self.assertIsNotNone(m.raw_warm_correspondence(record,capture([dad(),*frames.values()])))
        with patch.object(m.socket,'socket',return_value=Socket()),patch.object(m,'write',side_effect=written):
            m.send_negative_inputs(Path('/unwritten'),'resp6-tap0',protocol_warm=True)
        self.assertEqual(events,[frames['warm-ns'],'receive','close'])
        sock=Mock();sock.__enter__=Mock(return_value=sock);sock.__exit__=Mock(return_value=False);sock.send.return_value=1
        with patch.object(m.socket,'socket',return_value=sock),self.assertRaises(AssertionError):
            m.send_negative_inputs(Path('/unwritten'),'resp6-tap0',protocol_warm=True)
        sock.send.side_effect=lambda frame:len(frame);sock.recv.side_effect=TimeoutError
        with patch.object(m.socket,'socket',return_value=sock),self.assertRaises(TimeoutError):
            m.send_negative_inputs(Path('/unwritten'),'resp6-tap0',protocol_warm=True)

    def test_raw_capture_and_closed_ordered_receipt_precede_any_neighbor_pin(self):
        receipt,raw=self.raw_warm_fixture();frames=m.protocol_warm_frames()
        bad_records=[]
        for change in (lambda r:r.update(socket_closed=False),lambda r:r.update(closed_monotonic_ns=r['deadline_monotonic_ns']),
                       lambda r:r['events'].reverse(),lambda r:r['events'].append(copy.deepcopy(r['events'][0])),
                       lambda r:r['events'][1].update(frame='00'),lambda r:r.update(interface='wrong-tap')):
            bad=copy.deepcopy(receipt);change(bad);bad_records.append((bad,raw))
        bad_records.extend((receipt,capture(rows)) for rows in ([dad(),frames['warm-ns']], [dad(),frames['warm-na'],frames['warm-ns']],
                                                              [dad(),frames['warm-ns'],frames['warm-na'],frames['warm-na']]))
        for bad,cap in bad_records:
            called=Mock()
            with self.assertRaises(AssertionError):m.pin_protocol_neighbor('fixture','resp6-tap0',bad,cap,execute=called)
            called.assert_not_called()

    def test_actual_pin_readback_and_final_capture_binding_are_not_automatic_nd(self):
        receipt,raw=self.raw_warm_fixture();calls=[]
        row={'dst':m.GUEST_IP,'dev':'resp6-tap0','lladdr':m.GUEST_MAC.hex(':'),'state':['REACHABLE']}
        def execute(argv):
            calls.append(argv)
            return json.dumps([row]) if len(calls)==3 else '[]'
        warm=m.pin_protocol_neighbor('fixture','resp6-tap0',receipt,raw,execute=execute)
        self.assertEqual(calls[1],['ip','-n','fixture','-6','neigh','replace',m.GUEST_IP,'lladdr',m.GUEST_MAC.hex(':'),'nud','reachable','dev','resp6-tap0'])
        self.assertNotIn('dev',calls[0]);self.assertNotIn('dev',calls[2])
        self.assertIn('Administrator-set',warm['meaning']);m.warm_correspondence(raw,warm)
        with self.assertRaises(AssertionError):m.warm_correspondence(raw+b'changed',dict(warm,snapshot=dict(warm['snapshot'],capture_prefix=m.digest(raw+b'changed'))))
        for key,value in [('dst','fd00:ab5d::9'),('dev','other'),('lladdr','00:00:00:00:00:00'),('state',['STALE'])]:
            bad=dict(row,**{key:value});responses=iter(('[]','',json.dumps([bad])))
            with self.assertRaises(AssertionError):m.pin_protocol_neighbor('fixture','resp6-tap0',receipt,raw,execute=lambda argv:next(responses))


if __name__=='__main__':unittest.main()
