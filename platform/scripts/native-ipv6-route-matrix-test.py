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

spec = importlib.util.spec_from_file_location("route_matrix", Path(__file__).with_name("native-ipv6-route-matrix.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def wire_sum(data):
    value = 0
    for at in range(0, len(data), 2):
        value += (data[at] << 8) + (data[at + 1] if at + 1 < len(data) else 0)
        value = (value & 65535) + (value >> 16)
    return value ^ 65535


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


def build_fixture():
    child = elf(b"unique-child")
    parent = elf(b"unique-parent", child)
    kernel = elf(b"unique-kernel", parent)
    buffers = {"child": child, "parent": parent, "kernel": kernel}
    pointer = lambda path, data: {"path": path, **m.digest(data)}
    external = {"parent": pointer("parent.elf", parent), "input": pointer("empty-input", b""), "expected": pointer("empty-expected", b"")}
    receipt = {"schema": "absd-native-ipv6-route-build/1",
               "platform": {"revision": m.PRODUCT, "tree": m.PRODUCT_TREE, "clean": True,
                            "archive": {"bytes": m.PRODUCT_BYTES, "sha256": m.PRODUCT_ARCHIVE}},
               "kernel": {"revision": m.KERNEL, "tree": m.KERNEL_TREE, "clean": True,
                          "archive": {"bytes": m.KERNEL_BYTES, "sha256": m.KERNEL_ARCHIVE}},
               "commands": [["sh", "scripts/build-native-ipv6-route.sh"], ["make", "external-build", "EXTERNAL_USER_ELF=parent.elf", "EXTERNAL_INPUT=empty-input", "EXTERNAL_EXPECTED=empty-expected"]],
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


def packet(source, destination, body, source_mac, destination_mac, hop=255, protocol=58):
    body = bytearray(body)
    at = 2 if protocol == 58 else 6
    body[at:at+2] = bytes(2)
    body[at:at+2] = wire_sum(source + destination + struct.pack("!I3xB",len(body),protocol) + body).to_bytes(2,"big")
    return (destination_mac + source_mac + bytes.fromhex("86dd60000000")
            + struct.pack("!HBB",len(body),protocol,hop) + source + destination + body)


def nd(link):
    a,b,am,bm = (m.GUEST,m.ROUTER,m.GUEST_MAC,m.ROUTER_MAC) if link == "guest" else (m.UPLINK_LL,m.PEER,m.UPLINK_MAC,m.PEER_MAC)
    ns = packet(a,m.original.solicited(b),b"\x87\0"+bytes(6)+b+b"\x01\x01"+am,am,b"\x33\x33\xff"+b[-3:])
    flags = bytes.fromhex("e0000000" if link == "guest" else "60000000")
    na = packet(b,a,b"\x88\0"+bytes(2)+flags+b+b"\x02\x01"+bm,bm,am)
    return [ns,na]


def query(kind=1):
    label = b"\x01a" if kind == 1 else b"\x04aaaa"
    return bytes.fromhex("123401000001000000000000")+label+b"\x07example\0"+struct.pack("!HH",kind,1)


def udp(link, answer=False, kind=1, source=None, port=None):
    source = source or (m.PEER if answer else m.GUEST)
    dest = m.GUEST if answer else m.PEER
    sm,dm = ((m.GUEST_MAC,m.ROUTER_MAC) if not answer else (m.ROUTER_MAC,m.GUEST_MAC)) if link == "guest" else ((m.UPLINK_MAC,m.PEER_MAC) if not answer else (m.PEER_MAC,m.UPLINK_MAC))
    hop = (64 if not answer else 63) if link == "guest" else (63 if not answer else 64)
    body = m.dns.answer(query(kind)) if answer else query(kind)
    ports = (42010,7002) if answer else (7002,42010)
    if port:ports = (ports[0],port)
    body = struct.pack("!HHHH",*ports,len(body)+8,0)+body
    return packet(source,dest,body,sm,dm,hop,17)


def peer():
    records=[]
    for kind in (1,28):
        q=query(kind);name,k=m.dns.question(q)
        records.append({"transport":"Linux AF_INET6 SOCK_DGRAM","source":[m.GUEST_IP,7002,0,0],"port":42010,
                        "query_hex":q.hex(),"answer_hex":m.dns.answer(q).hex(),"name":name,"kind":k})
    return {"disposition":"PASS","errors":[],"records":records,"pid":123}


def frames(link):
    return nd(link)+[udp(link,False,1),udp(link,True,1),udp(link,False,28),udp(link,True,28)]


def output():
    return ("ROUTE6 SELECTOR local=fd00:ab5d:1::15/64 router=fd00:ab5d:1::2 peer=fd00:ab5d:2::9 udp=42010 scope=1 dad=unrun\n"
            "ROUTE6 CENSUS label=before processes=2 handles=13 pipes=2 cells=1 frames=100\n"
            "ROUTE6 NO-ROUTE REFUSAL PASS bind=denied sockets=0\n"
            "ROUTE6 API BOUNDARIES PASS malformed=9 denied=3 oversize=1 queue=4 endpoints=8 stale=2 sockets=0 queued-test-wire=0\n"
            "ROUTE6 PIPE BOUNDARIES PASS eof=1 partial-expiry=1 port-reuse=2 sockets=0\n"
            "ROUTE6 RX SETUP elapsed_ms=1100 continuous-vm=assumed\n"
            "ROUTE6 SERVICE READY scope=1 local-port=7002 peer=fd00:ab5d:2::9 peer-port=42010\n"
            "ROUTE6 CLIENT AUTHORITY PASS nic=0 framed-denied=3\n"
            "ROUTE6 DNS A PASS address=192.0.2.9\nROUTE6 DNS AAAA PASS address=2001:db8::9\n"
            "ROUTE6 RETIRE sockets=0\nROUTE6 CENSUS label=after processes=2 handles=13 pipes=2 cells=1 frames=150\n"
            "ROUTE6 SERVICE PASS child=exited sockets=0 resources=restored\n")


def serial(text=None):
    data=(output() if text is None else text).encode();h=0x811c9dc5
    for b in data:h=((h^b)*0x01000193)&0xffffffff
    return (b"NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n"
            b"SPAWN OK pid=3 parent=2 program=image\nUSER EXIT pid=3 status=0\nUSER EXIT pid=2 status=0\n"
            b"DURABLE WORKER OUTCOME generation=1 pid=2 status=0\n"
            b"EXTERNAL OUTPUT CHUNK offset=0000000000000000 data="+data.hex().encode()+b"\n"
            b"EXTERNAL OUTPUT END bytes="+str(len(data)).encode()+b" digest="+f"{h:08x}".encode()+b"\n"
            b"NIC STATS rx_frames=4 rx_refused=0 rx_missed=0 tx_frames=4 tx_refused=0 tx_errors=0 flags=1\n"
            b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 block_reads=0 block_writes=0 block_flushes=0 block_errors=0 block_waits=0 block_irqs=0 ticks=999\n"
            b"DURABLE WORKLOAD OK\nABSD BOOT OK\n")


def mld():
    # Existing retained Linux MLDv2 literal, parser-only, never injected.
    return (bytes.fromhex("33330000001652550000020286dd6000000000380001")+bytes(16)
            +bytes.fromhex("ff020000000000000000000000000016")
            +bytes.fromhex("3a000502000001008f006b6c0000000204000000ff0200000000000000000001ff00020204000000ff0200000000000000000001ff000002"))



def topology():
    value={"transport":"Linux kernel IPv6 forwarding and AF_INET6 UDP; application DNS answers are controlled fixtures","namespaces":{}}
    for role,devs in (("router",[("r6-tap",m.ROUTER_IP,m.ROUTER_MAC),("r6-out",m.UPLINK_IP,m.UPLINK_MAC)]),("peer",[("r6-peer",m.PEER_IP,m.PEER_MAC)])):
        value["namespaces"][role]={"inode":1 if role=="router" else 2,"sysctls":{"net.ipv6.conf.all.forwarding":"1" if role=="router" else "0","net.ipv6.conf.default.forwarding":"1" if role=="router" else "0","net.ipv6.conf.all.accept_ra":"0"},
            "links":[{"ifname":"lo","ifindex":1}]+[{"ifname":d,"ifindex":i+2,"address":mac.hex(":"),"mtu":1500,"flags":["UP"]} for i,(d,_,mac) in enumerate(devs)],
            "addresses":[{"ifname":d,"ifindex":i+2,"addr_info":[{"family":"inet6","local":ip,"prefixlen":64}]} for i,(d,ip,_) in enumerate(devs)],
            "offloads":{d:"tx-checksumming: off\ngeneric-segmentation-offload: off\ngeneric-receive-offload: off" for d,_,_ in devs},
            "routes":[{"dst":"fd00:ab5d:1::/64","gateway":m.UPLINK_IP,"dev":"r6-peer"}] if role=="peer" else []}
    value["namespaces"]["router"]["addresses"][1]["addr_info"].append(
        {"family":"inet6","local":m.UPLINK_LL_IP,"prefixlen":64,"scope":"link"})
    return value


class ArtifactControls(unittest.TestCase):
    def inspect(self,g=None,p=None,observed=None):
        return m.inspect(capture(frames("guest") if g is None else g),capture(frames("peer") if p is None else p),peer() if observed is None else observed)

    def test_exact_static_router_and_peer_configuration(self):
        self.assertEqual(set(m.validate_topology(topology())["namespaces"]),{"router","peer"})

    def test_forwarding_mtu_route_address_and_extra_interface_substitution_refuse(self):
        changes=[lambda p:p["namespaces"]["router"]["sysctls"].update({"net.ipv6.conf.all.forwarding":"0"}),
                 lambda p:p["namespaces"]["router"]["links"][1].update(mtu=1280),
                 lambda p:p["namespaces"]["router"]["links"][1].update(address="00:00:00:00:00:00"),
                 lambda p:p["namespaces"]["router"]["links"][1].update(ifindex=99),
                 lambda p:p["namespaces"]["router"]["links"][1].update(flags=[]),
                 lambda p:p["namespaces"]["peer"]["routes"][0].update(gateway=m.ROUTER_IP),
                 lambda p:p["namespaces"]["peer"]["links"].append({"ifname":"other"}),
                 lambda p:p["namespaces"]["peer"]["addresses"][0]["addr_info"][0].update(local=m.ROUTER_IP)]
        for change in changes:
            value=topology();change(value)
            with self.assertRaises(AssertionError):m.validate_topology(value)

    def test_complete_two_link_routing_and_socket_correlation(self):
        value=m.peer_result(json.dumps(peer()).encode());self.assertEqual(len(value["records"]),2)
        self.assertEqual(self.inspect()["queries"],2)

    def test_exact_egress_link_local_is_required_without_automatic_addresses(self):
        self.assertEqual(m.validate_topology(topology())["namespaces"]["router"]["addresses"][1]["addr_info"][1]["local"],m.UPLINK_LL_IP)
        for change in (lambda a:a.pop(),lambda a:a[1].update(local="fe80::204"),
                       lambda a:a[1].update(prefixlen=128),lambda a:a[1].update(scope="global"),
                       lambda a:a.append(dict(a[1]))):
            state=topology();change(state["namespaces"]["router"]["addresses"][1]["addr_info"])
            with self.assertRaises(AssertionError):m.validate_topology(state)

    def test_exact_forwarding_nd_link_local_and_reverse_gateway_resolution(self):
        # Actual forwarding NS uses the router LLA; the peer separately resolves
        # its configured ULA next hop before sending the return DNS datagram.
        rows=frames("peer")
        reverse_ns=packet(m.PEER,m.original.solicited(m.UPLINK),b"\x87\0"+bytes(6)+m.UPLINK+b"\x01\x01"+m.PEER_MAC,
                          m.PEER_MAC,b"\x33\x33\xff"+m.UPLINK[-3:])
        reverse_na=packet(m.UPLINK,m.PEER,b"\x88\0"+bytes(2)+bytes.fromhex("e0000000")+m.UPLINK+b"\x02\x01"+m.UPLINK_MAC,
                          m.UPLINK_MAC,m.PEER_MAC)
        rows[3:3]=[reverse_ns,reverse_na]
        self.assertEqual(self.inspect(p=rows)["answers"],2)
        unrelated=bytes.fromhex("fe800000000000000000000000000204")
        for at,replacement in ((0,packet(unrelated,m.original.solicited(m.PEER),
                                        b"\x87\0"+bytes(6)+m.PEER+b"\x01\x01"+m.UPLINK_MAC,
                                        m.UPLINK_MAC,b"\x33\x33\xff"+m.PEER[-3:])),
                               (1,packet(m.PEER,unrelated,b"\x88\0"+bytes(2)+bytes.fromhex("60000000")+m.PEER+b"\x02\x01"+m.PEER_MAC,
                                         m.PEER_MAC,m.UPLINK_MAC))):
            changed=frames("peer");changed[at]=replacement
            with self.assertRaises(AssertionError):self.inspect(p=changed)

    def test_valid_checksum_wrong_peer_ip_port_mac_refuses(self):
        for link in ("guest","peer"):
            for replacement in (udp(link,source=m.UPLINK),udp(link,port=42011),bytes(60)):
                changed=frames(link);changed[2]=replacement
                with self.assertRaises(AssertionError):self.inspect(**{("g" if link=="guest" else "p"):changed})

    def test_checksum_truncation_extensions_and_padding_refuse(self):
        for link in ("guest","peer"):
            baseline=frames(link)
            for at in range(len(baseline)):
                changed=list(baseline);bad=bytearray(changed[at]);bad[-1]^=1;changed[at]=bytes(bad)
                with self.assertRaises(AssertionError):self.inspect(**{("g" if link=="guest" else "p"):changed})
            for bad in (baseline[-1][:-1],baseline[-1]+b"\0",baseline[-1][:20]+b"\x2c"+baseline[-1][21:]):
                changed=list(baseline);changed[-1]=bad
                with self.assertRaises(AssertionError):self.inspect(**{("g" if link=="guest" else "p"):changed})

    def test_hop_limit_and_complete_packet_substitutions_refuse(self):
        changed=frames("peer");bad=bytearray(changed[2]);bad[21]=64;changed[2]=bytes(bad)
        with self.assertRaises(AssertionError):self.inspect(p=changed)
        changed=frames("peer");bad=bytearray(changed[2]);bad[15]^=1;changed[2]=bytes(bad)
        with self.assertRaises(AssertionError):self.inspect(p=changed)

    def test_missing_nd_wrong_router_flag_and_reply_order_refuse(self):
        for link in ("guest","peer"):
            changed=frames(link);changed.pop(0)
            with self.assertRaises(AssertionError):self.inspect(**{("g" if link=="guest" else "p"):changed})
            changed=frames(link);changed[2],changed[3]=changed[3],changed[2]
            with self.assertRaises(AssertionError):self.inspect(**{("g" if link=="guest" else "p"):changed})
        changed=frames("guest");body=bytearray(changed[1][54:]);body[4]&=0x7f
        changed[1]=packet(m.ROUTER,m.GUEST,body,m.ROUTER_MAC,m.GUEST_MAC)
        with self.assertRaises(AssertionError):self.inspect(g=changed)

    def test_missing_duplicate_or_third_datagram_refuses(self):
        for change in (lambda x:x.pop(),lambda x:x.append(x[-1]),lambda x:x.append(udp("guest",port=42011))):
            changed=frames("guest");change(changed)
            with self.assertRaises(AssertionError):self.inspect(g=changed)

    def test_retry_multiplicity_requires_exact_records_on_both_links(self):
        observed=peer();observed["records"].insert(1,copy.deepcopy(observed["records"][0]))
        g=frames("guest");p=frames("peer")
        for rows in (g,p):rows[4:4]=rows[2:4]
        self.assertEqual(self.inspect(g,p,observed)["queries"],3)
        with self.assertRaises(AssertionError):self.inspect(g,None,observed)

    def test_socket_source_question_type_id_answer_and_error_substitution_refuse(self):
        changes=[lambda p:p.update(errors=["failure"]),lambda p:p["records"][0].update(source=[m.ROUTER_IP,7002,0,0]),
                 lambda p:p["records"][0].update(port=42011),lambda p:p["records"][0].update(kind=28),
                 lambda p:p["records"][0].update(answer_hex=p["records"][0]["answer_hex"][:-2]+"00")]
        for change in changes:
            value=peer();change(value)
            with self.assertRaises((AssertionError,ValueError)):m.peer_result(json.dumps(value).encode())
        value=peer();q=bytearray.fromhex(value["records"][0]["query_hex"]);q[0]^=1;value["records"][0]["query_hex"]=q.hex()
        with self.assertRaises(AssertionError):m.peer_result(json.dumps(value).encode())

    def test_capture_bounds_and_nonmonotone_time_refuse(self):
        g=capture(frames("guest"));p=capture(frames("peer"))
        with self.assertRaises(AssertionError):m.inspect(g[:-1],p,peer())
        changed=bytearray(g);struct.pack_into("<I",changed,24,2)
        with self.assertRaises(AssertionError):m.inspect(bytes(changed),p,peer())
        with self.assertRaises(AssertionError):m.inspect(capture(frames("guest")*50),p,peer())

    def test_literal_mld_valid_and_bad_checksum_unexplained(self):
        result=self.inspect(g=[mld(),*frames("guest")]);self.assertEqual(result["guest_census"][0]["kind"],"linux-mldv2")
        bad=bytearray(mld());bad[-1]^=1
        with self.assertRaises(AssertionError):self.inspect(g=[bytes(bad),*frames("guest")])

    def test_exact_native_output_includes_controls_and_restoration(self):
        self.assertEqual(m.native_output(serial(),3)["census_before"][:4],[2,13,2,1])
        for old,new in (("framed-denied=3","framed-denied=2"),("queue=4","queue=3"),("label=after processes=2 handles=13","label=after processes=2 handles=12"),("sockets=0","sockets=1")):
            with self.assertRaises(AssertionError):m.native_output(serial(output().replace(old,new)),3)

    def test_raw_status_spawn_terminal_digest_and_offsets_are_strict(self):
        for old,new in ((b"offset=0000000000000000",b"offset=0000000000000001"),(b"USER EXIT pid=3 status=0",b"USER EXIT pid=3 status=1"),(b"frames=0",b"frames=1"),(b"END bytes=",b"END bytes=9")):
            with self.assertRaises(AssertionError):m.native_output(serial().replace(old,new),3)
        with self.assertRaises(AssertionError):m.native_output(serial(),7)

    def test_build_source_identity_empty_input_and_nested_elf_are_required(self):
        r,b=build_fixture();m.build_binding(r,b)
        for key in ("platform","kernel"):
            bad=copy.deepcopy(r);bad[key]["revision"]="0"*40
            with self.assertRaises(AssertionError):m.build_binding(bad,b)
        bad=copy.deepcopy(r);bad["external"]["input"].update(m.digest(b"data"))
        with self.assertRaises(AssertionError):m.build_binding(bad,b)
        bad=dict(b);bad["child"]+=b"different"
        with self.assertRaises(AssertionError):m.build_binding(r,bad)

    def test_actual_iso_extents_not_only_substring_are_required(self):
        _,b=build_fixture();k=b["kernel"];boot=b"exact boot\n";image=iso(k,boot);m.iso_binding(image,k,boot)
        for where in (21*2048,23*2048):
            changed=bytearray(image);changed[where]^=1;changed.extend(k)
            with self.assertRaises(AssertionError):m.iso_binding(bytes(changed),k,boot)

    def test_semantic_cleanup_capture_and_build_content_mutation_refuse_seal(self):
        for name in ("LOCAL-CLEANUP.json","PEER-RESULT.json","PEER-READY.json","LAUNCH.json","LINUX-TOPOLOGY-BEFORE.json","LINUX-TOPOLOGY-AFTER.json","guest-link.pcap","peer-link.pcap","BUILD-RECEIPT.json"):
            with tempfile.TemporaryDirectory(prefix="absd-route6-artifact-") as directory:
                work=Path(directory);path=work/name;data=b"evaluated bytes";path.write_bytes(data)
                value={"evaluated_artifacts":{name:m.identity(path,data)},"evaluated_build_inputs":{},"proof_inputs":{}}
                path.write_bytes(b"changed content")
                with self.assertRaises(AssertionError):m.seal_artifacts(work,value)

    def test_terminal_fact_shared_mapping_is_checked(self):
        with tempfile.TemporaryDirectory(prefix="absd-route6-artifact-") as directory:
            work=Path(directory);mapping={};value={"evaluated_artifacts":mapping,"evaluated_build_inputs":{},"proof_inputs":{}}
            path=work/"LOCAL-CLEANUP.json";data=m.write(path,{"disposition":"PASS"});mapping[path.name]=m.identity(path,data)
            self.assertIn(path.name,m.seal_artifacts(work,value));path.write_text('{"disposition":"FAIL"}\n')
            with self.assertRaises(AssertionError):m.seal_artifacts(work,value)

    def reasons(self,count=2,logs=2,change=None):
        raw=capture([mld()]*count+frames("guest"));census=m.inspect(raw,capture(frames("peer")),peer())["guest_census"]
        s=serial().replace(b"rx_refused=0",b"rx_refused="+str(count).encode());s=b"NIC RX FILTERED dst=33:33:00:00:00:16\n"*logs+s
        a={"schema":"absd-ipv6-ready-capture-sidecar/1","policy":m.original.POLICY,"capture":m.digest(raw),"serial":m.digest(s),"previous_absent":None,
           "observation":{"serial_bytes":len(s),"serial_sha256":m.digest(s)["sha256"],"capture_before_serial_read":m.digest(raw),"capture_after_serial_read":m.digest(raw)}}
        fields=dict(m.native_output(serial(),3)["NIC_counters"]);fields["rx_refused"]=str(count)
        if change:change(a,fields,census)
        return m.reason_accounting(raw,s,json.dumps(a).encode(),a,fields,census)

    def test_first_four_reason_profile_and_cardinality_are_exact(self):
        self.assertEqual(self.reasons()["disposition"],"PASS")
        self.assertEqual(self.reasons(5,5)["disposition"],"FAIL")
        self.assertEqual(self.reasons(2,1)["disposition"],"FAIL")

    def test_missed_tx_error_and_sidecar_substitution_refuse(self):
        for key in ("rx_missed","tx_refused","tx_errors"):
            self.assertEqual(self.reasons(change=lambda a,f,c:f.update({key:"1"}))["disposition"],"FAIL")
        self.assertEqual(self.reasons(change=lambda a,f,c:a["observation"].update(serial_sha256="0"*64))["disposition"],"FAIL")

    def test_namespace_replacement_unknown_creation_and_absence_cleanup(self):
        owned={"device":4,"inode":7};replacement={"device":4,"inode":8}
        command=Mock(side_effect=["owned\n","", "", ""])
        with patch.object(m,"namespace_identity",side_effect=[owned,owned]):
            self.assertTrue(m.retire_namespace("owned",owned,command))
        self.assertIn((["ip","netns","del","owned"],),[call.args for call in command.call_args_list])
        for expected, observed in ((None,[owned]),(owned,[replacement]),(owned,[owned,replacement])):
            command=Mock(side_effect=["owned\n", ""])
            with patch.object(m,"namespace_identity",side_effect=observed):
                with self.assertRaises(AssertionError):m.retire_namespace("owned",expected,command)
            self.assertNotIn((["ip","netns","del","owned"],),[call.args for call in command.call_args_list])
        command=Mock(return_value="")
        self.assertTrue(m.retire_namespace("owned",None,command))
        self.assertEqual(command.call_count,1)

    def test_exited_leader_still_terminates_owned_process_group(self):
        process=Mock(pid=12345);process.poll.return_value=0
        with patch.object(m,"group_live",side_effect=[True,False,False,False]),patch.object(m.os,"killpg") as kill:
            result=m.stop_owned(process)
        kill.assert_called_once_with(12345,m.signal.SIGTERM);self.assertTrue(result["group_absent"])


if __name__ == "__main__":
    unittest.main()
