#!/usr/bin/env python3
"""Meaningful artifact substitutions; source-only until the admitted VM runs them."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location("ipv6_server_matrix",Path(__file__).with_name("native-ipv6-tcp-server-matrix.py"))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def ip_frame(outgoing,next_header,payload,destination=None,mac=None,hop=64):
    src,dst=(m.GUEST,m.HOST) if outgoing else (m.HOST,m.GUEST)
    smac,dmac=(m.GUEST_MAC,m.HOST_MAC) if outgoing else (m.HOST_MAC,m.GUEST_MAC)
    dst=dst if destination is None else destination;dmac=dmac if mac is None else mac
    ip=struct.pack("!IHBB16s16s",0x60000000,len(payload),next_header,hop,src,dst)
    return dmac+smac+b"\x86\xdd"+ip+payload


def nd(outgoing,kind):
    src,dst=(m.GUEST,m.HOST) if outgoing else (m.HOST,m.GUEST)
    smac=m.GUEST_MAC if outgoing else m.HOST_MAC
    target=src if kind==136 else dst
    if kind==135:dst=m.accounting.solicited(target);dmac=b"\x33\x33\xff"+target[-3:]
    else:dmac=m.HOST_MAC if outgoing else m.GUEST_MAC
    body=bytearray(bytes([kind,0,0,0])+struct.pack("!I",0x60000000 if kind==136 else 0)+target+bytes([2 if kind==136 else 1,1])+smac)
    body[2:4]=struct.pack("!H",m.boot.checksum(src+dst+struct.pack("!I3xB",len(body),58)+body))
    return ip_frame(outgoing,58,body,dst,dmac,255)


def tcp(outgoing,seq,ack,flags,body=b"",port=42030,mss=1440):
    src,dst=(m.GUEST,m.HOST) if outgoing else (m.HOST,m.GUEST)
    ports=(7005,port) if outgoing else (port,7005)
    options=struct.pack("!BBH",2,4,mss) if flags&2 else b""
    segment=bytearray(struct.pack("!HHIIBBHHH",*ports,seq,ack,(5+len(options)//4)<<4,flags,8192,0,0)+options+body)
    segment[16:18]=struct.pack("!H",m.boot.checksum(src+dst+struct.pack("!I3xB",len(segment),6)+segment))
    return ip_frame(outgoing,6,segment)


def baseline():
    rows=[nd(False,135),nd(True,136),tcp(False,8000,0,2,port=42031),tcp(False,1000,0,2),tcp(True,4000,1001,18),tcp(False,1001,4001,16)]
    for at in range(0,3072,1024):rows.append(tcp(False,1001+at,4001,24,m.DATA[at:at+1024]))
    rows += [tcp(False,4073,4001,17),tcp(True,4001,4074,16)]
    for at in range(0,3072,511):rows.append(tcp(True,4001+at,4074,24,m.DATA[at:at+511]))
    rows += [tcp(True,7073,4074,17),tcp(False,4074,7074,16)]
    return rows


def pcap(rows,times=None):
    data=b"\xd4\xc3\xb2\xa1"+struct.pack("<HHIIII",2,4,0,0,65535,1)
    times=times if times is not None else [1_000_000,1_000_100,1_000_200]+[2_250_300+i*100 for i in range(len(rows)-3)]
    assert len(rows)==len(times)
    for timestamp,frame in zip(times,rows):
        sec,usec=divmod(timestamp,1_000_000);data+=struct.pack("<IIII",sec,usec,len(frame),len(frame))+frame
    return data


def output():
    return ("IPV6 TCP SERVER CENSUS v=1 label=before processes=2 handles=7 pipes=2 cells=0 frames=100\n"
            "IPV6 TCP SERVER GRANT v=1 local=[fd00:ab5d::1]:7005 peer=[fd00:ab5d::2]:42030 scope=1 mtu=1500 accept_ms=5000 lifetime_ms=10000 owner_start_ms=100 owner_until_ms=10100 sockets=0\n"
            "IPV6 TCP SERVER LISTEN READY v=1 sockets=1\n"
            "IPV6 TCP SERVER ECHO PASS v=1 bytes=3072 denied=1 nic=0\n"
            "IPV6 TCP SERVER REAP v=1 kind=1 status=0 request_eof=1 result_eof=1 pipe_read_bytes=4096 pipe_written_bytes=4096\n"
            "IPV6 TCP SERVER CENSUS v=1 label=after processes=2 handles=7 pipes=2 cells=0 frames=107\n"
            "IPV6 TCP SERVER DONE v=1 child=exited sockets=0 authority=retired objects_restored=1\n")


def serial(text=None):
    body=(output() if text is None else text).encode();value=0x811c9dc5
    for b in body:value=((value^b)*0x01000193)&0xffffffff
    return (b"\nABSD BOOT OK\nNETWORK LINK OK x\nEXTERNAL OUTPUT CHUNK offset=0000000000000000 data="+body.hex().encode()+b"\n"+
            f"EXTERNAL OUTPUT END bytes={len(body)} digest={value:08x}\n".encode()+
            b"NIC STATS rx_frames=20 tx_frames=20 rx_refused=0 rx_missed=0 tx_refused=0 tx_errors=0\nDURABLE status=0 frames=0 processes=0 cells=0 pipes=0 x\nDURABLE WORKLOAD OK\n")


class ArtifactControls(unittest.TestCase):
    def test_kernel_readiness_uses_recorded_raw_observation_not_worker_output(self):
            ready={"producer_observed_running":True,"serial_ready_line":m.NIC_READY.decode()}
            with patch.object(m.boot,"stdout_of") as worker:
                self.assertFalse(m.readiness_observed(m.NIC_READY,Path("fixture"),SimpleNamespace(observation=None)))
                self.assertTrue(m.readiness_observed(m.NIC_READY,Path("fixture"),SimpleNamespace(observation=ready)))
                for observation in ({**ready,"producer_observed_running":False},{**ready,"serial_ready_line":"other\n"}):
                    with self.assertRaises(AssertionError):m.readiness_observed(m.NIC_READY,Path("fixture"),SimpleNamespace(observation=observation))
                worker.assert_not_called()
            with patch.object(m.boot,"stdout_of",return_value=m.READY):
                self.assertTrue(m.readiness_observed(m.READY,Path("fixture"),SimpleNamespace(observation=None)))
            with patch.object(m.boot,"stdout_of",return_value=b""):
                self.assertFalse(m.readiness_observed(m.READY,Path("fixture"),SimpleNamespace(observation=ready)))

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
                with patch.object(m,"checked",side_effect=checked):
                    if automatic:
                        with self.assertRaises(AssertionError):m.prepare_peer_link("fixture","tap0")
                    else:self.assertEqual(m.prepare_peer_link("fixture","tap0")[0]["mtu"],1500)
                self.assertTrue(any("net.ipv6.conf.default.addr_gen_mode=1" in argv for argv in calls))
                self.assertFalse(any("addr" in argv and "add" in argv for argv in calls))

    def test_actual_peer_activation_requires_running_ready_and_exact_address_transition(self):
            ready={"producer_observed_running":True,"serial_ready_line":m.NIC_READY.decode()}
            for observation in (None,{**ready,"producer_observed_running":False},{**ready,"serial_ready_line":"other\n"}):
                with patch.object(m,"checked") as checked:
                    with self.assertRaises(AssertionError):m.activate_peer("fixture","tap0",SimpleNamespace(observation=observation))
                    checked.assert_not_called()
            peer={"family":"inet6","local":"fd00:ab5d::2","prefixlen":64}
            for before,after,accepted in (([],[peer],True),([peer],[peer],False),([],[{**peer,"local":"fe80::1"}],False),([],[peer,peer],False)):
                calls=[];reads=iter((before,after))
                def checked(argv):
                    calls.append(argv)
                    return SimpleNamespace(stdout=json.dumps([{"addr_info":next(reads)}]) if "show" in argv else "")
                with patch.object(m,"checked",side_effect=checked):
                    if accepted:
                        result=m.activate_peer("fixture","tap0",SimpleNamespace(observation=ready))
                        self.assertEqual(result["addresses_before"][0]["addr_info"],[])
                        self.assertEqual(result["addresses_after"][0]["addr_info"],[peer])
                    else:
                        with self.assertRaises(AssertionError):m.activate_peer("fixture","tap0",SimpleNamespace(observation=ready))
                additions=[a for a in calls if "addr" in a and "add" in a]
                self.assertEqual(len(additions),0 if before else 1)
                if additions:self.assertIn("fd00:ab5d::2/64",additions[0])

    def refuse(self,rows):
        with self.assertRaises(AssertionError):m.inspect_capture(pcap(rows))

    def test_complete_ipv6_flow_has_full_census_nd_and_3072_both_directions(self):
        r=m.inspect_capture(pcap(baseline()));self.assertEqual(r["application_bytes_each"],3072);self.assertEqual(r["wrong_port_syns"],[2]);self.assertEqual(r["frames"],len(baseline()));self.assertGreater(r["segments"]["guest"],2)

    def test_readiness_ns_and_na_are_both_required_before_wrong_syn(self):
        rows=baseline();self.refuse(rows[1:]);self.refuse(rows[:1]+rows[2:]);rows=baseline();rows[1],rows[2]=rows[2],rows[1];self.refuse(rows)

    def test_nd_checksum_target_hop_option_and_mac_are_exact(self):
        for index in [0,1]:
            for at in [0,21,57,62,78,80]:
                rows=baseline();b=bytearray(rows[index]);b[at]^=1;rows[index]=bytes(b);self.refuse(rows)

    def test_no_response_of_any_kind_to_wrong_transport_tuple(self):
        for flags,body in [(18,b""),(16,b""),(20,b""),(24,b"no")]:
            rows=baseline();rows.insert(3,tcp(True,9000,8001,flags,body,port=42031));self.refuse(rows)

    def test_wrong_syn_must_be_single_attempt_before_authorized_connection(self):
        rows=baseline();self.refuse(rows[:2]+rows[3:]);rows=baseline();rows.insert(6,tcp(False,8000,0,2,port=42031));self.refuse(rows);rows=baseline();rows.insert(3,tcp(False,8001,0,2,port=42031));self.refuse(rows)

    def test_negative_interval_strictly_exceeds_one_second(self):
        times=[1_000_000+i*100 for i in range(len(baseline()))]
        with self.assertRaises(AssertionError):m.inspect_capture(pcap(baseline(),times))

    def test_tcp_tuple_mss_hop_checksum_and_truncation_are_exact(self):
        for at in [0,21,22,38,54,56,-1]:
            rows=baseline();b=bytearray(rows[6]);b[at]^=1;rows[6]=bytes(b);self.refuse(rows)
        rows=baseline();rows[4]=tcp(True,4000,1001,18,mss=1220);self.refuse(rows)
        with self.assertRaises(AssertionError):m.inspect_capture(pcap(baseline())[:-1])

    def test_valid_checksum_alternate_body_is_refused(self):
        rows=baseline();rows[6]=tcp(False,1001,4001,24,b"x"*1024);self.refuse(rows)

    def test_uncaptured_ack_sequence_gap_and_early_data_are_refused(self):
        rows=baseline();rows[5]=tcp(False,1001,7074,16);self.refuse(rows);rows=baseline();del rows[6];self.refuse(rows)
        rows=baseline();rows[4],rows[6]=rows[6],rows[4];self.refuse(rows)

    def test_both_fin_and_causal_ack_and_client_half_close_are_required(self):
        rows=baseline();self.refuse(rows[:-1]);rows=baseline();del rows[9];self.refuse(rows)
        rows=baseline();rows.insert(9,rows[-1]);self.refuse(rows)

    def test_third_source_udp_and_unknown_ethertype_are_unexplained(self):
        rows=baseline();rows.append(ip_frame(False,17,b"\0"*8));self.refuse(rows)
        rows=baseline();rows.append(b"\0"*74);self.refuse(rows)

    def test_native_actual_output_digest_reap_and_object_equality(self):
        r=m.native_output(serial(),3);self.assertEqual(r["objects_before"][:4],r["objects_after"][:4]);self.assertTrue(r["frames_observed_only"])
        for old,new in [("request_eof=1","request_eof=0"),("result_eof=1","result_eof=0"),("kind=1 status=0","kind=3 status=0"),("label=after processes=2","label=after processes=3"),("owner_until_ms=10100","owner_until_ms=10101"),("mtu=1500","mtu=1280"),("authority=retired","authority=live")]:
            with self.assertRaises(AssertionError):m.native_output(serial(output().replace(old,new)),3)

    def test_native_missing_duplicate_or_digest_altered_output_is_refused(self):
        for data in [serial().replace(b"digest=",b"digest=f"),serial().replace(b"offset=0000000000000000",b"offset=0000000000000001"),serial(output()+"extra\n"),serial().replace(b"rx_missed=0",b"rx_missed=1")]:
            with self.assertRaises(AssertionError):m.native_output(data,3)
        with self.assertRaises(AssertionError):m.native_output(serial(),0)

    def test_literal_wire_vectors_are_independent_exact_shapes(self):
        lines=dict(line.split("=",1) for line in (m.ROOT/"fixtures/native-ipv6-tcp-server/wire-v3.txt").read_text().splitlines());listen=bytes.fromhex(lines["listen"])
        self.assertEqual(listen.hex(),"001c03200006fd00ab5d00000000000000000000000200000001a42e0000");self.assertEqual(bytes.fromhex(lines["denied"])[4],2)
        for h in lines.values():self.assertEqual(int.from_bytes(bytes.fromhex(h)[:2],"big"),len(bytes.fromhex(h))-2)

    def test_metadata_requires_both_actual_target_bins_and_canonical_std(self):
        metadata={"version":1,"packages":[{"name":"absd-std-probe","targets":[{"name":name,"kind":["bin"],"required-features":["native-ipv6-tcp-server-probe"],"src_path":"/received/src/bin/"+name+".rs"} for name in ("ipv6_tcp_server_echo","ipv6_tcp_server_service_probe")]}]};data=json.dumps(metadata).encode()
        receipt={"cargo_metadata":m.digest(data),"staged_std":{"sha256":"c35493ccdf6cb87a81767902413ad4487caa1bff401d5ccecb1cce9e7a18760c","files":2251,"bytes":45920288},"target":"x86_64-unknown-absd"}
        m.metadata_binding(receipt,data)
        for key in ("sha256","files","bytes"):
            bad=copy.deepcopy(receipt);bad["staged_std"][key]="wrong"
            with self.assertRaises(AssertionError):m.metadata_binding(bad,data)
        metadata["packages"][0]["targets"].pop();changed=json.dumps(metadata).encode();receipt["cargo_metadata"]=m.digest(changed)
        with self.assertRaises(AssertionError):m.metadata_binding(receipt,changed)

    def test_checksum_valid_wrong_nd_target_and_third_tcp_port_are_refused(self):
        rows=baseline();bad=bytearray(rows[0]);bad[77]^=1;bad[56:58]=b"\0\0";pseudo=bytes(bad[22:54])+struct.pack("!I3xB",len(bad)-54,58);bad[56:58]=struct.pack("!H",m.boot.checksum(pseudo+bad[54:]));rows[0]=bytes(bad);self.refuse(rows)
        rows=baseline();rows[6]=tcp(False,1001,4001,24,m.DATA[:1024],port=42032);self.refuse(rows)

    def test_peer_receipts_require_real_long_negative_and_complete_eof(self):
            wrong={"disposition":"PASS","local":["fd00:ab5d::2",42031],"peer":["fd00:ab5d::1",7005],"result":"connect-timeout","sent_bytes":0,"connect_attempts":1,"timeout_ns":m.WRONG_TIMEOUT_NS,"started_monotonic_ns":1_000_000_000,"ended_monotonic_ns":2_250_000_000,"post_negative_required_ns":m.POST_NEGATIVE_NS,"post_negative_started_monotonic_ns":2_250_000_000,"post_negative_ended_monotonic_ns":3_350_000_000}
            peer={"disposition":"PASS","local":["fd00:ab5d::2",42030,0,0],"peer":["fd00:ab5d::1",7005,0,0],"bytes":3072,"sha256":m.digest(m.DATA)["sha256"],"write_half_closed":True,"read_EOF":True,"connect_started_monotonic_ns":3_400_000_000,"connected_monotonic_ns":3_500_000_000,"completed_monotonic_ns":3_600_000_000}
            capture=m.inspect_capture(pcap(baseline()));m.peer_results(wrong,peer,capture)
            for key,value in [("ended_monotonic_ns",2_000_000_000),("sent_bytes",1),("connect_attempts",2),("result","connected")]:
                bad=copy.deepcopy(wrong);bad[key]=value
                with self.assertRaises(AssertionError):m.peer_results(bad,peer,capture)
            for key,value in [("read_EOF",False),("write_half_closed",False),("bytes",3071),("connect_started_monotonic_ns",2_000_000_000),("sha256","0"*64)]:
                bad=copy.deepcopy(peer);bad[key]=value
                with self.assertRaises(AssertionError):m.peer_results(wrong,bad,capture)

    def test_build_requires_exact_product_kernel_wrapper_and_embedded_elf_edges(self):
        child=b"\x7fELFchild";parent=b"\x7fELFparent"+child;kernel=b"\x7fELFkernel"+parent
        source=lambda revision,tree,archive,size:{"revision":revision,"tree":tree,"clean":True,"archive":{"sha256":archive,"bytes":size}}
        receipt={"schema":"absd-native-ipv6-tcp-server-build/1","profile":m.PROFILE,"platform":source(m.PRODUCT,m.PRODUCT_TREE,m.PRODUCT_ARCHIVE,m.PRODUCT_BYTES),"kernel":source(m.KERNEL,m.KERNEL_TREE,m.KERNEL_ARCHIVE,m.KERNEL_BYTES),"commands":[["sh","scripts/build-native-ipv6-tcp-server.sh"],["python3","scripts/served_kernel.py","external-build","EXTERNAL_USER_ELF=/exact/parent.elf"]],"logs":[{"bytes":1,"sha256":"a"*64}],"toolchain_receipt":{"bytes":1,"sha256":"b"*64},"served_kernel_policy":"frame-admission-v0","served_wrapper_sha256":m.SERVED_WRAPPER,"outputs":{name:m.digest(data) for name,data in [("child",child),("parent",parent),("kernel",kernel)]}}
        m.build_binding(receipt,child,parent,kernel)
        for name in ("platform","kernel"):
            for field,value in [("revision","0"*40),("tree","0"*40),("clean",False)]:
                bad=copy.deepcopy(receipt);bad[name][field]=value
                with self.assertRaises(AssertionError):m.build_binding(bad,child,parent,kernel)
        bad=copy.deepcopy(receipt);bad["served_wrapper_sha256"]="0"*64
        with self.assertRaises(AssertionError):m.build_binding(bad,child,parent,kernel)
        bad=copy.deepcopy(receipt);bad["outputs"]["parent"]=m.digest(parent+child);bad["outputs"]["kernel"]=m.digest(kernel+child)
        with self.assertRaises(AssertionError):m.build_binding(bad,child,parent+child,kernel+child)


    def test_ready_prefix_counter_binding_refuses_ambiguous_or_nonmatching_samples(self):
        from types import SimpleNamespace
        capture=pcap(baseline());raw=serial();native=m.native_output(raw,3)
        snap={"bytes":24,"sha256":m.digest(capture[:24])["sha256"],"partial_record":False}
        sample={"serial_bytes":0,"serial_sha256":m.digest(b"")["sha256"],"capture_before_serial_read":snap,"capture_after_serial_read":snap,"producer_observed_running":True}
        annotation={"observation":copy.deepcopy(sample),"previous_absent":copy.deepcopy(sample),"capture":m.digest(capture),"serial":m.digest(raw),"marker_after_record":0}
        m.counter_binding(raw,capture,SimpleNamespace(annotation=annotation),native)
        for field in ("producer_observed_running","partial_record","serial_sha256"):
            bad=copy.deepcopy(annotation)
            if field=="producer_observed_running":bad["observation"][field]=False
            elif field=="partial_record":bad["observation"]["capture_after_serial_read"][field]=True
            else:bad["observation"][field]="0"*64
            with self.assertRaises(AssertionError):m.counter_binding(raw,capture,SimpleNamespace(annotation=bad),native)
        bad=copy.deepcopy(native);bad["NIC_counters"]["rx_refused"]="1"
        with self.assertRaises(AssertionError):m.counter_binding(raw,capture,SimpleNamespace(annotation=annotation),bad)



    def test_actual_post_negative_wait_handles_early_wake_and_refuses_rewind_or_stall(self):
            with patch.object(m.time,"monotonic_ns",side_effect=[100,500_000_100,1_100_000_100]),patch.object(m.time,"sleep") as pause:
                r=m.post_negative_wait()
            self.assertEqual(r,{"post_negative_required_ns":1_100_000_000,"post_negative_started_monotonic_ns":100,"post_negative_ended_monotonic_ns":1_100_000_100})
            self.assertEqual([c.args[0] for c in pause.call_args_list],[1.1,0.6])
            for readings in ([100,99],[100,2_000_000_101]):
                with patch.object(m.time,"monotonic_ns",side_effect=readings),patch.object(m.time,"sleep"),self.assertRaises(AssertionError):m.post_negative_wait()

    def test_actual_wrong_client_closes_before_separate_wait_and_never_sends(self):
            events=[]
            class Socket:
                def __enter__(self):events.append("open");return self
                def __exit__(self,*args):events.append("close")
                def bind(self,address):self_address=address;events.append(("bind",self_address))
                def settimeout(self,seconds):events.append(("timeout",seconds))
                def connect(self,address):events.append(("connect",address));raise TimeoutError
            def quiet():
                self.assertEqual(events[-1],"close");events.append("quiet")
                return {"post_negative_required_ns":m.POST_NEGATIVE_NS,"post_negative_started_monotonic_ns":2_250_000_000,"post_negative_ended_monotonic_ns":3_350_000_000}
            with patch.object(m.socket,"socket",return_value=Socket()),patch.object(m.time,"monotonic_ns",side_effect=[1_000_000_000,2_250_000_000]),patch.object(m,"post_negative_wait",side_effect=quiet),patch.object(m,"write") as write:
                m.wrong_port_client(Path("unwritten.json"))
            self.assertEqual([e for e in events if isinstance(e,tuple) and e[0]=="connect"],[("connect",("fd00:ab5d::1",7005))])
            self.assertEqual(write.call_args.args[1]["post_negative_ended_monotonic_ns"],3_350_000_000)
            self.assertEqual(write.call_args.args[1]["sent_bytes"],0)

    def test_quiet_receipt_cannot_replace_strict_actual_wire_interval(self):
            wrong={"disposition":"PASS","local":["fd00:ab5d::2",42031],"peer":["fd00:ab5d::1",7005],"result":"connect-timeout","sent_bytes":0,"connect_attempts":1,"timeout_ns":m.WRONG_TIMEOUT_NS,"started_monotonic_ns":1_000_000_000,"ended_monotonic_ns":2_250_000_000,"post_negative_required_ns":m.POST_NEGATIVE_NS,"post_negative_started_monotonic_ns":2_250_000_000,"post_negative_ended_monotonic_ns":3_350_000_000}
            peer={"disposition":"PASS","local":["fd00:ab5d::2",42030,0,0],"peer":["fd00:ab5d::1",7005,0,0],"bytes":3072,"sha256":m.digest(m.DATA)["sha256"],"write_half_closed":True,"read_EOF":True,"connect_started_monotonic_ns":3_400_000_000,"connected_monotonic_ns":3_500_000_000,"completed_monotonic_ns":3_600_000_000}
            capture=m.inspect_capture(pcap(baseline()));m.peer_results(wrong,peer,capture)
            for key,value in [("post_negative_required_ns",1_000_000_000),("post_negative_started_monotonic_ns",2_249_999_999),("post_negative_ended_monotonic_ns",3_349_999_999),("post_negative_ended_monotonic_ns",4_250_000_001)]:
                bad=copy.deepcopy(wrong);bad[key]=value
                with self.assertRaises(AssertionError):m.peer_results(bad,peer,capture)
            bad=copy.deepcopy(peer);bad["connect_started_monotonic_ns"]=3_349_999_999
            with self.assertRaises(AssertionError):m.peer_results(wrong,bad,capture)
            # Actual ceb54 first-SYN gap, despite a successful long socket call.
            times=[1_000_000,1_000_100,1_000_200]+[1_807_657+i*100 for i in range(len(baseline())-3)]
            with self.assertRaises(AssertionError):m.inspect_capture(pcap(baseline(),times))


def boundary_text():
    rows=["IPV6 TCP SERVER NEG BEGIN v=1 whole_start_ms=0 whole_until_ms=20000",
          "IPV6 TCP SERVER NEG CENSUS v=1 label=before processes=2 handles=7 pipes=2 cells=0 frames=100"]
    for index,name in enumerate(("local-port","peer-port","offlink","self","unspecified","multicast","scope-zero","scope-other","accept-low","accept-high","lifetime-short","lifetime-high")):
        rows.append(f"IPV6 TCP SERVER NEG GRANT v=1 case={name} code={2 if index<8 else 1} sockets=0 tx=0")
    rows += ["IPV6 TCP SERVER NEG SLOTS v=1 reserved=8 duplicate=3 ninth=4 sockets=0 tx=0",
             "IPV6 TCP SERVER NEG SLOTS RETIRED v=1 stale=8 fresh=8 sockets=0 tx=0",
             "IPV6 TCP SERVER NEG BOOTSTRAP v=1 bytes=23 hex=03fd00ab5d00000000000000000000000200000001a42e"]
    # The published literal fixture is also consumed by the actual native child;
    # the oracle has its independently written exact expected bytes.
    for line in (m.ROOT/"fixtures/native-ipv6-tcp-server/boundary-v3.txt").read_text().splitlines():
        name,pair=line.split("=");request,reply=pair.split(":")
        rows.append(f"IPV6 TCP SERVER NEG API v=1 case={name} request={request} reply={reply} sockets=0 tx=0")
    rows += ["IPV6 TCP SERVER NEG LISTEN v=1 request=001c03200006fd00ab5d00000000000000000000000200000001a42e0000 reply=001d03200006fd00ab5d00000000000000000000000200000001a42e000100 sockets=1 tx=0",
             "IPV6 TCP SERVER NEG INTERRUPT v=1 child_handle=17 constructed_ms=10 grant_until_ms=10010 partial_poll_ms=40 observed_ms=41 prefix=00 prefix_bytes=1 input_bytes=301 output_bytes=301 kill_ms=42 kill_return=0 reaped_ms=43 wait_kind=3 wait_status=0 eof_ms=44 retired_ms=44 channel_live=0 sockets=0 tx=0 fallback_fence=0",
             "IPV6 TCP SERVER NEG CHILD v=1 cases=9 listen=1 nic=0",
             "IPV6 TCP SERVER NEG CLOSED v=1 process_reaped=1 protocol_handles=2 result_handles=1 result_eof=1",
             "IPV6 TCP SERVER NEG CENSUS v=1 label=after processes=2 handles=7 pipes=2 cells=0 frames=107",
             "IPV6 TCP SERVER NEG COMPLETE v=1 grants=12 api=9 slots=8 interrupted=1 objects_restored=1 sockets=0 tx=0"]
    return "\n".join(rows)+"\n"+output()


def boundary_native(text=None):
    return m.native_output(serial(boundary_text() if text is None else text),3)


class BoundaryControls(unittest.TestCase):
    def refuse(self,text):
        with self.assertRaises(AssertionError):m.boundary_observation(boundary_native(text))

    def test_actual_boundary_ledger_and_original_positive_are_both_required(self):
        result=m.boundary_observation(boundary_native());self.assertEqual(result["input_bytes"],301);self.assertEqual(result["output_bytes"],301);self.assertEqual(result["bootstrap_bytes"],23);self.assertEqual(result["interruption"]["wait_kind"],3)
        self.refuse(output());self.refuse(boundary_text().replace("IPV6 TCP SERVER ECHO PASS v=1 bytes=3072 denied=1 nic=0\n",""))

    def test_constructor_codes_and_distinct_ninth_slot_are_exact(self):
        text=boundary_text()
        for old,new in [("case=local-port code=2","case=local-port code=1"),("case=accept-low code=1","case=accept-low code=2"),("ninth=4","ninth=3"),("duplicate=3","duplicate=4"),("stale=8 fresh=8","stale=0 fresh=8")]:self.refuse(text.replace(old,new))

    def test_reserved_request_echo_cannot_substitute_for_invalid_reply(self):
        text=boundary_text();request="001c03207f06fd00ab5d00000000000000000000000200000001a42e0000";reply="001c03200106fd00ab5d00000000000000000000000200000001a42e0000"
        old=f"case=reserved request={request} reply={reply}";self.assertIn(old,text);self.refuse(text.replace(old,f"case=reserved request={request} reply={request}"))

    def test_actual_literal_tuple_scope_and_missing_body_reply_are_exact(self):
        text=boundary_text()
        for line in text.splitlines():
            if line.startswith("IPV6 TCP SERVER NEG API "):
                self.refuse(text.replace(line,line.replace("reply=001c03","reply=001c02")))
        self.refuse(text.replace("case=write-declared-without-body","case=complete-oversize-body"))
        self.refuse(text.replace("case=scope request=001c03200006fd00ab5d00000000000000000000000200000002", "case=scope request=001c03200006fd00ab5d00000000000000000000000200000001"))

    def test_actual_prefix_and_ledger_counts_cannot_be_replaced(self):
        text=boundary_text()
        for old,new in [("prefix=00","prefix=01"),("prefix_bytes=1","prefix_bytes=0"),("input_bytes=301","input_bytes=300"),("output_bytes=301","output_bytes=300"),("bytes=23 hex=03","bytes=22 hex=03")]:self.refuse(text.replace(old,new))

    def test_exact_live_handle_kill_kind_and_true_eof_are_required(self):
        text=boundary_text()
        for old,new in [("child_handle=17","child_handle=0"),("kill_return=0","kill_return=1"),("wait_kind=3","wait_kind=1"),("wait_status=0","wait_status=1"),("result_eof=1","result_eof=0"),("channel_live=0","channel_live=1"),("fallback_fence=0","fallback_fence=1")]:self.refuse(text.replace(old,new))

    def test_interruption_order_cannot_substitute_deadline_retirement(self):
        text=boundary_text()
        for old,new in [("kill_ms=42","kill_ms=40"),("reaped_ms=43","reaped_ms=41"),("eof_ms=44","eof_ms=42"),("retired_ms=44","retired_ms=290"),("retired_ms=44","retired_ms=10010"),("observed_ms=41","observed_ms=43")]:self.refuse(text.replace(old,new))

    def test_original_negative_and_whole_budgets_cannot_be_renewed(self):
        text=boundary_text()
        for old,new in [("grant_until_ms=10010","grant_until_ms=10011"),("whole_until_ms=20000","whole_until_ms=20001"),("owner_start_ms=100 owner_until_ms=10100","owner_start_ms=20 owner_until_ms=10020"),("owner_start_ms=100 owner_until_ms=10100","owner_start_ms=11000 owner_until_ms=21000")]:self.refuse(text.replace(old,new))

    def test_closed_owned_census_equalities_do_not_claim_frame_restoration(self):
        text=boundary_text();self.assertEqual(m.boundary_observation(boundary_native())["frame_delta_observed"],7)
        self.assertEqual(m.boundary_observation(boundary_native(text.replace("frames=107","frames=109")))["frame_delta_observed"],9)
        for old,new in [("label=after processes=2","label=after processes=3"),("label=after processes=2 handles=7","label=after processes=2 handles=8"),("protocol_handles=2","protocol_handles=1"),("result_handles=1","result_handles=0")]:self.refuse(text.replace(old,new))

    def test_phase_effects_and_complete_listen_reply_cannot_be_skipped(self):
        text=boundary_text()
        self.refuse(text.replace("case=reserved request=", "case=unknown request="))
        self.refuse(text.replace("sockets=0 tx=0","sockets=0 tx=1",1))
        line=next(line for line in text.splitlines() if line.startswith("IPV6 TCP SERVER NEG LISTEN "));self.refuse(text.replace(line,line.replace("000100 sockets=1","000101 sockets=1")));self.refuse(text.replace(line,line.replace("sockets=1","sockets=0")))

    def test_missing_duplicate_and_reordered_boundary_records_are_refused(self):
        text=boundary_text();lines=text.splitlines();self.refuse("\n".join(lines[:2]+lines[3:])+"\n");self.refuse(text+lines[1]+"\n");lines[14],lines[15]=lines[15],lines[14];self.refuse("\n".join(lines)+"\n")



if __name__=="__main__":unittest.main()
