#!/usr/bin/env python3
"""Deterministic artifact controls. Execute only on the admitted resource VM."""
import copy
import importlib.util
import ipaddress
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("feedback_matrix",Path(__file__).with_name("native-ipv6-feedback-matrix.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
GUEST = ipaddress.IPv6Address("fd00:ab5d::15").packed
HOST = ipaddress.IPv6Address("fd00:ab5d::2").packed


def wire_sum(data):
    total = 0
    for at in range(0,len(data),2):
        total += (data[at]<<8) + (data[at+1] if at+1<len(data) else 0)
        total = (total & 65535) + (total>>16)
    return total ^ 65535


def frame(payload,protocol,outgoing,destination=None,mac=None,hop=64):
    src,dst = (GUEST,HOST) if outgoing else (HOST,GUEST)
    dst = dst if destination is None else destination
    srcmac,dstmac = (m.GUEST_MAC,m.HOST_MAC) if outgoing else (m.HOST_MAC,m.GUEST_MAC)
    dstmac = dstmac if mac is None else mac
    payload = bytearray(payload)
    at = 6 if protocol==17 else 2
    payload[at:at+2] = bytes(2)
    value = wire_sum(src+dst+struct.pack("!I3xB",len(payload),protocol)+payload)
    payload[at:at+2] = (value or 65535).to_bytes(2,"big")
    return dstmac+srcmac+b"\x86\xdd"+b"\x60\0\0\0"+struct.pack("!HBB",len(payload),protocol,hop)+src+dst+payload


def request(identifier=0x1234,port=42019,hop=64):
    question = struct.pack("!HHHHHH",identifier,0x0100,1,0,0,0)+b"\x06closed\x07example\0"+struct.pack("!HH",1,1)
    udp = struct.pack("!HHHH",7002,port,8+len(question),0)+question
    return frame(udp,17,True,hop=hop)


def error(quote=None):
    quote = request()[14:] if quote is None else quote
    return frame(b"\x01\x04"+bytes(6)+quote,58,False)


def packets():
    solicited = bytes.fromhex("ff0200000000000000000001ff000002")
    ns = frame(b"\x87\0"+bytes(6)+HOST+b"\x01\x01"+m.GUEST_MAC,58,True,solicited,b"\x33\x33\xff\0\0\x02",255)
    na = frame(b"\x88\0"+bytes(2)+b"\x60\0\0\0"+HOST+b"\x02\x01"+m.HOST_MAC,58,False,hop=255)
    return [ns,na,request(),error()]


def capture(frames):
    raw = struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65536,1)
    for index,packet in enumerate(frames):
        raw += struct.pack("<IIII",1,index,len(packet),len(packet))+packet
    return raw


def serial(output=None):
    if output is None:
        output = (b"IPV6 FEEDBACK SERVICE READY static-on-link scope=1 udp=7002 peer-port=42019\n"
                  b"IPV6 FEEDBACK AUTHORITY PASS wrong-peer-and-selector-refused no-nic\n"
                  b"IPV6 DNS FEEDBACK PASS type=1 code=4 detail=0 auth=none lookup_boot_ms=807\n"
                  b"IPV6 FEEDBACK SERVICE PASS child=exited sockets=0\n")
    return (b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 \nDURABLE WORKLOAD OK\nABSD BOOT OK\n"
            b"NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n"
            b"EXTERNAL OUTPUT CHUNK offset=0000000000000000 data="+output.hex().encode()+b"\n"
            b"NIC STATS rx_frames=3 tx_frames=3 rx_refused=0 rx_missed=0 tx_refused=0 tx_errors=0\n")


class ArtifactControls(unittest.TestCase):
    def inspect(self,frames,raw=None):
        with tempfile.TemporaryDirectory(prefix="absd-v6-feedback-artifact-") as temporary:
            path = Path(temporary)/"capture.pcap"
            path.write_bytes(capture(frames) if raw is None else raw)
            return m.inspect(path,m.native_output(serial(),3))

    def refused(self,frames):
        with self.assertRaises(AssertionError):
            self.inspect(frames)

    def test_complete_query_quote_and_native_observation_positive(self):
        result = self.inspect(packets())
        self.assertEqual(len(result["requests"]),1)
        self.assertEqual(result["errors"][0]["compatible_request_indices"],[3])
        self.assertEqual(result["requests"][0]["query_hex"],"12340100000100000000000006636c6f736564076578616d706c650000010001")

    def test_identical_retries_have_explicit_multiple_compatible_indices(self):
        baseline = packets()
        result = self.inspect(baseline[:3]+[request(),error(),error()])
        self.assertEqual(len(result["requests"]),2)
        self.assertEqual(result["errors"][0]["compatible_request_indices"],[3,4])
        self.assertEqual(len(result["errors"]),2)

    def test_distinct_ipv6_headers_do_not_share_error_capacity(self):
        first, second = request(), request(hop=63)
        self.assertEqual(first[62:],second[62:])
        self.assertNotEqual(first[14:],second[14:])
        prefix = packets()[:2]
        # Changing hop limit leaves UDP checksum valid; error() independently
        # recomputes the outer ICMP checksum over each complete original quote.
        result = self.inspect(prefix+[first,second,error(first[14:]),error(second[14:])])
        self.assertEqual([e["compatible_request_indices"] for e in result["errors"]],[[3],[4]])
        self.refused(prefix+[first,second,error(first[14:]),error(first[14:])])

    def test_identical_copy_multiplicity_is_bounded_by_prior_copies(self):
        prefix, query = packets()[:2], request()
        result = self.inspect(prefix+[query,error(),query,error()])
        self.assertEqual([e["compatible_request_indices"] for e in result["errors"]],[[3],[3,5]])
        self.refused(prefix+[query,error(),query,error(),error()])
        # A later identical request cannot justify an earlier duplicate error.
        self.refused(prefix+[query,error(),error(),query])

    def test_accepted_linux_mld_is_retained_in_whole_capture_census(self):
        source=importlib.util.spec_from_file_location("accepted_mld_fixture",Path(__file__).with_name("native-ipv6-accounting-test.py"))
        fixtures=importlib.util.module_from_spec(source)
        source.loader.exec_module(fixtures)
        result=self.inspect([fixtures.packet()]+packets())
        self.assertEqual(result["census"][0]["kind"],"linux-mldv2")
        self.assertEqual(result["errors"][0]["compatible_request_indices"],[4])

    def test_more_than_four_queries_or_more_errors_than_queries_refuse(self):
        self.refused(packets()[:2]+[request()]*5+[error()])
        self.refused(packets()+[error()])

    def test_complete_but_different_query_quote_with_valid_checksums_refuses(self):
        changed = packets()
        changed[-1] = error(request(identifier=0x1235)[14:])
        self.refused(changed)

    def test_quote_tuple_source_body_and_length_substitutions_refuse(self):
        for quote in (request(port=42020)[14:],request()[14:-1],request()[14:]+bytes(1)):
            with self.subTest(quote=quote.hex()):
                changed = packets();changed[-1]=error(quote);self.refused(changed)
        changed = packets();broken=bytearray(changed[-1]);broken[6]^=1;changed[-1]=bytes(broken);self.refused(changed)

    def test_original_wire_checksum_corruption_is_refused(self):
        for index in (0,1,2,3):
            with self.subTest(index=index):
                changed=packets();broken=bytearray(changed[index]);broken[-1]^=1;changed[index]=bytes(broken);self.refused(changed)

    def test_missing_nd_or_error_before_request_refuses(self):
        self.refused(packets()[1:])
        baseline=packets();self.refused(baseline[:2]+list(reversed(baseline[2:])))
        self.refused(packets()[:3])

    def test_incoming_udp_is_not_a_closed_port_observation(self):
        changed=packets()
        changed.append(frame(struct.pack("!HHHH",42019,7002,20,0)+bytes(12),17,False))
        self.refused(changed)

    def test_capture_truncation_and_extra_protocol_refuse(self):
        with self.assertRaises(AssertionError):
            self.inspect([],raw=capture(packets())[:-1])
        self.refused(packets()+[bytes(60)])

    def test_native_authority_elapsed_exit_and_output_structure_are_strict(self):
        output=m.native_output(serial(),3)["output"].encode()
        for old,new in ((b"auth=none",b"auth=trusted"),(b"lookup_boot_ms=807",b"lookup_boot_ms=3000"),
                        (b"no-nic",b"has-nic"),(b"sockets=0",b"sockets=1"),(b"child=exited",b"child=unknown")):
            with self.subTest(old=old),self.assertRaises(AssertionError):m.native_output(serial(output.replace(old,new)),3)
        with self.assertRaises(AssertionError):m.native_output(serial(),1)
        with self.assertRaises(AssertionError):m.native_output(serial().replace(b"offset=0000000000000000",b"offset=0000000000000001"),3)

    def test_build_source_and_archive_and_output_substitutions_refuse(self):
        child=b"\x7fELFchild";parent=b"\x7fELFparent"+child;kernel=b"\x7fELFkernel"+parent
        receipt={"schema":"absd-native-ipv6-feedback-build/1",
                 "platform":{"revision":m.PRODUCT,"tree":m.PRODUCT_TREE,"clean":True,"archive":{"bytes":1,"sha256":m.PRODUCT_ARCHIVE}},
                 "kernel":{"revision":m.KERNEL,"tree":m.KERNEL_TREE,"clean":True,"archive":{"bytes":1,"sha256":m.KERNEL_ARCHIVE}},
                 "commands":[["sh","scripts/build-native-ipv6-feedback.sh"],["make","EXTERNAL_USER_ELF=parent.elf"]],
                 "logs":[m.buffer_digest(b"build log")],"toolchain_receipt":m.buffer_digest(b"toolchain"),
                 "outputs":{name:m.buffer_digest(data) for name,data in (("child",child),("parent",parent),("kernel",kernel))}}
        m.build_binding(receipt,child,parent,kernel)
        for key in ("platform","kernel"):
            changed=copy.deepcopy(receipt);changed[key]["revision"]="0"*40
            with self.assertRaises(AssertionError):m.build_binding(changed,child,parent,kernel)
            changed=copy.deepcopy(receipt);changed[key]["archive"]["sha256"]="0"*64
            with self.assertRaises(AssertionError):m.build_binding(changed,child,parent,kernel)
        with self.assertRaises(AssertionError):m.build_binding(receipt,child+b"changed",parent,kernel)


if __name__=="__main__":
    unittest.main()
