#!/usr/bin/env python3
"""Complete bounded Ethernet/ARP/IPv4/UDP and selected ICMP fixture census.

The filter-dump PCAP has no Ethernet FCS. Padding is bounded and retained in
frame hashes; it is not covered by the IP/UDP checksums. This is a two-endpoint
fixture profile, not a general capture decoder or protocol-conformance claim.
"""
import hashlib
import ipaddress
import re
import struct


class Refusal(ValueError):
    pass


def require(value, message):
    if not value:
        raise Refusal(message)


def checksum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def mac(text):
    require(isinstance(text, str) and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', text),
            'canonical explicit MAC required')
    value = bytes.fromhex(text.replace(':', ''))
    require(value != b'\0' * 6 and not value[0] & 1, 'unicast nonzero MAC required')
    return value


def observe(raw, case, guest_mac, peer_mac):
    selected = {'Q01': ('echo', 7800), 'Q12': ('truncated-header', 7811), 'Q13': ('invalid-tag', 7812), 'Q02': ('partial-io', 7801), 'Q03': ('initial-loss', 7802), 'Q04': ('stream-loss', 7803), 'Q05': ('duplicate-reorder', 7804), 'Q06': ('flow-pause', 7805), 'Q08': ('wrong-root', 7807),
                'Q07': ('silent', 7806), 'Q14': ('long-retry', 7813), 'Q15': ('stream-limit', 7814), 'Q16': ('unknown-cid', 7815), 'Q17': ('denied-destination', 7816), 'Q18': ('unauthorized-source', 7817), 'Q09': ('wrong-name', 7808), 'Q10': ('expired-certificate', 7809),
                'Q11': ('wrong-alpn', 7810), 'Q19': ('queue-exhausted', 7818), 'Q20': ('unknown-send', 7819),
                'Q21': ('silent', 7820), 'Q22': ('interrupt-stream', 7821),
                'Q23': ('owner-expiry', 7822), 'Q24': ('link-failure', 7823), 'Q29': ('missing-output', 7828),
                'Q30': ('missing-time', 7829), 'Q31': ('absent-rdrand', 7830), 'Q25': ('icmp-576', 7824),
                'Q26': ('icmp-1227', 7825), 'Q27': ('icmp-1200', 7826), 'Q28': ('icmp-zero', 7827)}
    require(case['id'] in selected
            and (case.get('peer_mode'), case['local_port']) == selected[case['id']],
            'only explicit canonical Q01/Q02/Q03/Q04/Q05/Q06/Q07/Q08/Q09/Q10/Q11/Q12/Q14/Q15/Q16/Q18/Q19/Q20/Q21/Q22/Q23/Q24/Q29/Q30/Q31 case-mode-port profiles are reviewed')
    local_port = case['local_port']
    icmp_profile = case['id'] in ('Q25', 'Q26', 'Q27', 'Q28')
    if icmp_profile:
        require(type(case.get('icmp_mtu')) is int
                and case.get('icmp_mtu') == {'Q25':576, 'Q26':1227, 'Q27':1200, 'Q28':0}[case['id']]
                and case.get('expected_outcome') == 'Native'
                and case.get('native_error_codes') == ([14] if case['id'] in ('Q27', 'Q28') else [14,15]),
                'exact ICMP advisory selector differs')
    guest, peer = '10.0.2.15', '10.0.2.2'
    gm, pm = mac(guest_mac), mac(peer_mac)
    require(gm != pm, 'distinct endpoint MACs required')
    identities = {gm: guest, pm: peer}
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 10**6), b'\xa1\xb2\xc3\xd4': ('>', 10**6),
               b'\x4d\x3c\xb2\xa1': ('<', 10**9), b'\xa1\xb2\x3c\x4d': ('>', 10**9)}
    require(24 <= len(raw) <= 2 * 1024**2 and raw[:4] in formats, 'PCAP header/size bound')
    order, resolution = formats[raw[:4]]
    major, minor, zone, accuracy, snaplen, link = struct.unpack(order + 'HHIIII', raw[4:24])
    require((major, minor, zone, accuracy, link) == (2, 4, 0, 0, 1) and snaplen >= 1514,
            'full Ethernet PCAP profile required')
    offset, frames = 24, []
    udp, arp, icmp = [], [], []
    while offset < len(raw):
        require(len(frames) < 1024 and len(raw) - offset >= 16, 'frame count/header bound')
        seconds, fraction, included, original = struct.unpack(order + 'IIII', raw[offset:offset + 16])
        offset += 16
        require(fraction < resolution and included == original and 14 <= included <= 1514
                and included <= snaplen and offset + included <= len(raw), 'complete bounded frame required')
        frame = raw[offset:offset + included]
        offset += included
        destination, source = frame[:6], frame[6:12]
        require(source in identities, 'third-party source MAC')
        other = pm if source == gm else gm
        kind = int.from_bytes(frame[12:14], 'big')
        row = {'ordinal': len(frames) + 1, 'timestamp': seconds + fraction / resolution,
               'bytes': len(frame), 'frame_sha256': hashlib.sha256(frame).hexdigest(),
               'source_mac': source.hex(':'), 'destination_mac': destination.hex(':'),
               'ethertype': kind}
        frames.append(row)
        if kind == 0x0806:
            require(len(frame) >= 42 and len(frame) <= max(60, 42), 'ARP size/padding bound')
            hardware, protocol, hlen, plen, operation = struct.unpack('!HHBBH', frame[14:22])
            sender_mac, sender_ip = frame[22:28], str(ipaddress.IPv4Address(frame[28:32]))
            target_mac, target_ip = frame[32:38], str(ipaddress.IPv4Address(frame[38:42]))
            require((hardware, protocol, hlen, plen) == (1, 0x0800, 6, 4) and operation in (1, 2), 'ARP profile')
            require(sender_mac == source and sender_ip == identities[source]
                    and target_ip == identities[other], 'ARP sender/target identity')
            # RFC 826 Packet Generation permits broadcast THA for an unknown
            # request target. Keep that allowance confined to Ethernet broadcast.
            require((operation == 1 and destination in (b'\xff' * 6, other)
                     and (target_mac in (b'\0' * 6, other)
                          or (destination == b'\xff' * 6 and target_mac == b'\xff' * 6)))
                    or (operation == 2 and destination == other and target_mac == other), 'ARP target MAC')
            arp.append({**row, 'operation': operation, 'source': sender_ip, 'destination': target_ip})
            continue
        require(kind == 0x0800 and destination == other, 'unexpected EtherType or destination MAC')
        ip = frame[14:]
        require(len(ip) >= 20 and ip[0] == 0x45, 'Q01 IPv4 header without options required')
        size = int.from_bytes(ip[2:4], 'big')
        require(28 <= size <= 1500 and size <= len(ip) and len(frame) <= max(60, 14 + size),
                'IPv4 size/padding bound')
        require(checksum(ip[:20]) == 0 and ip[8] > 0, 'IPv4 checksum/TTL')
        require(int.from_bytes(ip[6:8], 'big') & 0xbfff == 0, 'reserved flag or fragmented IPv4')
        src, dst = str(ipaddress.IPv4Address(ip[12:16])), str(ipaddress.IPv4Address(ip[16:20]))
        if ip[9] == 1:
            require(icmp_profile and source == pm and src == peer and dst == guest and size == 56,
                    'ICMP outside its exact incoming advisory profile')
            body = ip[20:size]
            require(len(body) == 36 and body[:2] == b'\x03\x04' and body[4:6] == b'\0\0'
                    and checksum(body) == 0 and int.from_bytes(body[6:8], 'big') == case['icmp_mtu'],
                    'ICMP type, code, unused field, MTU or checksum differs')
            quote = body[8:]
            originals = [packet for packet in udp if packet['source'][0] == guest]
            require(not icmp and originals and quote.hex() == originals[0]['ip_header_udp_hex']
                    and quote[6:8] == b'\x40\x00' and checksum(quote[:20]) == 0,
                    'ICMP must quote the literal first earlier emitted guest frame exactly once')
            icmp.append({**row, 'source':src, 'destination':dst, 'mtu':case['icmp_mtu'],
                         'icmp_hex':body.hex(), 'frame_hex':frame.hex(), 'quote_hex':quote.hex(),
                         'quoted_frame_ordinal':originals[0]['ordinal'],
                         'submitted_frame_sha256':originals[0]['frame_sha256'],
                         'icmp_checksum_valid':True})
            continue
        require(src == identities[source] and dst == identities[other] and ip[9] == 17,
                'unexpected IPv4 tuple or protocol')
        segment = ip[20:size]
        sport, dport, length, check = struct.unpack('!HHHH', segment[:8])
        expected = (local_port, 4443) if source == gm else (4443, local_port)
        # Q18 only: the peer host may also send from another local port; those
        # frames are classified separately as unauthorized, never as peer_udp.
        stray = case['id'] == 'Q18' and source != gm and dport == local_port and sport not in (0, 4443)
        require(((sport, dport) == expected or stray) and length == len(segment) and 8 < length <= 1208,
                'UDP tuple/length/fixed MTU')
        pseudo = ip[12:20] + b'\0\x11' + struct.pack('!H', length)
        require(check != 0 and checksum(pseudo + segment) == 0, 'present valid UDP checksum required')
        data = segment[8:]
        if case['id'] == 'Q20' and source == gm:
            require(len(data) == 1200 and data[0] & 0xf0 == 0xc0
                    and data[1:5] == b'\0\0\0\1', 'Q20 complete QUICv1 Initial required')
        require(source != gm or ip[1] & 3 == 0, 'native packet claims ECN')
        udp.append({**row, 'unauthorized': stray, 'source': [src, sport], 'destination': [dst, dport],
                    'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'ecn': ip[1] & 3,
                    'first_byte': data[0], 'ip_header_udp_hex': ip[:28].hex(),
                    'ip_checksum_valid': True, 'udp_checksum_valid': True,
                    **({'data_hex':data.hex(),
                        'long_header_version':int.from_bytes(data[1:5], 'big') if len(data) >= 5 else None}
                       if case['id'] in ('Q23', 'Q24', 'Q25', 'Q26', 'Q27', 'Q28') else {})})
    sent = [row for row in udp if row['source'][0] == guest]
    received = [row for row in udp if row['source'][0] == peer and not row['unauthorized']]
    unauthorized = [row for row in udp if row['unauthorized']]
    if icmp_profile:
        require(1 <= len(sent) <= 256 and not received and len(icmp) == 1
                and all(row['bytes'] == 1200 and row['first_byte'] & 0xf0 == 0xc0
                        and row['long_header_version'] == 1 for row in sent),
                'ICMP profile requires guest Initials, exactly one incoming ICMP and zero peer UDP')
    elif case['id'] in ('Q17', 'Q29', 'Q30', 'Q31'):
        require(not udp, 'Q17/Q29/Q30/Q31 pre-I/O refusal requires zero UDP in either direction')
    elif case['id'] == 'Q24':
        require(1 <= len(sent) <= 256 and not received
                and all(row['bytes'] == 1200 and row['first_byte'] & 0xf0 == 0xc0
                        and row['long_header_version'] == 1 for row in sent),
                'Q24 requires bounded guest QUICv1 Initials and zero peer UDP')
    elif case['id'] == 'Q23':
        marker = b'\x00ABSD-QUIC-Q23-INITIAL-OBSERVED'
        require(case.get('observation_marker_hex') == marker.hex(), 'canonical Q23 marker differs')
        require(1 <= len(sent) <= 256 and len(received) == 1
                and all(row['bytes'] == 1200 and row['first_byte'] & 0xf0 == 0xc0
                        and row['long_header_version'] == 1 for row in sent),
                'Q23 requires only bounded actual QUICv1 Initials and one marker')
        require(received[0]['data_hex'] == marker.hex()
                and received[0]['bytes'] == len(marker)
                and received[0]['sha256'] == hashlib.sha256(marker).hexdigest()
                and sent[0]['ordinal'] < received[0]['ordinal'],
                'Q23 exact marker must follow the first captured Initial')
    else:
        # Q07/Q21 peers are engine-free and silent: their direction must be empty.
        require(sent and ((not received) if case['id'] in ('Q07', 'Q20', 'Q21') else received) and len(sent) <= 256 and len(received) <= 512
                and sum(row['bytes'] for row in sent) <= 307200, case['id'] + ' packet/byte bound or missing direction')
    if case['id'] == 'Q20':
        require(len(sent) == 1 and not received,
                'Q20 requires exactly one possibly effected Initial and no sink response')
    return {'pcap_sha256': hashlib.sha256(raw).hexdigest(), 'frames': frames, 'arp': arp,
            'guest_udp': sent, 'peer_udp': received, 'icmp': icmp, 'frame_count': len(frames),
            'arp_count': len(arp), 'udp_count': len(udp), 'unexpected_frames': 0,
            'guest_udp_count': len(sent), 'guest_udp_bytes': sum(row['bytes'] for row in sent),
            'unauthorized_guest_udp_count': 0, 'unauthorized_peer_udp': unauthorized, 'all_guest_non_ect': True,
            'limit': ('Only selected Q25/Q26/Q27/Q28 additionally admit one checksum-valid incoming ICMP3/4 with a literal earlier guest IP/UDP-header quote. Native matching is advisory and not full-body identity. '
                      if icmp_profile else '') + 'Every complete captured frame classified as exact-pair ARP or checksum-valid exact-pair IPv4/UDP. No FCS, IP-options, fragments, offload-partial checksums or unrelated traffic accepted. Capture completeness outside the measured QEMU filter lifetime is not established.'}
