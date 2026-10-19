#!/usr/bin/env python3
"""Synthetic artifact controls and captured wire vectors, no native execution."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('refusal', Path(__file__).with_name('native-dhcp-refusal-matrix.py'))
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
DISCOVER = bytes.fromhex((m.ROOT / 'fixtures/native-dhcp/captured-discover.hex').read_text())
REQUEST = bytes.fromhex((m.ROOT / 'fixtures/native-dhcp/captured-request.hex').read_text())


def frame(payload, outgoing=True):
    source = bytes(4) if outgoing else m.peer.HOST;destination = bytes([255]) * 4
    udp = bytearray(struct.pack('!HHHH', 68 if outgoing else 67, 67 if outgoing else 68, 8 + len(payload), 0) + payload)
    udp[6:8] = (m.positive.boot.checksum(source + destination + bytes([0, 17]) + len(udp).to_bytes(2, 'big') + udp) or 65535).to_bytes(2, 'big')
    ip = bytearray(bytes.fromhex('450000000000000040110000') + source + destination)
    ip[2:4] = (20 + len(udp)).to_bytes(2, 'big');ip[10:12] = m.positive.boot.checksum(ip).to_bytes(2, 'big')
    return bytes([255]) * 6 + (m.GUEST_MAC if outgoing else m.HOST_MAC) + b'\x08\0' + ip + udp


def fixture(profile, retry_xid=False, stale_wire=False, queued_stale=False, premature_wire_request=False):
    packets = [('tx', frame(DISCOVER))]
    if profile != 'no-offer':packets.append(('rx', frame(m.peer.offer(DISCOVER, profile), False)))
    if profile == 'valid-offer-noack':
        packets += [('tx', frame(REQUEST)), ('tx', frame(REQUEST))]
        if premature_wire_request:packets[1],packets[2]=packets[2],packets[1]
    else:
        retry = bytearray(DISCOVER)
        if retry_xid:retry[4:8] = bytes([1, 2, 3, 4])
        packets.append(('tx', frame(retry)))
        if stale_wire:
            packets[1], packets[2] = packets[2], packets[1]
            packets.append(('tx', frame(retry)))
        elif queued_stale:packets.append(('tx', frame(retry)))
    capture = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    events = [];output = ['DHCP REFUSAL BEGIN acquire_ms=20000 child=not-started'];rx = tx = 0
    for i, (direction, packet) in enumerate(packets):
        capture += struct.pack('<IIII', 0, i, len(packet), len(packet)) + packet
        payload = packet[42:]
        event = {'event': 'receive' if direction == 'tx' else 'send', 'monotonic_ns': i * 1_100_000_000, 'bytes': len(payload), 'hex': payload.hex(), 'sha256': m.identity(payload)['sha256']}
        if direction == 'tx':event['source'] = ['0.0.0.0', 68];tx += 1
        else:
            event['destination'] = ['255.255.255.255', 68];rx += 1
            event.update(first_discover_monotonic_ns=0,offer_not_before_monotonic_ns=1_100_000_000,send_ready_monotonic_ns=1_100_000_000,trigger_discover_sha256=m.identity(DISCOVER)['sha256'])
        events.append(event)
        output.append(f'DHCP REFUSAL FRAME direction={direction} start_ms={100+i*10} end_ms={101+i*10} status=0 length={len(packet)} hex={packet.hex()}')
    if queued_stale or premature_wire_request:
        output[2], output[3] = output[3], output[2]
        output[2] = output[2].replace('start_ms=120 end_ms=121', 'start_ms=110 end_ms=111')
        output[3] = output[3].replace('start_ms=110 end_ms=111', 'start_ms=120 end_ms=121')
    output += [f'DHCP REFUSAL LINK DROP now_ms=20100 rx={rx} tx={tx} overflow=false',
               f'DHCP REFUSAL END error=Timeout start_ms=100 deadline_ms=20100 ended_ms=20100 dropped=true overflow=false rx={rx} tx={tx} child=not-started']
    peer = {'profile': profile, 'errors': [], 'socket_closed': True, 'events': events, 'sent': rx}
    return capture, '\n'.join(output) + '\n', peer


def evaluate(profile='malformed-offer', mutate=None, **options):
    capture, output, peer = fixture(profile, **options)
    if mutate:capture, output, peer = mutate(capture, output, copy.deepcopy(peer))
    with tempfile.TemporaryDirectory() as directory:
        p = Path(directory) / 'fixture.pcap';p.write_bytes(capture)
        return m.inspect(p, output, profile, peer)


class RefusalControls(unittest.TestCase):
    def test_actual_peer_receive_event_preserves_distinct_dhcp_kind(self):
        result={'events':[]}
        row=m.peer.record_event(result,'receive',DISCOVER,source=['0.0.0.0',68],kind=1)
        self.assertEqual(row['event'],'receive');self.assertEqual(row['kind'],1)
        self.assertEqual(row['bytes'],len(DISCOVER));self.assertEqual(row['hex'],DISCOVER.hex())
        self.assertEqual(row['sha256'],m.identity(DISCOVER)['sha256'])
        self.assertEqual(result['events'],[row]);self.assertIsInstance(row['monotonic_ns'],int)

    def test_actual_peer_event_budget_refuses_without_appending(self):
        result={'events':[]}
        for _ in range(64):m.peer.record_event(result,'receive',DISCOVER,kind=1)
        with self.assertRaisesRegex(ValueError,'peer observation bound'):
            m.peer.record_event(result,'receive',DISCOVER,kind=1)
        self.assertEqual(len(result['events']),64)

    def test_all_four_profiles_have_exact_native_capture_correspondence(self):
        for profile in m.peer.PROFILES:
            result = evaluate(profile)
            self.assertEqual(result['native_link_rx'], int(profile != 'no-offer'))
            self.assertEqual(result['deadline_ms'], 20100)
            self.assertEqual(3 in result['tx_kinds'], profile == 'valid-offer-noack')

    def test_offer_calibration_is_literal_captured_dnsmasq_payload(self):
        expected = bytes.fromhex((m.ROOT / 'fixtures/native-dhcp/captured-offer.hex').read_text())
        self.assertEqual(m.peer.offer(DISCOVER, 'valid-offer-noack'), expected)

    def test_malformed_offer_changes_only_one_duplicate_option(self):
        valid = m.peer.offer(DISCOVER, 'valid-offer-noack');_, end = m.peer.options(valid)
        changed = m.peer.offer(DISCOVER, 'malformed-offer')
        self.assertEqual(changed, valid[:end] + bytes([53, 1, 2]) + valid[end:])
        with self.assertRaises(ValueError):m.peer.options(changed)
        self.assertEqual(len(m.peer.options(changed, allow_duplicate=True)[0][53]), 2)

    def test_unauthorized_offer_changes_only_server_identifier(self):
        valid = m.peer.offer(DISCOVER, 'valid-offer-noack');fields, _ = m.peer.options(valid)
        at = fields[54][0][0];expected = bytearray(valid);expected[at:at + 4] = bytes([192, 0, 2, 2])
        self.assertEqual(m.peer.offer(DISCOVER, 'unauthorized-offer'), expected)
        self.assertEqual(m.peer.options(expected)[0][54][0][1], bytes([192, 0, 2, 2]))

    def test_runtime_substitution_binds_transaction_and_guest(self):
        changed = bytearray(DISCOVER);changed[4:8] = bytes([1, 2, 3, 4])
        reply = m.peer.offer(changed, 'valid-offer-noack');self.assertEqual(reply[4:8], bytes([1, 2, 3, 4]))
        for at in (0, 1, 2, 3, 12, 24, 28):
            changed = bytearray(DISCOVER);changed[at] ^= 1
            with self.assertRaises(ValueError):m.peer.offer(changed, 'valid-offer-noack')

    def test_silent_profile_cannot_generate_offer(self):
        with self.assertRaises(ValueError):m.peer.offer(DISCOVER, 'no-offer')

    def test_cookie_option_tail_and_truncation_refused(self):
        for data in (DISCOVER[:239], DISCOVER[:-2], DISCOVER[:236] + bytes(4) + DISCOVER[240:]):
            with self.assertRaises(ValueError):m.peer.options(data)
        changed = bytearray(DISCOVER);_, end = m.peer.options(changed);changed.extend(b'\x01')
        with self.assertRaises(ValueError):m.peer.options(changed)

    def test_one_discover_cannot_pass_timeout_liveness(self):
        with self.assertRaises(ValueError):evaluate('no-offer', lambda c,o,p:(c[:24+16+len(frame(DISCOVER))],o,p))

    def test_every_captured_offer_byte_mutation_fails(self):
        capture, _, _ = fixture('malformed-offer');start = 24 + 16 + len(frame(DISCOVER)) + 16
        for at in range(len(frame(m.peer.offer(DISCOVER, 'malformed-offer'), False))):
            changed = bytearray(capture);changed[start+at] ^= 1
            with self.assertRaises((ValueError, AssertionError)):
                evaluate(mutate=lambda c,o,p:(bytes(changed),o,p))

    def test_native_received_bytes_must_match_not_only_packet_capture(self):
        with self.assertRaises(ValueError):evaluate(mutate=lambda c,o,p:(c,o.replace('direction=rx', 'direction=tx'),p))
        with self.assertRaises(ValueError):evaluate(mutate=lambda c,o,p:(c,'\n'.join(line for line in o.splitlines() if 'direction=rx' not in line)+'\n',p))

    def test_native_accepted_send_or_length_substitution_refused(self):
        size=len(frame(DISCOVER))
        for before, after in [('status=0', 'status=-5'), (f'length={size}', f'length={size-1}')]:
            self.assertIn(before,fixture('malformed-offer')[1])
            with self.assertRaises(ValueError):evaluate(mutate=lambda c,o,p:(c,o.replace(before,after,1),p))

    def test_native_frame_order_and_clock_rewind_refused(self):
        def swapped(c,o,p):
            lines=o.splitlines();lines[1],lines[2]=lines[2],lines[1];return c,'\n'.join(lines)+'\n',p
        with self.assertRaises(ValueError):evaluate(mutate=swapped)
        with self.assertRaises(ValueError):evaluate(mutate=lambda c,o,p:(c,o.replace('start_ms=110', 'start_ms=99'),p))

    def test_original_deadline_and_observed_termination_are_distinct(self):
        for before, after in [('deadline_ms=20100','deadline_ms=21100'), ('ended_ms=20100','ended_ms=20099'), ('now_ms=20100','now_ms=20101')]:
            with self.assertRaises(ValueError):evaluate(mutate=lambda c,o,p:(c,o.replace(before,after),p))

    def test_missing_drop_overflow_or_not_dropped_refused(self):
        for before, after in [('dropped=true','dropped=false'), ('overflow=false','overflow=true'), ('LINK DROP','OTHER DROP')]:
            with self.assertRaises(ValueError):evaluate(mutate=lambda c,o,p:(c,o.replace(before,after),p))

    def test_peer_full_datagram_hash_hex_and_count_are_bound(self):
        for key, value in [('sha256','0'*64), ('hex','00'), ('bytes',1), ('source',['192.0.2.1',68])]:
            def change(c,o,p):p['events'][0][key]=value;return c,o,p
            with self.assertRaises(ValueError):evaluate(mutate=change)

    def test_peer_error_wrong_profile_socket_or_sent_count_refused(self):
        for key,value in [('errors',['x']),('profile','no-offer'),('socket_closed',False),('sent',0)]:
            def change(c,o,p):p[key]=value;return c,o,p
            with self.assertRaises(ValueError):evaluate(mutate=change)

    def test_peer_event_order_and_unexplained_events_refused(self):
        def change(c,o,p):p['events'][1]['monotonic_ns']=-1;return c,o,p
        with self.assertRaises(ValueError):evaluate(mutate=change)
        def change(c,o,p):p['events'][1]['event']='other';return c,o,p
        with self.assertRaises(ValueError):evaluate(mutate=change)

    def test_capture_size_header_checksum_and_extra_frame_refused(self):
        original=fixture('malformed-offer')[0]
        changed=bytearray(original);changed[24+16+14+10]^=1
        for data in (original[:-1],original+b'x',bytes(24)+original[24:],bytes(changed)):
            with self.assertRaises((ValueError,AssertionError)):evaluate(mutate=lambda c,o,p:(data,o,p))

    def test_unexpected_activation_and_unknown_stdout_refused(self):
        for suffix in ('DHCP ACTIVE address=192.0.2.100\n','DHCP DNS ANSWER other\n','unexplained\n'):
            with self.assertRaises(ValueError):evaluate(mutate=lambda c,o,p:(c,o+suffix,p))
        with self.assertRaises(ValueError):evaluate(mutate=lambda c,o,p:(c,'',p))

    def test_strict_stdout_chunk_offset_refuses_gap_and_overlap(self):
        line=b'EXTERNAL OUTPUT CHUNK offset=0000000000000000 data=6162\n'
        self.assertEqual(m.stdout(line),'ab')
        for data in (line+line,line.replace(b'0000000000000000',b'0000000000000001')):
            with self.assertRaises(ValueError):m.stdout(data)

    def test_offer_setup_guard_has_fixed_origin_and_original_absolute_deadline(self):
        clock=SimpleNamespace(ns=0)
        def pause(seconds):clock.ns+=round(seconds*1_000_000_000)
        kwargs={'now':lambda:clock.ns/1_000_000_000,'now_ns':lambda:clock.ns,'pause':pause}
        result=m.peer.defer_offer(0,2.0,lambda:False,**kwargs)
        self.assertEqual(result['offer_not_before_monotonic_ns'],1_100_000_000)
        self.assertEqual(result['send_ready_monotonic_ns'],1_100_000_000)
        clock.ns=0
        with self.assertRaises(ValueError):m.peer.defer_offer(0,0.5,lambda:False,**kwargs)
        self.assertLessEqual(clock.ns,500_000_000)
        clock.ns=0
        with self.assertRaises(ValueError):m.peer.defer_offer(0,2.0,lambda:True,**kwargs)
        self.assertEqual(clock.ns,0)

    def test_missing_or_short_offer_setup_interval_cannot_pass_refusal(self):
        for key,value in [('first_discover_monotonic_ns',1),('offer_not_before_monotonic_ns',1_000_000_000),('send_ready_monotonic_ns',1_099_999_999)]:
            def changed(c,o,p):p['events'][1][key]=value;return c,o,p
            with self.assertRaises(ValueError):evaluate(mutate=changed)

    def test_offer_setup_clock_crossing_never_passes_negative_sleep(self):
        samples=iter((1_099_999_999,1_100_000_001,1_100_000_002,1_100_000_003));pauses=[]
        def pause(seconds):
            self.assertGreaterEqual(seconds,0.0);pauses.append(seconds)
        result=m.peer.defer_offer(0,2.0,lambda:False,now=lambda:1.1,now_ns=lambda:next(samples),pause=pause)
        self.assertEqual(pauses,[0.0])
        self.assertGreaterEqual(result['send_ready_monotonic_ns'],1_100_000_000)

    def test_every_captured_selecting_request_follows_its_offer(self):
        with self.assertRaisesRegex(ValueError,'captured Request before delivered Offer'):
            evaluate('valid-offer-noack',premature_wire_request=True)

    def test_extra_malformed_terminal_or_overflow_records_refused(self):
        for extra in ('DHCP REFUSAL LINK DROP now_ms=20100 rx=1 tx=2 overflow=true',
                      'DHCP REFUSAL END error=Link',
                      'DHCP REFUSAL BEGIN acquire_ms=1 child=not-started'):
            with self.assertRaises(ValueError):evaluate(mutate=lambda c,o,p:(c,o+extra+'\n',p))
        def inserted(c,o,p):
            lines=o.splitlines();lines.insert(-2,'DHCP REFUSAL LINK DROP now_ms=20100 rx=1 tx=2 overflow=true');return c,'\n'.join(lines)+'\n',p
        with self.assertRaises(ValueError):evaluate(mutate=inserted)

    def test_namespace_unknown_creation_retains_residual_and_refuses_cleanup(self):
        calls=[]
        def checked(argv):calls.append(argv);return SimpleNamespace(stdout='owned-ns\n')
        result=m.reconcile_namespace('owned-ns',True,False,None,checked)
        self.assertEqual(result['disposition'],'FAIL')
        self.assertFalse(any('del' in argv for argv in calls))
        self.assertIsNone(result['observed_absent'])

    def test_namespace_success_requires_exact_identity_no_process_and_absence(self):
        state=SimpleNamespace(present=True);calls=[]
        def checked(argv):
            calls.append(argv)
            if 'list' in argv:return SimpleNamespace(stdout='owned-ns\n' if state.present else '')
            if 'pids' in argv:return SimpleNamespace(stdout='')
            if 'del' in argv:state.present=False;return SimpleNamespace(stdout='')
            raise AssertionError(argv)
        result=m.reconcile_namespace('owned-ns',True,True,[1,2],checked,lambda p:SimpleNamespace(st_dev=1,st_ino=2))
        self.assertEqual(result['disposition'],'PASS');self.assertTrue(result['observed_absent'])
        self.assertTrue(any('del' in argv for argv in calls))
        state.present=False
        self.assertEqual(m.reconcile_namespace('owned-ns',True,False,None,checked)['disposition'],'PASS')

    def test_namespace_replacement_live_process_or_unknown_list_never_deletes(self):
        for failure in ('identity','pids','list'):
            calls=[]
            def checked(argv):
                calls.append(argv)
                if 'list' in argv:
                    if failure=='list':raise TimeoutError('list unavailable')
                    return SimpleNamespace(stdout='owned-ns\n')
                if 'pids' in argv:return SimpleNamespace(stdout='123\n')
                raise AssertionError(argv)
            result=m.reconcile_namespace('owned-ns',True,True,[1,2],checked,lambda p:SimpleNamespace(st_dev=1,st_ino=3 if failure=='identity' else 2))
            self.assertEqual(result['disposition'],'FAIL');self.assertFalse(any('del' in argv for argv in calls))

    def test_namespace_replaced_during_process_check_is_retained(self):
        state=SimpleNamespace(inode=2);calls=[]
        def checked(argv):
            calls.append(argv)
            if 'list' in argv:return SimpleNamespace(stdout='owned-ns\n')
            if 'pids' in argv:state.inode=3;return SimpleNamespace(stdout='')
            raise AssertionError(argv)
        result=m.reconcile_namespace('owned-ns',True,True,[1,2],checked,lambda p:SimpleNamespace(st_dev=1,st_ino=state.inode))
        self.assertEqual(result['disposition'],'FAIL')
        self.assertFalse(any('del' in argv for argv in calls))

    def test_changed_discover_xid_is_normal_for_silent_and_refused_profiles(self):
        for profile in ('no-offer','malformed-offer','unauthorized-offer'):
            result=evaluate(profile,retry_xid=True)
            self.assertEqual(result['discover_xids'][-1],'01020304')
            self.assertNotEqual(result['discover_xids'][0],result['discover_xids'][-1])
            self.assertNotIn(3,result['tx_kinds'])

    def test_stale_offer_at_wire_or_native_dequeue_does_not_establish_refusal(self):
        for profile in ('malformed-offer','unauthorized-offer'):
            with self.assertRaisesRegex(ValueError,'stale Offer at captured'):evaluate(profile,retry_xid=True,stale_wire=True)
            with self.assertRaisesRegex(ValueError,'stale Offer at native'):evaluate(profile,retry_xid=True,queued_stale=True)

    def test_malformed_or_unanchored_stdout_chunks_refused(self):
        valid=b'EXTERNAL OUTPUT CHUNK offset=0000000000000000 data=6162\n'
        for extra in (b'EXTERNAL OUTPUT CHUNK offset=0000000000000002 data=zz\n',
                      b'EXTERNAL OUTPUT CHUNK offset=2 data=61\n',
                      b'prefix EXTERNAL OUTPUT CHUNK offset=0000000000000002 data=61\n'):
            with self.assertRaises(ValueError):m.stdout(valid+extra)

    def test_duplicate_json_keys_refused(self):
        with self.assertRaises(ValueError):m.decode(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError):m.decode(b'[]')

    def test_build_receipt_requires_both_expected_sources_and_exact_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);a=root/'archive';a.write_bytes(b'archive');log=root/'log';log.write_bytes(b'actual log');tool=root/'tool';tool.write_bytes(b'tool')
            def desc(p):return {'path':str(p),**m.identity(p.read_bytes())}
            receipt={'schema':'absd-native-dhcp-refusal-build/1','sources':{name:{'revision':'1'*40,'tree':'2'*40,'clean':True,'archive':desc(a)} for name in ('platform','kernel')},'outputs':{'probe':m.identity(b'probe'),'kernel':m.identity(b'kernel')},'commands':[{'argv':['sh','scripts/build-native-dhcp-refusal.sh'], 'log':desc(log)},{'argv':['make','external-build','EXTERNAL_USER_ELF='+str(root/'probe')], 'log':desc(log)}],'toolchain':desc(tool)}
            p=root/'receipt';p.write_text(json.dumps(receipt));args=SimpleNamespace(elf=root/'probe',build_receipt=p,build_receipt_sha256=m.identity(p.read_bytes())['sha256'],platform_revision='1'*40,platform_tree='2'*40,kernel_revision='1'*40,kernel_tree='2'*40)
            m.build_binding(args,b'kernel',b'probe')
            for name in ('platform','kernel'):
                for field,value in [('revision','3'*40),('tree','4'*40),('clean',False)]:
                    changed=copy.deepcopy(receipt);changed['sources'][name][field]=value;p.write_text(json.dumps(changed));args.build_receipt_sha256=m.identity(p.read_bytes())['sha256']
                    with self.assertRaises(ValueError):m.build_binding(args,b'kernel',b'probe')
            p.write_text(json.dumps(receipt));args.build_receipt_sha256=m.identity(p.read_bytes())['sha256']
            with self.assertRaises(ValueError):m.build_binding(args,b'kernel',b'changedprobe')
            a.write_bytes(b'changed')
            with self.assertRaises(ValueError):m.build_binding(args,b'kernel',b'probe')


if __name__ == '__main__':unittest.main()
