#!/usr/bin/env python3
"""Fixed 1280-profile controls; execute only on the serialized Linux VM."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('mtu1280_matrix', 'native-ipv6-mtu1280-matrix.py')
f = load('original_tcp_fixtures', 'native-ipv6-routed-tcp-matrix-test.py')


def frames(link):
    result = f.frames(link)
    for at, raw in enumerate(result):
        if len(raw) >= 74 and raw[20] == 6 and raw[67] & 2:
            result[at] = f.tcp(link, raw[22:38] == m.PEER, raw[67],
                               int.from_bytes(raw[58:62], 'big'),
                               int.from_bytes(raw[62:66], 'big'), mss=1220)
    return result


def topology():
    state = f.old.topology()
    state['transport'] = 'Linux kernel IPv6 forwarding and AF_INET6 UDP/TCP; application DNS answers are controlled fixtures'
    for row in state['namespaces'].values():
        for link in row['links']:
            if link['ifname'] != 'lo':
                link['mtu'] = 1280
    return state


def build():
    r, buffers = f.old.build_fixture()
    r['schema'] = 'absd-native-ipv6-mtu1280-build/1'
    r['ip_mtu'] = 1280
    r['platform'].update(revision=m.PRODUCT, tree=m.PRODUCT_TREE,
                         archive={'bytes': m.PRODUCT_BYTES, 'sha256': m.PRODUCT_ARCHIVE})
    r['kernel'].update(revision=m.KERNEL, tree=m.KERNEL_TREE,
                       archive={'bytes': m.KERNEL_BYTES, 'sha256': m.KERNEL_ARCHIVE})
    r['commands'][0] = ['env', 'ABSD_ROUTE6_TCP_IP_MTU=1280', 'sh', 'scripts/build-native-ipv6-routed-tcp.sh']
    r['commands'][1][:1] = ['python3', '/product/scripts/served_kernel.py']
    r['served_kernel_policy'] = {'features': 'frame-admission-v0', 'helper_sha256': m.SERVED_KERNEL_HASH}
    return r, buffers


class Mtu1280Controls(unittest.TestCase):
    def test_complete_fixed_1280_two_link_and_socket_correspondence(self):
        peer = m.peer_result(json.dumps(f.peer()).encode())
        result = m.inspect(f.old.capture(frames('guest')), f.old.capture(frames('peer')), peer)
        self.assertEqual((result['connections'], result['tcp_answers']), (1, 2))

    def test_guest_mss_must_be_1220_and_original_1500_profile_stays_distinct(self):
        record = lambda size: {'frame': f.tcp('guest', False, 2, 1000, 0, mss=size), 'index': 0, 'timestamp': 1}
        self.assertEqual(m.classify(record(1220), 'guest')['kind'], 'tcp-query')
        for size in (0, 1219, 1440, 65535):
            with self.assertRaises(AssertionError):
                m.classify(record(size), 'guest')
        self.assertEqual(f.m.classify(record(1440), 'guest')['kind'], 'tcp-query')
        with self.assertRaises(AssertionError):
            f.m.classify(record(1220), 'guest')

    def test_checksum_valid_exact_boundary_and_oversize_frames_are_not_trimmed(self):
        for link in ('guest', 'peer'):
            for answer in (False, True):
                exact = f.tcp(link, answer, 0x18, 1001, 2001, b'x' * 1220)
                row = m.classify({'frame': exact, 'index': 0, 'timestamp': 1}, link)
                self.assertNotEqual(row['kind'], 'unexplained')
                for raw in (f.tcp(link, answer, 0x18, 1001, 2001, b'x' * 1221), exact + b'\0'):
                    self.assertEqual(m.classify({'frame': raw, 'index': 0, 'timestamp': 1}, link)['kind'], 'unexplained')

    def test_full_census_cannot_hide_one_checksum_valid_oversize_packet(self):
        peer = m.peer_result(json.dumps(f.peer()).encode())
        guest = frames('guest') + [f.tcp('guest', False, 0x18, 1001, 2001, b'x' * 1221)]
        with self.assertRaises(AssertionError):
            m.inspect(f.old.capture(guest), f.old.capture(frames('peer')), peer)

    def test_every_linux_path_link_must_match_the_1280_profile(self):
        m.validate_topology(topology())
        for role, names in (('router', ('r6-tap', 'r6-out')), ('peer', ('r6-peer',))):
            for name in names:
                for value in (1279, 1500):
                    state = topology()
                    next(row for row in state['namespaces'][role]['links'] if row['ifname'] == name)['mtu'] = value
                    with self.assertRaises(AssertionError):
                        m.validate_topology(state)

    def test_build_selector_source_and_profile_must_agree(self):
        receipt, buffers = build()
        m.build_binding(receipt, buffers)
        for change in (lambda r: r.__setitem__('ip_mtu', 1500),
                       lambda r: r.pop('ip_mtu'),
                       lambda r: r['commands'].__setitem__(0, ['sh', 'scripts/build-native-ipv6-routed-tcp.sh']),
                       lambda r: r['commands'][0].__setitem__(1, 'ABSD_ROUTE6_TCP_IP_MTU=1500'),
                       lambda r: r['platform'].__setitem__('revision', f.m.PRODUCT)):
            bad = copy.deepcopy(receipt)
            change(bad)
            with self.assertRaises((AssertionError, KeyError)):
                m.build_binding(bad, buffers)

    def test_actual_owner_mtu_marker_is_required_without_weakening_native_contract(self):
        text = f.output().replace('path-mtu=1500', 'path-mtu=1280')
        self.assertEqual(m.native_output(f.old.serial(text), 3)['census_after'][:4], [2, 13, 2, 1])
        for before, after in (('path-mtu=1280', 'path-mtu=1500'), ('path-mtu=1280', 'path-mtu=1279'),
                              ('tcp-denied=3', 'tcp-denied=2'), ('ROUTE6TCP DNS CLOSE PASS\n', '')):
            with self.assertRaises(AssertionError):
                m.native_output(f.old.serial(text.replace(before, after)), 3)

    def test_current_served_kernel_wrapper_and_feature_policy_are_required(self):
        receipt, buffers = build()
        m.build_binding(receipt, buffers)
        for change in (lambda r: r.pop('served_kernel_policy'),
                       lambda r: r['served_kernel_policy'].__setitem__('features', ''),
                       lambda r: r['served_kernel_policy'].__setitem__('helper_sha256', '0' * 64),
                       lambda r: r['commands'][1].__setitem__(1, '/product/scripts/not-served.py'),
                       lambda r: r['kernel'].__setitem__('revision', f.m.KERNEL),
                       lambda r: r['kernel'].__setitem__('tree', f.m.KERNEL_TREE),
                       lambda r: r['kernel']['archive'].__setitem__('sha256', f.m.KERNEL_ARCHIVE)):
            bad = copy.deepcopy(receipt)
            change(bad)
            with self.assertRaises((AssertionError, KeyError)):
                m.build_binding(bad, buffers)


if __name__ == '__main__':
    unittest.main()
