#!/usr/bin/env python3
"""Check executed OUT observations from installed GDB, not an emulator trace guess."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def serial_contract(mode, serial, expected_reason=None, case_name=None):
    serial = serial.replace("\r\n", "\n")
    require(mode in ("fadt", "legacy"), "unknown reset mode")
    require(expected_reason in ("Disabled", "Missing", "Walk") if mode == "legacy"
            else expected_reason is None, "legacy requires an explicit supported expected reason")
    require(not re.search(r"PANIC|KERNEL FAULT|init: FAILED", serial), "kernel/consumer failure")
    require("MACHINE RECOVER TEST handing recover-only handle\n" in serial, "wrong consumer")
    probe = re.findall(r"^SPAWN OK pid=([0-9]+) parent=1 program=machine-probe$", serial, re.M)
    require(len(probe) == 1 and int(probe[0]) > 1, "missing unique recover-only child")
    require(re.findall(r"^MACHINE RECOVER RESET pid=([0-9]+)$", serial, re.M) == probe,
            "reset did not come from recover-only child exactly once")
    require(re.search(r"^SERVED RECOVERY CENSUS processes=2 ", serial, re.M), "recovery census")
    require(not re.search(r"^SERVED SHUTDOWN|^SERVED RECOVERY BEGIN|^SERVED RECOVERY RESET|ABSD BOOT OK|USER EXIT pid=1 ", serial, re.M),
            "unexpected served boot or completion marker")
    request = f"MACHINE RECOVER RESET pid={probe[0]}\n"
    census = re.search(r"^SERVED RECOVERY CENSUS processes=2 .*$", serial, re.M).group()
    require(serial.index(census) < serial.index(request), "reset record precedes its recovery census")
    if mode == "fadt":
        require(serial.index(request) < serial.index("ACPI RESET ATTEMPT"), "FADT attempt precedes authorized reset request")
        require(serial.splitlines().count("ACPI OK") == 1, "missing unique validated ACPI walk")
        require(serial.splitlines().count("ACPI RESET ARMED profile=q35-byte-io port=0xcf9 value=0x0f") == 1,
                "missing unique armed Q35 reset plan")
        require(serial.count("ACPI RESET ATTEMPT port=0xcf9 value=0x0f\n") == 1, "missing unique FADT attempt")
        require(not re.search(r"ACPI RESET RETURNED|ACPI RESET UNAVAILABLE", serial), "FADT attempt returned/fell back")
    else:
        diagnostics = re.findall(r"^ACPI RESET UNAVAILABLE[^\n]*$", serial, re.M)
        expected = f"ACPI RESET UNAVAILABLE reason={expected_reason} fallback=legacy"
        require(diagnostics == [expected], "wrong or duplicate legacy reason")
        require(serial.index(request) < serial.index(expected), "legacy diagnostic precedes authorized request")
        require(not re.search(r"ACPI RESET ARMED|ACPI RESET ATTEMPT", serial), "FADT armed/attempted in legacy control")
        if case_name == "missing-descriptor":
            require("ACPI FADT RESET absent (table too short)" in serial.splitlines(), "absent-descriptor control not exercised")
        if case_name == "duplicate-fadt":
            require("ACPI REFUSED stage=fadt reason=Duplicate" in serial.splitlines(), "unique-FADT refusal not exercised")
            require(len(re.findall(r"^ACPI TABLE sig=FACP ", serial, re.M)) == 2, "not two actual FADTs")


def check_observation(out, mode, expected_reason=None, fixture=False, case_name=None):
    out = Path(out)
    metadata = json.loads((out / 'metadata.json').read_text())
    result = json.loads((out / 'result.json').read_text())
    for name, expected in result['evidence_sha256'].items():
        require(Path(name).name == name and hashlib.sha256((out / name).read_bytes()).hexdigest() == expected,
                'observation artifact identity differs: ' + name)
    events = [json.loads(line) for line in (out / 'observations.jsonl').read_text().splitlines()]
    require(metadata['kind'] == ('fixture' if fixture else 'product'), "fixture/product identity boundary")
    require(result['observation_complete'] and not result['cleanup'], "observer incomplete or producer terminated by controller")
    require({key: row['exit'] for key, row in result['children'].items()} == {'qemu': 0, 'gdb': 0},
            "natural QEMU/GDB exit0 not established")
    require([row['sequence'] for row in events] == list(range(len(events))), "observation sequence is not complete")
    require(not any(row['event'] == 'apparatus-error' for row in events), "native observer error")
    def selected(name):
        return [row for row in events if row['event'] == name]
    def unique(name):
        found = selected(name)
        require(len(found) == 1, 'missing/nonunique ' + name)
        return found[0]
    plan = metadata['plan']
    if not fixture:
        contracts = {'positive': ('fadt', None), 'feature-only': ('legacy', 'Disabled'),
                     'option-only': ('legacy', 'Disabled'), 'default': ('legacy', 'Disabled'),
                     'missing-descriptor': ('legacy', 'Missing'), 'duplicate-fadt': ('legacy', 'Walk')}
        require(case_name in contracts and contracts[case_name] == (mode, expected_reason)
                and metadata['case_name'] == case_name, 'case-specific reset contract differs')
        require(metadata['source_commit'] == plan['source_commit'] == 'f47818e18ea1dcee54bb5836f2710c247a7683da', 'product source identity differs')
        require(metadata['elf_sha256'] == plan['elf_sha256'] and metadata['elf_sha256'] in
                ['fc4852ea42b7776e49789cb95edc04ff5a7d35d250fd98df286e18b06ef18e88',
                 '8ce0ed4ca760cd4658dcf8f56b0ebb7683d62a746da50065b0c6c1515e276116'], 'frozen product ELF identity differs')
    require(unique('attached')['plan'] == plan, "attached plan differs")
    require(unique('entry')['pc'] == plan['entry'], "entry PC differs")
    reset = unique('reset-entry')
    require(reset['pc'] == plan['reset_entry'] and reset['return_pc'] in plan['allowed_return_addresses'], "reset entry/caller differs")
    require(len(bytes.fromhex(reset['return_bytes_hex'])) == 8
            and int.from_bytes(bytes.fromhex(reset['return_bytes_hex']), 'little') == reset['return_pc'], "actual eight-byte call frame missing")
    call = bytes.fromhex(reset['call_bytes_hex'])
    require(len(call) == 5 and call[0] == 0xe8 and reset['call_pc'] + 5 == reset['return_pc']
            and reset['return_pc'] + int.from_bytes(call[1:], 'little', signed=True) == plan['reset_entry'],
            "actual caller opcode/target differs")
    require(unique('observer-finished')['target_exited'] and len(selected('target-exited')) == 1, "native target exit missing")
    roles = {row['pc']: row['role'] for row in plan['outs']}
    armed = unique('outs-armed')
    require([row['pc'] for row in armed['points']] == list(roles)
            and all(row['type'] == 2 for row in armed['points']), "eligible hardware breakpoint set differs")
    if roles:
        require('hw breakpoint' in armed['description'], "hardware breakpoint primitive missing")
    serial = (out / 'serial.log').read_bytes()
    before = selected('before-out')
    require([row['index'] for row in before] == list(range(len(before))), "OUT indices are not ordered")
    require(len(selected('step-issued')) == len(before), 'OUT/step count differs')
    values, previous_prefix = [], b''
    completed_sequence = armed['sequence']
    for row in before:
        index, pc = row['index'], row['pc']
        require(row['sequence'] > completed_sequence, 'next OUT preceded execution of previous OUT')
        require(pc in roles and row['opcode_hex'] == 'ee', "unrecognized OUT PC/opcode")
        decoded = row['decoded']
        require(len(decoded) == 1 and decoded[0]['addr'] == pc and decoded[0]['length'] == 1
                and decoded[0]['asm'].strip().startswith('out'), "native one-byte OUT decode missing")
        require(row['flags'] & (1 << 9) == 0, "interrupts enabled at terminal OUT")
        require(row['prefix_file'] == f'prefix-{index}.bin', "prefix identity differs")
        prefix = (out / row['prefix_file']).read_bytes()
        require(len(prefix) == row['prefix_bytes'] and hashlib.sha256(prefix).hexdigest() == row['prefix_sha256'], "pre-OUT prefix bytes/hash differ")
        require(serial.startswith(prefix) and prefix.startswith(previous_prefix), "serial prefix is not the pre-OUT stream")
        previous_prefix = prefix
        if fixture:
            require(prefix == bytes.fromhex(metadata['fixture']['prefix_hex']), "actual fixture prefix missing before OUT")
        else:
            serial_contract(mode, prefix.decode(), expected_reason, case_name)
        issued = [event for event in selected('step-issued') if event['index'] == index]
        require(len(issued) == 1 and issued[0]['pc'] == pc and issued[0]['sequence'] > row['sequence'], "OUT was located but not stepped")
        advanced = [event for event in selected('after-step') if event['index'] == index]
        disconnected = [event for event in selected('step-disconnected') + selected('step-target-exited') if event['index'] == index]
        if advanced:
            require(len(advanced) == 1 and advanced[0]['pc'] == pc + 1 and advanced[0]['sequence'] > issued[0]['sequence'], "OUT did not execute one byte")
        else:
            require(len(disconnected) == 1 and disconnected[0]['sequence'] > issued[0]['sequence']
                    and unique('target-exited')['active_step'] == index, "OUT execution/terminal step not established")
        completed_sequence = advanced[0]['sequence'] if advanced else disconnected[0]['sequence']
        values.append((row['dx'], row['al'], roles[pc]))
    cf9 = [value for port, value, _ in values if port == 0xcf9]
    require(cf9 == ([15] if mode == 'fadt' else [2, 6]), f"CF9 sequence mismatch: {cf9}")
    if mode == 'fadt':
        require(len(values) == 1 and (fixture or values[0][2] == 'fadt'), "legacy/extra OUT after FADT")
    elif not fixture:
        require([role for _, _, role in values] in [['legacy-2', 'legacy-6'], ['legacy-2', 'legacy-6', 'legacy-keyboard']], "legacy sites/order differ")
        require(all(port == 0xcf9 or (port, value, role) == (0x64, 0xfe, 'legacy-keyboard') for port, value, role in values), "unexpected terminal I/O")
    if not fixture:
        serial_contract(mode, serial.decode(), expected_reason, case_name)
    return {'disposition': 'FIXTURE_ACCEPT' if fixture else 'PRODUCT_OBSERVATION_ACCEPT',
            'cf9_values': cf9, 'observed_outs': len(values), 'natural_qemu_exit': 0}



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observation', type=Path, required=True)
    parser.add_argument('--mode', choices=['fadt', 'legacy'], required=True)
    parser.add_argument('--expected-reason', choices=['Disabled', 'Missing', 'Walk'])
    parser.add_argument('--fixture', action='store_true')
    parser.add_argument('--case-name')
    args = parser.parse_args()
    if (args.mode == 'legacy') != (args.expected_reason is not None):
        parser.error('--expected-reason is required only for legacy mode')
    print(check_observation(args.observation, args.mode, args.expected_reason, args.fixture, args.case_name))


if __name__ == '__main__':
    main()
