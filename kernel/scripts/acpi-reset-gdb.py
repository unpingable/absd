"""Read-only reset observer executed by installed GDB Python (one vCPU)."""
import hashlib
import json
import os
from pathlib import Path
import time

import gdb

config = json.loads(Path(os.environ['ABSD_RESET_GDB_CONFIG']).read_text())
out = Path(config['out'])
plan = config['plan']
exited = False
active_step = None
sequence = 0


def event(kind, **fields):
    global sequence
    row = {'sequence': sequence, 'event': kind, 'unix': time.time(), **fields}
    sequence += 1
    with (out / 'observations.jsonl').open('a') as stream:
        stream.write(json.dumps(row, sort_keys=True) + '\n')
        stream.flush()
    gdb.write('RESET_OBSERVER ' + json.dumps(row, sort_keys=True) + '\n')


def register(name):
    return int(gdb.parse_and_eval('$' + name))


def memory(address, size):
    return bytes(gdb.selected_inferior().read_memory(address, size))


def target_exit(stop):
    global exited
    exited = True
    event('target-exited', active_step=active_step, exit_code=getattr(stop, 'exit_code', None))


def hardware(pc):
    return gdb.Breakpoint('*' + hex(pc), type=gdb.BP_HARDWARE_BREAKPOINT)


try:
    gdb.execute('set pagination off')
    gdb.execute('set confirm off')
    quote = lambda text: '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'
    gdb.execute('file ' + quote(config['elf']))
    gdb.execute('set architecture i386:x86-64')
    gdb.execute('set language c')
    gdb.execute('target remote ' + config['gdb_socket'])
    gdb.events.exited.connect(target_exit)
    entry = hardware(plan['entry'])
    event('attached', gdb_version=gdb.VERSION, plan=plan)
    gdb.execute('continue')
    if exited or register('pc') != plan['entry'] or len(gdb.selected_inferior().threads()) != 1:
        raise RuntimeError('required one-vCPU entry was not established')
    event('entry', pc=register('pc'), cs=register('cs'), flags=register('eflags'))
    entry.delete()
    reset = hardware(plan['reset_entry'])
    gdb.execute('continue')
    if exited or register('pc') != plan['reset_entry']:
        raise RuntimeError('reset entry was not reached through its actual caller')
    rsp = register('rsp')
    return_bytes = memory(rsp, 8)
    return_pc = int.from_bytes(return_bytes, 'little')
    if return_pc not in plan['allowed_return_addresses']:
        raise RuntimeError('reset caller is outside the frozen observation plan')
    call_pc = return_pc - 5
    call_bytes = memory(call_pc, 5)
    if call_bytes[0] != 0xe8 or return_pc + int.from_bytes(call_bytes[1:], 'little', signed=True) != plan['reset_entry']:
        raise RuntimeError('caller does not decode to the actual direct reset call')
    event('reset-entry', pc=register('pc'), rsp=rsp, return_pc=return_pc,
          return_bytes_hex=return_bytes.hex(), call_pc=call_pc,
          call_bytes_hex=call_bytes.hex(), decoded=gdb.selected_frame().architecture().disassemble(call_pc, count=1))
    reset.delete()
    points = {row['pc']: hardware(row['pc']) for row in plan['outs']}
    event('outs-armed', points=[{'pc': pc, 'type': bp.type} for pc, bp in points.items()],
          description=gdb.execute('info breakpoints', to_string=True))
    index = 0
    while not exited:
        try:
            gdb.execute('continue')
        except gdb.error as error:
            event('continue-disconnected', detail=str(error))
            if not exited:
                raise RuntimeError('disconnect without native target-exited event') from error
            break
        if exited:
            break
        pc = register('pc')
        if pc not in points or len(gdb.selected_inferior().threads()) != 1:
            raise RuntimeError('unexpected stop or vCPU count')
        opcode = memory(pc, 1)
        decoded = gdb.selected_frame().architecture().disassemble(pc, count=1)
        if opcode != b'\xee' or len(decoded) != 1 or decoded[0]['length'] != 1 or not decoded[0]['asm'].strip().startswith('out'):
            raise RuntimeError('eligible PC is not the decoded one-byte OUT DX,AL')
        prefix = Path(config['serial']).read_bytes()
        prefix_name = f'prefix-{index}.bin'
        (out / prefix_name).write_bytes(prefix)
        event('before-out', index=index, pc=pc, opcode_hex=opcode.hex(), decoded=decoded,
              al=register('al'), dx=register('dx'), flags=register('eflags'), cs=register('cs'),
              prefix_file=prefix_name, prefix_bytes=len(prefix), prefix_sha256=hashlib.sha256(prefix).hexdigest())
        points[pc].enabled = False
        active_step = index
        event('step-issued', index=index, pc=pc)
        try:
            gdb.execute('stepi')
        except gdb.error as error:
            event('step-disconnected', index=index, detail=str(error))
            if not exited:
                raise RuntimeError('step disconnect without native target-exited event') from error
            break
        if exited:
            event('step-target-exited', index=index)
            break
        after = register('pc')
        event('after-step', index=index, pc=after)
        if after != pc + 1:
            raise RuntimeError('OUT single step did not advance one byte')
        active_step = None
        points[pc].enabled = True
        index += 1
    event('observer-finished', target_exited=exited)
    gdb.execute('quit 0')
except Exception as error:
    event('apparatus-error', detail=f'{type(error).__name__}: {error}')
    gdb.execute('quit 2')
