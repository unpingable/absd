#!/usr/bin/env python3
"""Guard actual probe source ordering; no register/device behavior is modeled.

The guard ties the early PCI calls to the propagated disable handshake,
queue initialization and final enable. Independent source substitutions must
be refused. Guest NVMe gates and physical qualification remain separate.
"""
from pathlib import Path
import argparse
import re


def block(source, marker):
    if source.count(marker) != 1:
        raise ValueError(f'expected one block: {marker}')
    start = source.index(marker) + len(marker)
    depth = 1
    for end in range(start, len(source)):
        depth += (source[end] == '{') - (source[end] == '}')
        if depth == 0:
            return source[start:end], start, end
    raise ValueError(f'unclosed block: {marker}')


def check(source, block_source):
    source = re.sub(r'/\*.*?\*/|//[^\n]*', '', source, flags=re.S)
    probe, _, _ = block(source, 'pub fn probe(write_serial: Option<&[u8]>) -> Result<Identity, NvmeError> {')
    patterns = [
        ('bus-master off', r'pci::disable_dma\(function\);'),
        ('memory decode', r'pci::enable_memory\(function\);'),
        ('capability read', r'found\.read64\(REG_CAP\)'),
        ('ready timeout rules', r'nvme_ready::Timeouts::from_registers\(found\.identity\.version, capabilities, crto\)'),
        ('new enable timeout binding', r'let ready_limit = limits\.with_media;'),
        ('withdrawal timeout binding', r'found\.ready_limit = ready_limit;'),
        ('propagate settled disable failure', r'found\.disable_before_probe\(limits\)\?;'),
        ('clear owned queues', r'zero\(page\);'),
        ('admin queue size', r'found\.write32\(REG_AQA, \(size << 16\) \| size\);'),
        ('admin submission address', r'found\.write64\(REG_ASQ, found\.admin\.submission\);'),
        ('admin completion address', r'found\.write64\(REG_ACQ, found\.admin\.completion\);'),
        ('bus-master on', r'pci::enable_polled_dma\(function\);'),
        ('enable controller', r'found\.write32\(REG_CC, CC_QUEUE_ENTRY_SIZES \| CC_ENABLE\);'),
        ('propagate enable failure', r'found\.wait_ready\(true, ready_limit\)\?;'),
    ]
    last = -1
    for name, pattern in patterns:
        found = list(re.finditer(pattern, probe))
        if len(found) != 1:
            raise ValueError(f'{name}: expected exactly one source site, got {len(found)}')
        position = found[0].start()
        if position <= last:
            raise ValueError(f'{name}: violates required probe ordering')
        last = position
    if source.count('enable_polled_dma') != 1 or any(
        token in source for token in ('COMMAND_BUS_MASTER', 'pci::write32')
    ):
        raise ValueError('unreviewed bus-master token outside the one enable site')
    if source.count('write32(REG_CC, 0)') != 2:
        raise ValueError('CC clear must occur only in the guarded disable and cleanup blocks')
    crto, _, _ = block(probe, 'let crto = if nvme_ready::uses_crto(found.identity.version, capabilities) {')
    if not re.fullmatch(r'\s*Some\(found\.read32\(REG_CRTO\)\)\s*', crto) or source.count('read32(REG_CRTO)') != 1:
        raise ValueError('CRTO read must be gated by supported version and ready mode')
    reset, _, _ = block(source, 'fn disable_before_probe(&self, limits: nvme_ready::Timeouts) -> Result<(), NvmeError> {')
    enabled, enabled_start, enabled_end = block(reset, 'if configuration & CC_ENABLE != 0 {')
    if not re.fullmatch(r'\s*let configuration = self\.read32\(REG_CC\);\s*', reset[:enabled_start - len('if configuration & CC_ENABLE != 0 {')]):
        raise ValueError('inherited configuration must be observed before disable')
    if not re.fullmatch(
        r'\s*self\.wait_ready\(true, limits\.for_configuration\(configuration\)\)'
        r'\s*\.map_err\(\|error\| match error {'
        r'\s*NvmeError::Timeout\(_\) => NvmeError::Timeout\("inherited enable"\),'
        r'\s*other => other,\s*}\)\?;'
        r'\s*let status = self\.read32\(REG_CSTS\);'
        r'\s*if !nvme_ready::may_clear_enable\(configuration, status\)\s*{'
        r'\s*return Err\(NvmeError::Timeout\("inherited enable"\)\);\s*}'
        r'\s*self\.write32\(REG_CC, 0\);\s*', enabled
    ):
        raise ValueError('EN clear must follow propagated ready wait and a fresh RDY guard')
    if not re.fullmatch(r'\s*self\.wait_ready\(false, limits\.with_media\)\s*', reset[enabled_end + 1:]):
        raise ValueError('disable completion must be propagated before queue reuse')
    initialized, start, end = block(probe, 'let initialized = (|| -> Result<(), NvmeError> {')
    if 'pci::enable_polled_dma(function);' not in initialized:
        raise ValueError('DMA enable must be inside captured initialization')
    suffix = probe[end + 1:]
    error, error_start, error_end = block(suffix, 'if let Err(error) = initialized {')
    if not re.fullmatch(r'\s*found\.abandon_probe\(ready_limit\);\s*return Err\(error\);\s*', error):
        raise ValueError('every captured refusal must clean up and preserve the original error')
    outside_error = suffix[:error_start - len('if let Err(error) = initialized {')] + suffix[error_end + 1:]
    if '?' in outside_error or 'return' in outside_error:
        raise ValueError('post-enable error bypasses captured cleanup')
    if any(token in outside_error for token in ('unwrap', 'expect', 'panic!', 'let _ =')) or re.search(r'\bfound\s*\.\s*\w+\s*\(', outside_error):
        raise ValueError('unreviewed post-closure panic or command bypasses cleanup')
    if any(re.search(r'CONTROLLER[^;]*=\s*Some\s*\(\s*found\b', part) for part in (probe[:start], initialized, suffix[:error_end + 1])):
        raise ValueError('controller published before initialization error handling completes')
    cleanup, _, _ = block(source, 'fn abandon_probe(&self, ready_limit: u64) {')
    if cleanup.count('pci::disable_dma(') != 1:
        raise ValueError('cleanup must clear BME exactly once after stop')
    stop, _, stop_end = block(cleanup, 'let stopped = if status & CSTS_READY != 0 {')
    if not re.fullmatch(r'\s*self\.write32\(REG_CC, 0\);\s*self\.wait_ready\(false, ready_limit\)\.is_ok\(\)\s*', stop):
        raise ValueError('ready controller must get a bounded stop before DMA disable')
    if not re.match(r'\s*else\s*{\s*false\s*};\s*pci::disable_dma\(self\.identity\.pci\);', cleanup[stop_end + 1:]):
        raise ValueError('every cleanup outcome must reach DMA disable')
    if '?' in cleanup or 'return' in cleanup:
        raise ValueError('cleanup can return before DMA disable')
    withdrawn, _, _ = block(source, 'pub fn withdraw_failed_probe() {')
    if withdrawn.count('CONTROLLER)).take()') != 1 or withdrawn.count('found.abandon_probe(found.ready_limit);') != 1:
        raise ValueError('published controller must be taken once and contained once')
    if withdrawn.index('CONTROLLER)).take()') > withdrawn.index('found.abandon_probe(found.ready_limit);'):
        raise ValueError('controller withdrawal must precede containment')
    if '?' in withdrawn or 'return' in withdrawn or withdrawn.count('addr_of_mut!(CONTROLLER)') != 1:
        raise ValueError('withdrawal must not bypass containment or republish')
    taken, taken_start, taken_end = block(withdrawn, 'if let Some(found) = previous {')
    if not re.fullmatch(r'\s*crate::kernel_lock::assert_bsp_device_access\(\);\s*let previous = unsafe { \(\*core::ptr::addr_of_mut!\(CONTROLLER\)\)\.take\(\) };\s*', withdrawn[:taken_start - len('if let Some(found) = previous {')]):
        raise ValueError('withdrawal must directly take the published controller')
    if not re.fullmatch(r'\s*found\.abandon_probe\(found\.ready_limit\);\s*crate::serial::write\("NVME CONTROLLER WITHDRAWN reason=first-read\\n"\);\s*', taken) or withdrawn[taken_end + 1:].strip():
        raise ValueError('taken controller must be contained without a conditional bypass')
    block_source = re.sub(r'/\*.*?\*/|//[^\n]*', '', block_source, flags=re.S)
    block_probe, _, _ = block(block_source, 'pub fn probe(nvme_write: Option<&[u8]>) -> Result<u64, BlockError> {')
    read, _, _ = block(block_probe, 'match nvme::read_sector(0, &mut sector) {')
    failed_read, _, _ = block(read, 'Err(error) => {')
    if block_probe.count('nvme::withdraw_failed_probe();') != 1 or failed_read.count('return') != 1:
        raise ValueError('first-read failure must contain its published controller exactly once')
    if not re.search(r'nvme::withdraw_failed_probe\(\);\s*return Err\(nvme_error\(error\)\);\s*$', failed_read):
        raise ValueError('first-read failure must clean up before preserving the read error')
    if 'DEVICE' in failed_read or 'pci::disable_dma' in failed_read:
        raise ValueError('first-read failure must not publish or bypass ordered containment')
    return len(patterns) + 12


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    source = (Path(__file__).resolve().parents[1]/'src/nvme.rs').read_text()
    block_source = (Path(__file__).resolve().parents[1]/'src/block.rs').read_text()
    sites = check(source, block_source)
    if args.self_test:
        enable = 'pci::enable_polled_dma(function);'
        disable = 'pci::disable_dma(function);'
        wait = 'found.disable_before_probe(limits)?;'
        assert source.count(enable) == source.count(disable) == source.count(wait) == 1
        mutants = {
            'original early DMA': source.replace(enable, '').replace(disable, enable+'\n'+disable),
            'omitted bus-master off': source.replace(disable, ''),
            'omitted disable wait': source.replace(wait, ''),
            'swallowed disable refusal': source.replace(wait, 'let _ = found.disable_before_probe(limits);'),
            'DMA before queues configured': source.replace(enable, '').replace('found.write32(REG_AQA,', enable+'\nfound.write32(REG_AQA,'),
            'uncaptured post-enable refusal': source.replace('if let Err(error) = initialized {', 'return Err(NvmeError::Fatal);\nif let Err(error) = initialized {'),
            'cleanup omitted': source.replace('found.abandon_probe(ready_limit);', ''),
            'cleanup DMA disable omitted': source.replace('pci::disable_dma(self.identity.pci);', ''),
            'cleanup wait omitted': source.replace('self.wait_ready(false, ready_limit).is_ok()', 'true'),
            'cleanup original error lost': source.replace('return Err(error);', 'return Err(NvmeError::Fatal);'),
            'publication before error handling': source.replace('if let Err(error) = initialized {', 'unsafe { *core::ptr::addr_of_mut!(CONTROLLER) = Some(found); }\nif let Err(error) = initialized {'),
            'cleanup DMA off before reset': source.replace('fn abandon_probe(&self, ready_limit: u64) {', 'fn abandon_probe(&self, ready_limit: u64) {\npci::disable_dma(self.identity.pci);'),
            'uncaptured unwrap': source.replace('if let Err(error) = initialized {', 'initialized.unwrap();\nif let Err(error) = initialized {'),
            'uncaptured swallowed command': source.replace('if let Err(error) = initialized {', 'let _ = found.identify(IDENTIFY_CONTROLLER, 0);\nif let Err(error) = initialized {'),
            'publication through clone': source.replace(enable, 'unsafe { *core::ptr::addr_of_mut!(CONTROLLER) = Some(found.clone()); }\n'+enable),
            'alternate DMA call': source.replace(disable, 'enable_polled_dma(function);\n'+disable),
            'raw PCI command write': source.replace(disable, 'pci::write32(function, 4, 4);\n'+disable),
            'raw BME bit': source.replace(disable, 'let _ = COMMAND_BUS_MASTER;\n'+disable),
            'unconditional inherited CC clear': source.replace(wait, 'found.write32(REG_CC, 0);\nfound.wait_ready(false, ready_limit)?;'),
            'omitted inherited ready wait': source.replace('self.wait_ready(true, limits.for_configuration(configuration))', 'Ok::<(), NvmeError>(())'),
            'omitted fresh RDY guard': source.replace('if !nvme_ready::may_clear_enable(configuration, status)', 'if false'),
            'ungated CRTO read': source.replace('if nvme_ready::uses_crto(found.identity.version, capabilities)', 'if true'),
            'legacy-only timeout': source.replace('nvme_ready::Timeouts::from_registers(found.identity.version, capabilities, crto)', 'legacy_limits'),
            'fixed new enable timeout': source.replace('let ready_limit = limits.with_media;', 'let ready_limit = 500;'),
            'fixed withdrawal timeout': source.replace('found.ready_limit = ready_limit;', 'found.ready_limit = 500;'),
            'withdrawal omitted': source.replace('let previous = unsafe { (*core::ptr::addr_of_mut!(CONTROLLER)).take() };', 'let previous = None;'),
            'published controller not contained': source.replace('found.abandon_probe(found.ready_limit);', ''),
        }
        for name, mutant in mutants.items():
            if mutant == source:
                raise RuntimeError(f'negative not applied: {name}')
            try:
                check(mutant, block_source)
            except ValueError as error:
                print(f'negative refused: {name}: {error}')
            else:
                raise RuntimeError(f'negative survived: {name}')
        block_mutants = {
            'first-read cleanup omitted': block_source.replace('nvme::withdraw_failed_probe();', ''),
            'first-read cleanup after return': block_source.replace('nvme::withdraw_failed_probe();\n                    return Err(nvme_error(error));', 'return Err(nvme_error(error));\n                    nvme::withdraw_failed_probe();'),
            'first-read error swallowed': block_source.replace('return Err(nvme_error(error));', 'return Err(BlockError::Absent);'),
        }
        for name, mutant in block_mutants.items():
            if mutant == block_source:
                raise RuntimeError(f'negative not applied: {name}')
            try:
                check(source, mutant)
            except ValueError as error:
                print(f'negative refused: {name}: {error}')
            else:
                raise RuntimeError(f'negative survived: {name}')
        print(f'NVME PROBE ORDER CONTROLS OK cases={len(mutants) + len(block_mutants)}')
    print(f'NVME PROBE ORDER OK sites={sites}')


if __name__ == '__main__':
    main()
