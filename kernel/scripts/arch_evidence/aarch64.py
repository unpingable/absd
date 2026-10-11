"""Mirrors arch/aarch64::memory_fault; native syndrome retained separately."""
def memory_fault(vector, address, error):
    ec, fsc = error >> 26, error & 63
    if vector != ec or ec not in (0x20, 0x24):
        raise ValueError('inconsistent/unqualified native memory exception')
    return dict(kind='translation' if 4 <= fsc <= 7 else 'permission' if 12 <= fsc <= 15 else 'alignment' if fsc == 0x21 else 'other',
                access='execute' if ec == 0x20 else 'write' if error & 64 else 'read',
                from_user=True, address=address)
