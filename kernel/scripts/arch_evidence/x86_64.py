"""Mirrors arch/x86_64::memory_fault; does not infer hidden fault causes."""
def memory_fault(vector, address, error):
    if vector != 14:
        raise ValueError('unqualified native exception for B2 memory case')
    return dict(kind='other' if error & ~0x17 else 'translation' if not error & 1 else 'permission',
                access='execute' if error & 16 else 'write' if error & 2 else 'read',
                from_user=bool(error & 4), address=address)
