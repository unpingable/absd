"""Read the owning literal ABI/catalog bounds for same-source host oracles."""
from pathlib import Path
import re
ROOT = Path(__file__).resolve().parents[1]

def bound(file, name):
    matches = re.findall(r'^pub const '+name+r': usize = ([0-9]+);$', (ROOT/file).read_text(), re.M)
    if len(matches) != 1 or int(matches[0]) <= 0:
        raise ValueError('missing/ambiguous literal source bound: '+name)
    return int(matches[0])

MAX_PROCESS_SLOTS = bound('abi/src/syscall.rs', 'MAX_PROCESS_SLOTS')
MAX_PROCESS_HANDLES = bound('abi/src/syscall.rs', 'MAX_PROCESS_HANDLES')
FILE_SERVER_SLOTS = bound('abi/src/program.rs', 'FILE_SERVER_SLOTS')
if __name__ == '__main__':
    print(MAX_PROCESS_SLOTS)
