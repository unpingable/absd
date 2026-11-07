#!/usr/bin/env python3
"""Exercise a running operator image through its existing private QEMU serial socket.
This does not launch QEMU, modify images or claim physical keyboard coverage.
The socket must have one exclusive client; token bytes are never printed.
"""
import argparse
from pathlib import Path
import select
import socket
import time

class Console:
    def __init__(self, stream, timeout=30):
        self.stream, self.timeout, self.pending = stream, timeout, b''
    def send(self, data):
        self.stream.sendall(data)
    def expect(self, pattern):
        deadline = time.monotonic() + self.timeout
        while pattern not in self.pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f'timed out awaiting {pattern!r}')
            ready, _, _ = select.select([self.stream], [], [], remaining)
            if ready:
                data = self.stream.recv(4096)
                if not data:
                    raise RuntimeError('serial console closed')
                self.pending += data
                if len(self.pending) > 128 * 1024:
                    raise RuntimeError('console output flooded acceptance reader')
        at = self.pending.index(pattern) + len(pattern)
        result, self.pending = self.pending[:at], self.pending[at:]
        return result
    def command(self, text, expected):
        self.send(text + b'\r')
        if expected:
            self.expect(b'\r\n' + expected)
        self.expect(b'absd$ ')

def exercise(console, token):
    # A nonblocking serial socket may attach after the original prompt.
    # Request an actual redraw before waiting; never consume a log as input.
    console.send(b'\x1dr')
    console.expect(b'operator token: ')
    console.send(b'incorrect\r')
    console.expect(b'Authentication failed; retry in 2s.')
    time.sleep(2.1)
    console.send(token + b'\r')
    console.expect(b'Authenticated operator.')
    console.expect(b'absd$ ')
    console.command(b'echo local-one', b'local-one\r\n')
    console.command(b'cd /home/operator', b'')
    console.send(b'\x1d2')
    console.expect(b'operator token: ')
    console.send(token + b'\r')
    console.expect(b'Authenticated operator.')
    console.expect(b'absd$ ')
    console.command(b'pwd', b'/\r\n')
    console.command(b'echo local-two', b'local-two\r\n')
    console.send(b'\x1d1')
    console.expect(b'ABSD local console 1')
    console.expect(b'absd$ ')
    # Force a fresh result beyond all retained transcript bytes.
    console.pending = b''
    console.command(b'echo retained-one-fresh', b'retained-one-fresh\r\n')
    console.command(b'pwd', b'/home/operator\r\n')
    console.send(b'cat\r')
    time.sleep(1)
    console.send(b'\x03')
    console.expect(b'absd$ ')
    console.command(b'echo survived-interrupt', b'survived-interrupt\r\n')
    console.send(b'\x1dk')
    console.expect(b'ABSD kernel maintenance')
    console.send(b'maintenance-input-must-not-reach-shell\r')
    console.send(b'\x1dr')
    console.expect(b'ABSD local console 1')
    console.expect(b'absd$ ')
    console.pending = b''
    console.command(b'echo resumed-local-fresh', b'resumed-local-fresh\r\n')
    console.send(b'\x1dl')
    console.expect(b'Enter confirms logout; any other key cancels.')
    console.send(b'\r')
    console.expect(b'Session ended.')
    time.sleep(1.1)
    console.send(token + b'\r')
    console.expect(b'Authenticated operator.')
    console.expect(b'absd$ ')
    console.send(b'\x04')
    console.expect(b'Session ended.')
    print('LOCAL CONSOLE: failed auth, login, two retained shells, foreground interrupt, maintenance return, logout, fresh login and EOF observed')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial-socket', required=True, type=Path)
    parser.add_argument('--token-file', required=True, type=Path)
    args = parser.parse_args()
    token = args.token_file.read_bytes().strip()
    if len(token) != 32 or any(c not in b'0123456789abcdef' for c in token):
        parser.error('token file must hold the enrolled 32-character token')
    with socket.socket(socket.AF_UNIX) as stream:
        stream.connect(str(args.serial_socket))
        exercise(Console(stream), token)
if __name__ == '__main__':
    main()
