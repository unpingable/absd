#!/usr/bin/env python3
"""Real Linux sshd/SSH producer-stream regression; no ABSD guest or remote host."""
from pathlib import Path
import argparse, importlib.util, json, os, re, shutil, signal, subprocess, sys, tempfile, time


class CleanupUnknown(RuntimeError):
    pass


def group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def stop_server(server, term_timeout=10, kill_timeout=5):
    """End only the session/group created for this owned Popen, then reap it."""
    pgid = server.pid
    if pgid == os.getpgrp():
        raise CleanupUnknown('refusing the caller process group')
    if server.returncode is not None:
        if group_exists(pgid):
            raise CleanupUnknown(f'reaped server has an unverified remaining group pid={server.pid}')
        return dict(pid=server.pid, pgid=pgid, term_sent=False, kill_sent=False,
                    returncode=server.returncode, group_gone=True)
    try:
        if os.getpgid(server.pid) != pgid:
            raise CleanupUnknown(f'owned server changed process group pid={server.pid}')
    except ProcessLookupError:
        pass

    def send(sig):
        try:
            os.killpg(pgid, sig)
            return True
        except ProcessLookupError:
            return False  # The group can exit between observation and signal.

    def ended(timeout):
        deadline = time.monotonic() + timeout
        try:
            server.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            return False
        while group_exists(pgid):
            if time.monotonic() >= deadline:
                return False
            time.sleep(.01)
        return True

    term_sent = send(signal.SIGTERM)
    kill_sent = False
    if not ended(term_timeout):
        # An unreaped direct child reserves this group identity. Once wait
        # reaped it, never signal a possibly reused numeric group identifier.
        if server.returncode is not None:
            raise CleanupUnknown(f'server reaped but group disappearance unverified pid={server.pid}')
        kill_sent = send(signal.SIGKILL)
        if not ended(kill_timeout):
            raise CleanupUnknown(f'owned server/group cleanup unknown pid={server.pid} returncode={server.returncode}')
    return dict(pid=server.pid, pgid=pgid, term_sent=term_sent,
                kill_sent=kill_sent, returncode=server.returncode, group_gone=True)


def finish_server_keys(server, private, term_timeout=10, kill_timeout=5):
    try:
        cleanup = stop_server(server, term_timeout, kill_timeout)
    except BaseException:
        print(f'owned server cleanup unknown; retain private test keys at {private}; pid={server.pid}', file=sys.stderr)
        raise
    shutil.rmtree(private)
    return cleanup

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sshd', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('ssh_matrix', Path(__file__).with_name('ssh-matrix.py'))
    matrix = importlib.util.module_from_spec(spec); spec.loader.exec_module(matrix)
    args.work.mkdir(parents=True, exist_ok=False)
    os.umask(0o077)
    private = Path(tempfile.mkdtemp(prefix='keys-', dir=args.work))
    server = None
    try:
        key = matrix.keygen(private/'operator')
        wrong = matrix.keygen(private/'other')
        auth = private/'authorized_keys'; auth.write_bytes(Path(str(key)+'.pub').read_bytes())
        port = matrix.free_port()
        with (args.work/'stdout').open('wb') as out, (args.work/'stderr').open('wb') as err:
            server = subprocess.Popen([str(args.sshd.resolve()), '--listen', f'127.0.0.1:{port}', '--host-key', str(private/'host'), '--authorized-keys', str(auth)], stdout=out, stderr=err, start_new_session=True)
            try:
                deadline = time.monotonic()+20
                while time.monotonic()<deadline:
                    text = (args.work/'stdout').read_text()+(args.work/'stderr').read_text()
                    public = re.search(r'SSH HOST KEY (?:GENERATED|LOADED) (ssh-ed25519 \S+)', text)
                    if public and 'SSH LISTENING' in text: break
                    if server.poll() is not None: raise AssertionError('server exited before readiness')
                    time.sleep(.05)
                else: raise AssertionError('server readiness timeout')
                client = matrix.Client(private, port)
                client.known_hosts.write_text(f'[127.0.0.1]:{port} {public[1]}\n')
                assert client.run(key, 'printf priority-ok', timeout=10)==(0,b'priority-ok',b'')
                assert client.run(key, 'exit 7', timeout=10)[0]==7
                assert client.run(wrong, 'true', timeout=10)[0]==255
                time.sleep(.1)
            finally:
                cleanup = finish_server_keys(server, private)
                (args.work/'cleanup.json').write_text(json.dumps(cleanup, indent=2)+'\n')
    finally:
        # Construction failed before a server existed. Once it exists, only
        # verified finish_server_keys may retire keys; unknown cleanup retains them.
        if server is None:
            shutil.rmtree(private)
    out=(args.work/'stdout').read_text(); err=(args.work/'stderr').read_text()
    for text in ('authenticated', 'exec "printf priority-ok"', 'session child exited: Code(0)', 'end: connection closed (defunct)'):
        assert text in out, f'routine activity missing from info/stdout: {text}'
        assert text not in err, f'routine activity leaked to warning/stderr: {text}'
    for text in ('session child exited: Code(7)', 'public key refused'):
        assert text in err and text not in out, f'failure no longer warning/stderr: {text}'
    print('REAL SSH PRIORITY PASS: routine info, failures stderr, guest command streams unchanged; owned server/keys retired')

if __name__ == '__main__': main()
