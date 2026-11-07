"""Independent Linux ssl/OpenSSL peer. Operator supplies external test credentials."""
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import stat


def publish(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x", encoding="ascii") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())
    os.link(temporary, path)
    temporary.unlink()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--leaf-der", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--mode", choices=["happy", "duplicate", "short", "truncate", "extra", "partial", "indirect", "crossing"], required=True)
    args = parser.parse_args()
    key = args.key.stat()
    if key.st_uid != os.getuid() or stat.S_IMODE(key.st_mode) & 0o077:
        raise RuntimeError("operator key must be owner-only")
    certificate = args.certificate.read_text(encoding="ascii")
    certificate_count = 2 if args.mode == "indirect" else 1
    parts = certificate.split("-----END CERTIFICATE-----")
    if (len(parts) != certificate_count + 1 or parts[-1].strip()
            or certificate.count("-----BEGIN CERTIFICATE-----") != certificate_count):
        raise RuntimeError("provide the exact selected leaf/chain count")
    blocks = [part.strip() + "-----END CERTIFICATE-----" for part in parts[:-1]]
    if any(not block.startswith("-----BEGIN CERTIFICATE-----") for block in blocks):
        raise RuntimeError("certificate PEM framing differs")
    decoded = [ssl.PEM_cert_to_DER_cert(block) for block in blocks]
    if decoded[0] != args.leaf_der.read_bytes():
        raise RuntimeError("public leaf PEM and DER differ")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(args.certificate, args.key)
    result = {"mode": args.mode, "certificate_count": certificate_count, "sni": "", "tls": "", "alpn": "", "request_hex": "",
              "response_sent": 0, "complete_get": False, "tls_closed": False, "exception": ""}
    context.set_servername_callback(lambda _socket, name, _context: result.update(sni=name or ""))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        port = listener.getsockname()[1]
        publish(args.directory / "READY", str(port) + "\n")
        connection = None
        try:
            raw, _address = listener.accept()
            raw.settimeout(3)
            connection = context.wrap_socket(raw, server_side=True)
            result.update(tls=connection.version(), alpn=connection.selected_alpn_protocol() or "")
            request = bytearray()
            while not request.endswith(b"\r\n\r\n"):
                data = connection.recv(1)
                if not data or len(request) >= 4096:
                    raise RuntimeError("incomplete or oversized GET")
                request.extend(data)
                result["request_hex"] = request.hex()
            expected = (f"GET /document.bin?edition=1 HTTP/1.1\r\nHost: document.example:{port}\r\n"
                        "Connection: close\r\n\r\n").encode("ascii")
            if bytes(request) != expected:
                raise RuntimeError("decrypted GET differs")
            result["complete_get"] = True
            body = bytes(range(256)) + bytes([0, 255, 13, 10])
            header = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n".encode("ascii")
            if args.mode == "duplicate":
                header += f"Content-Length: {len(body)}\r\n".encode("ascii")
            header += b"\r\n"
            if args.mode == "partial":
                # Keep the body incomplete and send no close_notify. The client
                # must enter Body before its callback expires/cancels the run.
                response = header + body[:7]
            elif args.mode in {"short", "truncate"}:
                response = header + body[:-1]
            else:
                response = header + body + (b"x" if args.mode == "extra" else b"")
            connection.sendall(response)
            result["response_sent"] = len(response)
            if args.mode == "truncate":
                descriptor = connection.detach()
                socket.socket(fileno=descriptor).close()  # Actual TCP EOF without TLS close_notify.
                connection = None
            elif args.mode == "partial":
                # Only client cancellation/expiry closes this bounded read.
                if connection.recv(1):
                    raise RuntimeError("unexpected extra plaintext")
            else:
                raw = connection.unwrap()
                result["tls_closed"] = True
                raw.close()
                connection = None
        except (ssl.SSLError, EOFError, TimeoutError, ConnectionError) as error:
            result["exception"] = type(error).__name__
        finally:
            if connection is not None:
                connection.close()
            publish(args.directory / "RESULT.json", json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
