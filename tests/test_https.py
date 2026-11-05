import datetime
import ipaddress
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from phase1 import transport


def test_real_tls_pinning_and_redirect(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "callback.example")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=1)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("callback.example")]), False
        )
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    received, sni = [], []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            received.append(
                (
                    self.path,
                    self.headers["Host"],
                    self.rfile.read(int(self.headers["Content-Length"])),
                )
            )
            self.send_response(302 if self.path == "/redirect" else 200)
            self.send_header("Location", "https://127.0.0.1/private")
            self.end_headers()
            if self.path == "/slow":
                try:
                    for _ in range(20):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                        time.sleep(0.02)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            else:
                self.wfile.write(b"{}")

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    context.set_servername_callback(lambda sock, name, ctx: sni.append(name))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client_context = ssl.create_default_context(cafile=cert_file)
    original_dns, original_dial = socket.getaddrinfo, transport.dial_ip
    monkeypatch.setattr(transport.ssl, "create_default_context", lambda: client_context)

    def dns(host, port, **kwargs):
        if host in ("callback.example", "wrong.example"):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
            ]
        return original_dns(host, port, **kwargs)

    monkeypatch.setattr(transport.socket, "getaddrinfo", dns)
    dialed = []

    def mapped_dial(address, timeout):
        assert ipaddress.ip_address(address[0]).is_global
        dialed.append(address)
        return original_dial(("127.0.0.1", server.server_port), timeout)

    monkeypatch.setattr(transport, "dial_ip", mapped_dial)
    try:
        body = json.dumps({"fixture": True}).encode()
        url = f"https://callback.example:{server.server_port}"
        assert transport.HTTPS().post(url + "/ok", body, {}) == (200, b"{}")
        assert transport.HTTPS().post(url + "/redirect", body, {}) == (302, b"{}")
        assert [row[0] for row in received] == ["/ok", "/redirect"]
        assert received[0][2] == body
        assert sni[:2] == ["callback.example", "callback.example"]
        assert all(address[0] == "93.184.216.34" for address in dialed)
        monkeypatch.setattr(transport, "REQUEST_TIMEOUT", 0.05)
        start = time.monotonic()
        with pytest.raises(OSError):
            transport.HTTPS().post(url + "/slow", body, {})
        assert time.monotonic() - start < 0.3
        with pytest.raises(ssl.SSLCertVerificationError):
            transport.HTTPS().post(
                f"https://wrong.example:{server.server_port}/", body, {}
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_dns_deadline(monkeypatch):
    import time

    monkeypatch.setattr(transport, "DNS_TIMEOUT", 0.02, raising=False)

    def stuck(*args, **kwargs):
        time.sleep(0.15)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(transport.socket, "getaddrinfo", stuck)
    start = time.monotonic()
    with pytest.raises(transport.DestinationError):
        transport.resolve_public("https://callback.example/")
    assert time.monotonic() - start < 0.1
