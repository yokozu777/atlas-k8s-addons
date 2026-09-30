"""TSIG probe signs a no-op UPDATE and treats BIND rejection as failure."""

from __future__ import annotations

import base64
import importlib.util
import socket
import struct
import threading
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROBE = REPO_ROOT / "roles" / "common" / "files" / "check_tsig.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_tsig", PROBE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TsigProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe = _load()

    def test_roles_check_tsig_before_dns_tasks(self):
        expected = {
            "roles/530_external_dns/tasks/main.yaml": [
                "k8s_secrets.external_dns_tsig_secret",
                "k8s_secrets.external_dns_apex_tsig_secret",
            ],
            "roles/540_cert_manager/tasks/main.yaml": [
                "k8s_secrets.external_dns_tsig_secret",
            ],
            "roles/560_apply_ingress/tasks/main.yaml": [
                "k8s_secrets.external_dns_tsig_secret",
            ],
            "roles/720_external_dns_istio/tasks/main.yaml": [
                "k8s_secrets.external_dns_istio_tsig_secret",
            ],
        }
        for rel, secrets in expected.items():
            text = (REPO_ROOT / rel).read_text(encoding="utf-8")
            check = text.find("assert_tsig_key.yaml")
            self.assertGreater(check, 0, rel)
            if "560_apply_ingress" in rel:
                later = text.find("Wait for wildcard Certificate Ready")
            else:
                later = text.find("Helming")
            self.assertGreater(later, check, rel)
            for secret in secrets:
                self.assertIn(secret, text, rel)

    def test_signature_matches_dnspython(self):
        try:
            import dns.message
            import dns.tsigkeyring
        except ImportError:
            self.skipTest("dnspython is not installed")
        secret_b64 = "dGVzdC1rZXktbWF0ZXJpYWwtdGhhdC1pcy1sb25nLWVub3VnaA=="
        secret = base64.b64decode(secret_b64)
        wire = self.probe.build_update(
            "k8s.example.com",
            "k8s.example.com-key",
            secret,
            now=int(time.time()),
            msgid=0x1A2B,
        )
        keyring = dns.tsigkeyring.from_text({"k8s.example.com-key": secret_b64})
        message = dns.message.from_wire(wire, keyring=keyring)
        self.assertEqual(message.id, 0x1A2B)

    def test_badsig_is_bad_authentication(self):
        response = struct.pack("!HHHHHH", 1, 0x8009, 0, 0, 0, 1) + struct.pack(
            "!HHH", 0x1A2B, 16, 0
        )
        self.assertEqual(self.probe.rejection_reason(response), "bad authentication")

    def test_noerror_is_accepted(self):
        response = struct.pack("!HHHHHH", 1, 0x8000, 0, 0, 0, 1) + struct.pack(
            "!HHH", 0x1A2B, 0, 0
        )
        self.assertIsNone(self.probe.rejection_reason(response))

    def test_live_socket_reports_rejection(self):
        secret_b64 = "dGVzdC1rZXktbWF0ZXJpYWwtdGhhdC1pcy1sb25nLWVub3VnaA=="
        payload = self.probe.build_update(
            "example.com",
            "example.com",
            base64.b64decode(secret_b64),
            now=1_700_000_000,
            msgid=0x22,
        )
        reply = struct.pack("!HHHHHH", 0x22, 0x8009, 0, 0, 0, 1) + struct.pack(
            "!HHH", 0x22, 16, 0
        )

        def serve(sock):
            conn, _addr = sock.accept()
            with conn:
                prefix = conn.recv(2)
                size = struct.unpack("!H", prefix)[0]
                got = b""
                while len(got) < size:
                    got += conn.recv(size - len(got))
                self.assertEqual(got, payload)
                conn.sendall(struct.pack("!H", len(reply)) + reply)

        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        thread = threading.Thread(target=serve, args=(server,))
        thread.start()
        try:
            response = self.probe.query("127.0.0.1", port, payload, timeout=5)
        finally:
            thread.join(5)
            server.close()
        self.assertEqual(self.probe.rejection_reason(response), "bad authentication")


if __name__ == "__main__":
    unittest.main()
