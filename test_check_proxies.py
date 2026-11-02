import contextlib
import io
import json
import socket
import struct
import threading
import tempfile
import unittest
from pathlib import Path

import check_proxies


class ProxyParsingTests(unittest.TestCase):
    def test_load_json_proxy_objects(self):
        data = [
            {
                "hostname": "proxy.example",
                "port": 443,
                "type": "MTPROTO",
                "secret": "0123456789abcdef0123456789abcdef",
            },
            {"hostname": "bad.example", "port": 70000, "secret": "bad"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "listOfProxy.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                proxies, invalid_count = check_proxies.load_proxies(path)

        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0].host, "proxy.example")
        self.assertEqual(invalid_count, 1)
        self.assertIn("Пропущено записей: 1", output.getvalue())

    def test_json_root_must_be_an_array(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "listOfProxy.json"
            path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "массивом"):
                check_proxies.load_proxies(path)

    def test_load_telegram_export_proxy_buttons(self):
        proxy_url = (
            "https://t.me/proxy?server=proxy.example&port=443&"
            "secret=0123456789abcdef0123456789abcdef"
        )
        unsupported_url = (
            "https://t.me/proxy?server=tls.example&port=443&"
            "secret=ee0123456789abcdef0123456789abcdef"
        )
        export = {
            "messages": [
                {"inline_bot_buttons": [[{"data": proxy_url}]]},
                {"inline_bot_buttons": [[{"data": proxy_url}]]},
                {"inline_bot_buttons": [[{"data": unsupported_url}]]},
                {"inline_bot_buttons": [[{"data": unsupported_url}]]},
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "listOfProxy.json"
            path.write_text(json.dumps(export), encoding="utf-8")
            proxies, invalid_count = check_proxies.load_proxies(path)

        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0].host, "proxy.example")
        self.assertEqual(invalid_count, 1)

    def test_malformed_json_reports_location(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "listOfProxy.json"
            path.write_text("[", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "строке"):
                check_proxies.load_proxies(path)

    def test_parse_host_port_secret(self):
        proxy = check_proxies.parse_proxy(
            "proxy.example:443:0123456789abcdef0123456789abcdef"
        )
        self.assertEqual(proxy, check_proxies.Proxy(
            "proxy.example", 443, "0123456789abcdef0123456789abcdef"
        ))

    def test_parse_tg_link_and_dd_secret(self):
        proxy = check_proxies.parse_proxy(
            "tg://proxy?server=proxy.example&port=80&secret=dd"
            "0123456789abcdef0123456789abcdef"
        )
        self.assertEqual(proxy.host, "proxy.example")
        self.assertEqual(proxy.port, 80)
        self.assertTrue(check_proxies.parse_secret(proxy.secret)[1])

    def test_parse_bracketed_ipv6(self):
        proxy = check_proxies.parse_proxy(
            "[2001:db8::1]:443:0123456789abcdef0123456789abcdef"
        )
        self.assertEqual(proxy.host, "2001:db8::1")

    def test_invalid_secret_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "32 hex"):
            check_proxies.parse_proxy("proxy.example:443:not-a-secret")

    def test_results_are_sorted_and_limited(self):
        proxies = [
            (check_proxies.Proxy(f"host{i}", 443, "0" * 32), float(i))
            for i in range(25)
        ]
        selected = check_proxies.select_fastest(list(reversed(proxies)))
        output = Path("test-proxy-results.txt")
        try:
            check_proxies.write_results(output, selected)
            rows = output.read_text(encoding="utf-8").splitlines()
            self.assertEqual(sum(row.startswith("https://t.me/proxy?") for row in rows), 20)
            self.assertIn("https://t.me/proxy?server=host0&port=443&secret=", rows[2])
            self.assertIn("ping=0.0 ms", rows[1])
            self.assertIn("https://t.me/proxy?server=host19&port=443&secret=", rows[-2])
        finally:
            output.unlink(missing_ok=True)

    def test_proxy_link_encodes_hostname_and_preserves_dd_secret(self):
        proxy = check_proxies.Proxy("proxy.example/path", 443, "dd" + "ab" * 16)
        output = Path("test-proxy-link.txt")
        try:
            check_proxies.write_results(output, [(proxy, 42.5)])
            contents = output.read_text(encoding="utf-8")
            self.assertIn(
                "https://t.me/proxy?server=proxy.example%2Fpath&port=443&secret="
                + proxy.secret,
                contents,
            )
            self.assertIn("MTPROTO", contents)
            self.assertIn("ping=42.5 ms", contents)
        finally:
            output.unlink(missing_ok=True)


class ProxyHandshakeTests(unittest.TestCase):
    def test_full_mtproto_probe_against_local_proxy(self):
        key = bytes.fromhex("0123456789abcdef0123456789abcdef")
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        errors = []

        def serve():
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(2)
                    header = self._recv_exact(conn, 64)
                    reverse = header[55:7:-1]
                    client_cipher = check_proxies.AesCtr(
                        check_proxies.hashlib.sha256(header[8:40] + key).digest(),
                        header[40:56],
                    )
                    keystream = client_cipher.process(bytes(64))
                    tag_and_dc = bytes(
                        value ^ mask
                        for value, mask in zip(header[56:64], keystream[56:64])
                    )
                    self.assertEqual(tag_and_dc[:4], b"\xee" * 4)
                    packet_length = struct.unpack(
                        "<I", client_cipher.process(self._recv_exact(conn, 4))
                    )[0]
                    request = client_cipher.process(self._recv_exact(conn, packet_length))
                    nonce = request[24:40]

                    response_body = struct.pack("<I", check_proxies.RES_PQ_CONSTRUCTOR) + nonce
                    response = struct.pack(
                        "<QqI", 0, int(check_proxies.time.time() * (1 << 32)) & ~3,
                        len(response_body),
                    ) + response_body
                    server_cipher = check_proxies.AesCtr(
                        check_proxies.hashlib.sha256(reverse[:32] + key).digest(),
                        reverse[32:48],
                    )
                    conn.sendall(server_cipher.process(struct.pack("<I", len(response)) + response))
            except Exception as exc:
                errors.append(exc)
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        proxy = check_proxies.Proxy("127.0.0.1", port, key.hex())
        try:
            ping = check_proxies.check_proxy(proxy, timeout=2)
            thread.join(timeout=2)
            self.assertFalse(errors, errors)
            self.assertGreaterEqual(ping, 0)
        finally:
            listener.close()

    @staticmethod
    def _recv_exact(conn, size):
        data = bytearray()
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise ConnectionError("unexpected EOF")
            data.extend(chunk)
        return bytes(data)


if __name__ == "__main__":
    unittest.main()
