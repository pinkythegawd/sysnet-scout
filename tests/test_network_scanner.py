import unittest
from unittest.mock import Mock, patch

from sysnet_scout.network_scanner import (
    _extract_header,
    _extract_http_title,
    assess_risk,
    fingerprint_service,
    parse_port_spec,
    ping_host,
    scan_hosts,
    scan_ports,
    vulnerability_hints,
)


class TestParsePortSpec(unittest.TestCase):
    def test_parses_ports_and_ranges(self) -> None:
        ports = parse_port_spec("22,80,443,1-3")
        self.assertEqual(ports, [1, 2, 3, 22, 80, 443])

    def test_reversed_range_is_supported(self) -> None:
        ports = parse_port_spec("5-3")
        self.assertEqual(ports, [3, 4, 5])

    def test_invalid_input_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_port_spec("0,70000")


class TestHostScanner(unittest.TestCase):
    @patch("sysnet_scout.network_scanner.ping_host")
    def test_scan_hosts_uses_ping_and_filters_alive(self, mock_ping: Mock) -> None:
        # /30 has 2 usable hosts: .1 and .2
        mock_ping.side_effect = lambda ip, timeout_ms: ip.endswith(".1")
        alive = scan_hosts("192.168.1.0/30", timeout_ms=500, workers=4)
        self.assertEqual(alive, ["192.168.1.1"])

    @patch("sysnet_scout.network_scanner.subprocess.run")
    def test_ping_host_true_on_returncode_zero(self, mock_run: Mock) -> None:
        mock_run.return_value.returncode = 0
        self.assertTrue(ping_host("127.0.0.1", timeout_ms=100))

    @patch("sysnet_scout.network_scanner.subprocess.run")
    def test_ping_host_false_on_subprocess_error(self, mock_run: Mock) -> None:
        mock_run.side_effect = OSError("ping not available")
        self.assertFalse(ping_host("127.0.0.1", timeout_ms=100))

    @patch("sysnet_scout.network_scanner.ping_host")
    def test_scan_hosts_progress_callback(self, mock_ping: Mock) -> None:
        mock_ping.return_value = False
        updates = []

        def progress(done: int, total: int) -> None:
            updates.append((done, total))

        scan_hosts("192.168.1.0/30", timeout_ms=100, workers=2, progress_callback=progress)
        self.assertTrue(updates)
        self.assertEqual(updates[-1], (2, 2))


class TestPortScanner(unittest.TestCase):
    @patch("sysnet_scout.network_scanner.service_name")
    @patch("sysnet_scout.network_scanner._scan_single_port")
    def test_scan_ports_reports_open_ports(self, mock_scan_port: Mock, mock_service_name: Mock) -> None:
        open_set = {22, 443}
        mock_scan_port.side_effect = lambda host, port, timeout: port in open_set
        mock_service_name.side_effect = lambda port: {22: "ssh", 443: "https"}.get(port, "unknown")

        result = scan_ports("127.0.0.1", [22, 80, 443], timeout_s=0.1, workers=8)

        self.assertEqual(
            result,
            [
                {"port": "22", "service": "ssh"},
                {"port": "443", "service": "https"},
            ],
        )

    def test_scan_ports_empty_input(self) -> None:
        self.assertEqual(scan_ports("127.0.0.1", []), [])

    def test_vulnerability_hints_common_ports(self) -> None:
        hints = vulnerability_hints([
            {"port": "22", "service": "ssh"},
            {"port": "445", "service": "microsoft-ds"},
            {"port": "50000", "service": "unknown"},
        ])
        self.assertGreaterEqual(len(hints), 2)
        self.assertTrue(any("SSH" in hint for hint in hints))

    def test_assess_risk_returns_level(self) -> None:
        risk = assess_risk(
            [
                {"port": "23", "service": "telnet"},
                {"port": "445", "service": "microsoft-ds"},
            ],
            ["Telnet open: insecure plaintext protocol, migrate to SSH."],
        )
        self.assertIn(risk["level"], {"low", "medium", "high"})
        self.assertGreaterEqual(int(risk["score"]), 20)


class _FakeSocket:
    def __init__(self, recv_payloads):
        self._payloads = list(recv_payloads)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def settimeout(self, value):
        return None

    def connect_ex(self, target):
        return 0

    def sendall(self, data):
        return None

    def recv(self, size):
        if self._payloads:
            return self._payloads.pop(0)
        return b""


class TestFingerprinting(unittest.TestCase):
    def test_extract_http_title(self) -> None:
        text = "<html><head><title> Test Page </title></head></html>"
        self.assertEqual(_extract_http_title(text), "Test Page")

    def test_extract_header(self) -> None:
        text = "HTTP/1.1 200 OK\nServer: nginx\n"
        self.assertEqual(_extract_header(text, "Server"), "nginx")

    @patch("sysnet_scout.network_scanner.socket.socket")
    def test_fingerprint_http_includes_server_and_title(self, mock_socket: Mock) -> None:
        payload = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html><title>Hello</title></html>"
        mock_socket.return_value = _FakeSocket([payload])
        value = fingerprint_service("127.0.0.1", 80)
        self.assertIn("HTTP/1.1 200 OK", value)
        self.assertIn("server=nginx", value)
        self.assertIn("title=Hello", value)

    @patch("sysnet_scout.network_scanner.socket.socket")
    def test_fingerprint_ssh_banner(self, mock_socket: Mock) -> None:
        mock_socket.return_value = _FakeSocket([b"SSH-2.0-OpenSSH_9.0\r\n"])
        value = fingerprint_service("127.0.0.1", 22)
        self.assertIn("SSH-2.0", value)


if __name__ == "__main__":
    unittest.main()
