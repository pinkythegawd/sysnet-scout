import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from sysnet_scout.cli import main


class TestCli(unittest.TestCase):
    def test_info_json_output(self) -> None:
        stream = io.StringIO()
        with redirect_stdout(stream):
            exit_code = main(["info", "--json"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(stream.getvalue())
        self.assertIn("tool", payload)
        self.assertIn("author", payload)

    def test_start_choice_info_json_output(self) -> None:
        stream = io.StringIO()
        with redirect_stdout(stream):
            exit_code = main(["start", "--choice", "info", "--json"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(stream.getvalue())
        self.assertIn("tool", payload)

    def test_demo_mode_generates_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                stream = io.StringIO()
                with redirect_stdout(stream):
                    exit_code = main(["demo", "--json"])
                self.assertEqual(exit_code, 0)
                payload = json.loads(stream.getvalue())
                self.assertEqual(payload["mode"], "demo")
                self.assertTrue(os.path.exists(os.path.join(tmp, "reports", "demo_dashboard.html")))
            finally:
                os.chdir(old_cwd)

    @patch("sysnet_scout.cli.scan_hosts")
    def test_scan_hosts_json_output(self, mock_scan_hosts: Mock) -> None:
        mock_scan_hosts.return_value = ["192.168.1.10", "192.168.1.20"]
        stream = io.StringIO()
        with redirect_stdout(stream):
            exit_code = main(["scan-hosts", "--cidr", "192.168.1.0/24", "--json"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(stream.getvalue())
        self.assertEqual(payload["target"], "192.168.1.0/24")
        self.assertEqual(payload["count"], 2)

    @patch("sysnet_scout.cli.scan_ports")
    def test_scan_ports_json_output(self, mock_scan_ports: Mock) -> None:
        mock_scan_ports.return_value = [{"port": "443", "service": "https"}]
        stream = io.StringIO()
        with redirect_stdout(stream):
            exit_code = main(
                ["scan-ports", "--host", "127.0.0.1", "--ports", "443", "--json"]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stream.getvalue())
        self.assertEqual(payload["target"], "127.0.0.1")
        self.assertEqual(payload["open_ports"], [{"port": "443", "service": "https"}])

    @patch("sysnet_scout.cli.scan_ports")
    def test_scan_ports_top_preset(self, mock_scan_ports: Mock) -> None:
        mock_scan_ports.return_value = []
        stream = io.StringIO()
        with redirect_stdout(stream):
            exit_code = main(
                ["scan-ports", "--host", "127.0.0.1", "--top", "20", "--json"]
            )

        self.assertEqual(exit_code, 0)
        called_ports = mock_scan_ports.call_args.kwargs["ports"]
        self.assertEqual(len(called_ports), 20)

    @patch("sysnet_scout.cli.scan_ports")
    def test_scan_ports_profile_web(self, mock_scan_ports: Mock) -> None:
        mock_scan_ports.return_value = []
        stream = io.StringIO()
        with redirect_stdout(stream):
            exit_code = main(
                ["scan-ports", "--host", "127.0.0.1", "--profile", "web", "--json"]
            )

        self.assertEqual(exit_code, 0)
        called_ports = mock_scan_ports.call_args.kwargs["ports"]
        self.assertIn(80, called_ports)
        self.assertIn(443, called_ports)

    @patch("sysnet_scout.cli.vulnerability_hints")
    @patch("sysnet_scout.cli.fingerprint_service")
    @patch("sysnet_scout.cli.scan_ports")
    def test_scan_ports_with_fingerprint_and_hints(
        self,
        mock_scan_ports: Mock,
        mock_fingerprint: Mock,
        mock_hints: Mock,
    ) -> None:
        mock_scan_ports.return_value = [{"port": "443", "service": "https"}]
        mock_fingerprint.return_value = "HTTP/1.1 200 OK"
        mock_hints.return_value = ["HTTP open: ensure HTTPS redirect and remove sensitive debug endpoints."]

        stream = io.StringIO()
        with redirect_stdout(stream):
            exit_code = main(
                [
                    "scan-ports",
                    "--host",
                    "127.0.0.1",
                    "--ports",
                    "443",
                    "--fingerprint",
                    "--hints",
                    "--json",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stream.getvalue())
        self.assertTrue(payload["fingerprinting"])
        self.assertTrue(payload["hints_enabled"])
        self.assertEqual(payload["open_ports"][0]["banner"], "HTTP/1.1 200 OK")
        self.assertEqual(len(payload["hints"]), 1)
        self.assertIn("risk", payload)
        self.assertIn("score", payload["risk"])
        self.assertIn("level", payload["risk"])

    @patch("sysnet_scout.cli._resolve_target")
    def test_resolve_json_output(self, mock_resolve: Mock) -> None:
        mock_resolve.return_value = {
            "target": "example.com",
            "aliases": ["www.example.com"],
            "resolved_ips": ["93.184.216.34"],
            "reverse_lookup": "example.com",
        }
        stream = io.StringIO()
        with redirect_stdout(stream):
            exit_code = main(["resolve", "--target", "example.com", "--json"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(stream.getvalue())
        self.assertEqual(payload["target"], "example.com")
        self.assertIn("93.184.216.34", payload["resolved_ips"])

    def test_info_save_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_path = f"{tmp}/info.json"
            stream = io.StringIO()
            with redirect_stdout(stream):
                exit_code = main(["info", "--json", "--save", out_path])

            self.assertEqual(exit_code, 0)
            with open(out_path, "r", encoding="utf-8") as saved:
                payload = json.load(saved)
            self.assertIn("tool", payload)

    def test_info_export_json_by_extension_without_json_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_path = f"{tmp}/auto.json"
            stream = io.StringIO()
            with redirect_stdout(stream):
                exit_code = main(["info", "--export", out_path])

            self.assertEqual(exit_code, 0)
            with open(out_path, "r", encoding="utf-8") as saved:
                payload = json.load(saved)
            self.assertIn("tool", payload)

    def test_resolve_export_txt_writes_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_path = f"{tmp}/resolve.txt"
            stream = io.StringIO()
            with redirect_stdout(stream):
                exit_code = main(["--no-color", "resolve", "--target", "example.com", "--export", out_path])

            self.assertEqual(exit_code, 0)
            with open(out_path, "r", encoding="utf-8") as saved:
                content = saved.read()
            self.assertIn("target", content)

    def test_info_export_html_writes_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_path = f"{tmp}/info.html"
            stream = io.StringIO()
            with redirect_stdout(stream):
                exit_code = main(["info", "--export", out_path])

            self.assertEqual(exit_code, 0)
            with open(out_path, "r", encoding="utf-8") as saved:
                content = saved.read()
            self.assertIn("<html", content.lower())

    def test_compare_host_scan_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            baseline_path = f"{tmp}/baseline.json"
            current_path = f"{tmp}/current.json"
            with open(baseline_path, "w", encoding="utf-8") as baseline_file:
                json.dump({"alive_hosts": ["192.168.1.10"]}, baseline_file)
            with open(current_path, "w", encoding="utf-8") as current_file:
                json.dump({"alive_hosts": ["192.168.1.10", "192.168.1.20"]}, current_file)

            stream = io.StringIO()
            with redirect_stdout(stream):
                exit_code = main(
                    ["compare", "--baseline", baseline_path, "--current", current_path, "--json"]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stream.getvalue())
            self.assertEqual(payload["type"], "host-scan")
            self.assertEqual(payload["added_hosts"], ["192.168.1.20"])

    def test_risk_summary_from_saved_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = f"{tmp}/ports.json"
            with open(report_path, "w", encoding="utf-8") as report_file:
                json.dump(
                    {
                        "target": "192.168.1.10",
                        "open_ports": [{"port": "445", "service": "microsoft-ds"}],
                        "hints": ["SMB open: patch regularly and restrict to trusted LAN ranges."],
                    },
                    report_file,
                )

            stream = io.StringIO()
            with redirect_stdout(stream):
                exit_code = main(["risk", "--report", report_path, "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stream.getvalue())
            self.assertEqual(payload["target"], "192.168.1.10")
            self.assertIn("risk", payload)
            self.assertIn("level", payload["risk"])

    def test_risk_export_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = f"{tmp}/ports.json"
            out_path = f"{tmp}/risk.html"
            with open(report_path, "w", encoding="utf-8") as report_file:
                json.dump({"target": "x", "open_ports": []}, report_file)

            stream = io.StringIO()
            with redirect_stdout(stream):
                exit_code = main(["risk", "--report", report_path, "--export", out_path])

            self.assertEqual(exit_code, 0)
            with open(out_path, "r", encoding="utf-8") as saved:
                content = saved.read().lower()
            self.assertIn("<html", content)

    def test_risk_trend_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_a = f"{tmp}/a.json"
            report_b = f"{tmp}/b.json"
            with open(report_a, "w", encoding="utf-8") as a_file:
                json.dump({"target": "x", "open_ports": [{"port": "23", "service": "telnet"}]}, a_file)
            with open(report_b, "w", encoding="utf-8") as b_file:
                json.dump({"target": "x", "open_ports": []}, b_file)

            stream = io.StringIO()
            with redirect_stdout(stream):
                exit_code = main(
                    [
                        "risk-trend",
                        "--reports",
                        report_a,
                        report_b,
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stream.getvalue())
            self.assertEqual(payload["report_count"], 2)
            self.assertIn(payload["trend"], {"improved", "stable", "worse"})
            self.assertEqual(len(payload["snapshots"]), 2)

    def test_risk_trend_sorts_by_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old_report = f"{tmp}/old.json"
            new_report = f"{tmp}/new.json"
            with open(old_report, "w", encoding="utf-8") as old_file:
                json.dump(
                    {
                        "target": "x",
                        "timestamp": "2026-03-13T10:00:00Z",
                        "open_ports": [{"port": "23", "service": "telnet"}],
                    },
                    old_file,
                )
            with open(new_report, "w", encoding="utf-8") as new_file:
                json.dump(
                    {
                        "target": "x",
                        "timestamp": "2026-03-13T12:00:00Z",
                        "open_ports": [],
                    },
                    new_file,
                )

            stream = io.StringIO()
            with redirect_stdout(stream):
                exit_code = main(
                    [
                        "risk-trend",
                        "--reports",
                        new_report,
                        old_report,
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stream.getvalue())
            self.assertEqual(payload["snapshots"][0]["report_file"], old_report)
            self.assertEqual(payload["snapshots"][1]["report_file"], new_report)

    def test_scan_ports_invalid_port_spec_exits(self) -> None:
        with self.assertRaises(SystemExit) as context:
            main(["scan-ports", "--host", "127.0.0.1", "--ports", "abc", "--json"])
        self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
