import unittest

from sysnet_scout.system_info import bytes_to_human, collect_system_info


class TestSystemInfo(unittest.TestCase):
    def test_bytes_to_human(self) -> None:
        self.assertEqual(bytes_to_human(1024), "1.00 KB")
        self.assertEqual(bytes_to_human(None), "unknown")

    def test_collect_system_info_has_expected_keys(self) -> None:
        info = collect_system_info()
        expected_keys = {
            "tool",
            "author",
            "timestamp",
            "hostname",
            "local_ip",
            "mac_address",
            "os",
            "system",
            "release",
            "machine",
            "python",
            "cpu_cores_logical",
            "memory_total",
            "uptime",
            "processor",
            "time_zone",
        }
        self.assertTrue(expected_keys.issubset(info.keys()))


if __name__ == "__main__":
    unittest.main()
