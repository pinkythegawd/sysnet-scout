from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Sequence


def ping_host(ip_address: str, timeout_ms: int = 1000) -> bool:
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip_address]
    else:
        timeout_s = max(1, int(timeout_ms / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip_address]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return result.returncode == 0
    except (OSError, ValueError):
        return False


def scan_hosts(
    cidr: str,
    timeout_ms: int = 1000,
    workers: int = 64,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> List[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(host) for host in network.hosts()]
    if not hosts:
        return []

    alive_hosts: List[str] = []
    max_workers = max(1, min(workers, len(hosts)))

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(ping_host, host, timeout_ms): host
            for host in hosts
        }
        processed = 0
        total = len(futures)
        for future in as_completed(futures):
            host = futures[future]
            try:
                if future.result():
                    alive_hosts.append(host)
            except Exception:
                continue
            finally:
                processed += 1
                if progress_callback:
                    progress_callback(processed, total)

    return sorted(alive_hosts, key=lambda ip: tuple(int(x) for x in ip.split(".")))


def parse_port_spec(port_spec: str) -> List[int]:
    ports = set()
    for chunk in port_spec.split(","):
        value = chunk.strip()
        if not value:
            continue
        if "-" in value:
            start_s, end_s = value.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            if start > end:
                start, end = end, start
            for port in range(start, end + 1):
                if 1 <= port <= 65535:
                    ports.add(port)
        else:
            port = int(value)
            if 1 <= port <= 65535:
                ports.add(port)

    if not ports:
        raise ValueError("No valid ports were provided.")

    return sorted(ports)


def _scan_single_port(host: str, port: int, timeout_s: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout_s)
        return sock.connect_ex((host, port)) == 0


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def _extract_http_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:90]


def _extract_header(text: str, key: str) -> str:
    for line in text.splitlines():
        if line.lower().startswith(key.lower() + ":"):
            return line.split(":", 1)[1].strip()[:120]
    return ""


def _first_line(text: str) -> str:
    line = text.splitlines()[0].strip() if text.splitlines() else ""
    return line[:120]


def fingerprint_service(host: str, port: int, timeout_s: float = 0.8) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout_s)
            if sock.connect_ex((host, port)) != 0:
                return ""

            if port in (80, 8080, 8000, 8008, 8081, 8443, 8888, 9000, 3000):
                request = b"GET / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n"
                sock.sendall(request)
                data = sock.recv(2048)
                text = data.decode("utf-8", errors="replace").replace("\r", "")
                status = _first_line(text)
                server = _extract_header(text, "Server")
                title = _extract_http_title(text)
                parts = [part for part in [status, f"server={server}" if server else "", f"title={title}" if title else ""] if part]
                return " | ".join(parts)[:160]

            if port in (25, 587, 2525):
                banner = sock.recv(512)
                sock.sendall(b"EHLO sysnet-scout.local\r\n")
                ehlo = sock.recv(1024)
                text = (banner + b"\n" + ehlo).decode("utf-8", errors="replace").replace("\r", "")
                first = _first_line(text)
                return first or "SMTP service detected"

            if port == 6379:
                sock.sendall(b"*1\r\n$4\r\nPING\r\n")
                data = sock.recv(256)
                text = data.decode("utf-8", errors="replace").strip()
                return text[:120]

            data = sock.recv(512)
            text = data.decode("utf-8", errors="replace").strip().replace("\r", "")
            if not text:
                return ""
            first_line = _first_line(text)
            if first_line.startswith("SSH-"):
                return first_line

            return first_line
    except OSError:
        return ""


def vulnerability_hints(open_port_items: Sequence[Dict[str, str]]) -> List[str]:
    hints: List[str] = []
    open_ports = {int(item.get("port", "0")) for item in open_port_items if item.get("port", "0").isdigit()}

    mapping = {
        21: "FTP open: prefer SFTP/FTPS and disable anonymous access.",
        22: "SSH open: enforce key auth, disable password login, and restrict source IPs.",
        23: "Telnet open: insecure plaintext protocol, migrate to SSH.",
        80: "HTTP open: ensure HTTPS redirect and remove sensitive debug endpoints.",
        139: "NetBIOS open: review file-share exposure and SMB hardening.",
        445: "SMB open: patch regularly and restrict to trusted LAN ranges.",
        3389: "RDP open: use VPN/NLA and strong access controls.",
        3306: "MySQL open: avoid internet exposure and require strong credentials.",
        5432: "PostgreSQL open: restrict network access and enforce TLS/auth controls.",
        6379: "Redis open: avoid public exposure unless auth/TLS and ACLs are configured.",
        27017: "MongoDB open: do not expose publicly without auth and network controls.",
    }

    for port in sorted(open_ports):
        hint = mapping.get(port)
        if hint:
            hints.append(hint)

    if open_ports and any(port > 49151 for port in open_ports):
        hints.append("High ephemeral ports are open: verify if services are intentionally exposed.")

    return hints


def assess_risk(open_port_items: Sequence[Dict[str, str]], hint_items: Sequence[str]) -> Dict[str, object]:
    score = 0
    reasons: List[str] = []

    critical_ports = {23, 445, 3389, 6379, 27017}
    high_ports = {21, 22, 80, 139, 1433, 3306, 5432}

    open_ports = []
    for item in open_port_items:
        port_str = str(item.get("port", ""))
        if port_str.isdigit():
            open_ports.append(int(port_str))

    for port in sorted(set(open_ports)):
        if port in critical_ports:
            score += 20
            reasons.append(f"Sensitive service exposed on port {port}.")
        elif port in high_ports:
            score += 12
            reasons.append(f"Potentially risky service exposed on port {port}.")
        else:
            score += 2

    for hint in hint_items:
        score += 4
        if len(reasons) < 6:
            reasons.append(hint)

    for item in open_port_items:
        banner = str(item.get("banner", "")).lower()
        if not banner:
            continue
        if "apache/2.2" in banner or "iis/6" in banner:
            score += 15
            reasons.append("Fingerprint suggests potentially outdated web server stack.")
        if "telnet" in banner:
            score += 10
            reasons.append("Plaintext remote management indication in fingerprint.")

    score = min(100, score)
    if score >= 70:
        level = "high"
    elif score >= 35:
        level = "medium"
    else:
        level = "low"

    return {
        "score": score,
        "level": level,
        "reasons": reasons[:10],
    }


def scan_ports(
    host: str,
    ports: Sequence[int],
    timeout_s: float = 0.5,
    workers: int = 256,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> List[Dict[str, str]]:
    if not ports:
        return []

    max_workers = max(1, min(workers, len(ports)))
    open_ports: List[Dict[str, str]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_scan_single_port, host, port, timeout_s): port
            for port in ports
        }
        processed = 0
        total = len(futures)
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(
                        {
                            "port": str(port),
                            "service": service_name(port),
                        }
                    )
            except Exception:
                continue
            finally:
                processed += 1
                if progress_callback:
                    progress_callback(processed, total)

    return sorted(open_ports, key=lambda item: int(item["port"]))
