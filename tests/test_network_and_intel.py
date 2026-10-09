import io
import os
import socket
import struct
import threading
import time
import zipfile

import pytest

from sentinel_vision.engines.base import ScanObject
from sentinel_vision.engines.clamav import ClamAVEngine, parse_clamd_reply
from sentinel_vision.network.firewall import FirewallError, block_commands
from sentinel_vision.network.monitor import Connection
from sentinel_vision.network.threatintel import (
    IntelStore,
    parse_hash_list,
    parse_ip_list,
    parse_ip_port,
    parse_malwarebazaar_csv,
    parse_spamhaus_json,
)
from sentinel_vision.updater import extract_yara_zip


def test_ip_parsers():
    assert parse_ip_list("# c\n1.2.3.4\n10.0.0.0/8 ; comment\nbad\n2001:db8::/32\n") == [
        "1.2.3.4/32",
        "10.0.0.0/8",
        "2001:db8::/32",
    ]
    assert parse_spamhaus_json('{"cidr":"5.6.0.0/16","sblid":"x"}\n{"type":"metadata"}\n') == ["5.6.0.0/16"]
    assert parse_ip_port('"2024-01-01","1","9.9.9.9:443","ip:port"\n') == ["9.9.9.9/32"]


def test_hash_parsers():
    sha = "a" * 64
    assert parse_hash_list(f"# x\n{sha}\nnot-a-hash\n{'b' * 32}\n") == [
        (sha, "Malware.Generic"),
        ("b" * 32, "Malware.Generic"),
    ]
    csv_text = (
        '# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess",'
        '"mime_type","signature"\n'
        f'"2026-10-01 00:00:00", "{sha}", "{"c" * 32}", "{"d" * 40}", "x", "a.exe", "exe", "app", "AgentTesla"\n'
    )
    rows = parse_malwarebazaar_csv(csv_text)
    assert (sha, "MalwareBazaar.AgentTesla") in rows and len(rows) == 3


def test_intel_lookup(isolated_home):
    store = IntelStore()
    store.save_feed("Test Feed", ["203.0.113.0/24", "198.51.100.7/32", "2001:db8::/32"])
    store.reload()
    assert store.lookup("203.0.113.200") == "Test Feed"
    assert store.lookup("198.51.100.7") == "Test Feed"
    assert store.lookup("198.51.100.8") is None
    assert store.lookup("::ffff:203.0.113.1") == "Test Feed"
    assert store.lookup("2001:db8::1") == "Test Feed"
    assert store.lookup("garbage") is None


def test_network_classification(sentinel):
    sentinel.intel.add_runtime("203.0.113.0/24", "unit")
    c = Connection("TCP", "10.0.0.2:5000", "203.0.113.9:443", "203.0.113.9", 443, 5000, "ESTABLISHED", 1)
    sentinel.network.classify(c)
    assert c.severity == 3 and "unit" in c.threat
    sentinel.network.whitelist.add("203.0.113.9")
    c2 = Connection("TCP", "10.0.0.2:5000", "203.0.113.9:443", "203.0.113.9", 443, 5000, "ESTABLISHED", 1)
    sentinel.network.classify(c2)
    assert c2.severity == -1


def test_network_poll_snapshot(sentinel):
    sentinel.network.poll()
    time.sleep(0.2)
    snap = sentinel.network.poll()
    assert snap.total_recv >= 0 and isinstance(snap.connections, list)
    assert len(sentinel.network.snapshot().history) == 2


def test_firewall_validation():
    with pytest.raises(FirewallError):
        block_commands("10.0.0.1")
    with pytest.raises(FirewallError):
        block_commands("1.2.3.4; rm -rf /")
    with pytest.raises(FirewallError):
        block_commands("127.0.0.1")


def test_yara_zip_extraction_is_traversal_safe(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../evil.yar", "rule a { condition: true }")
        z.writestr("pkg/good.yar", "rule b { condition: true }")
        z.writestr("pkg/run.sh", "echo no")
    dest = tmp_path / "out"
    dest.mkdir()
    assert extract_yara_zip(buf.getvalue(), dest) == 2
    assert sorted(p.name for p in dest.iterdir()) == ["evil.yar", "good.yar"]
    assert not (tmp_path / "evil.yar").exists()


def test_clamd_reply_parsing():
    assert parse_clamd_reply("stream: OK\0") is None
    assert parse_clamd_reply("stream: Win.Test.EICAR_HDB-1 FOUND\0") == "Win.Test.EICAR_HDB-1"
    assert parse_clamd_reply("/a: b/c.exe: Eicar-Signature FOUND") == "Eicar-Signature"


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX") or os.name == "nt", reason="unix sockets")
def test_clamd_instream_protocol(tmp_path, eicar):
    """A tiny fake clamd proves the INSTREAM framing is correct."""
    import tempfile

    # AF_UNIX paths are limited to ~104 bytes on macOS, so use a short directory
    path = os.path.join(tempfile.mkdtemp(prefix="sv", dir="/tmp"), "c.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(5)

    def serve():
        for _ in range(3):
            conn, _ = srv.accept()
            with conn:
                cmd = b""
                while not cmd.endswith(b"\0"):
                    cmd += conn.recv(1)
                if cmd == b"zPING\0":
                    conn.sendall(b"PONG\0")
                    continue
                data = b""
                while True:
                    (n,) = struct.unpack("!L", conn.recv(4, socket.MSG_WAITALL))
                    if n == 0:
                        break
                    data += conn.recv(n, socket.MSG_WAITALL)
                conn.sendall(b"stream: Eicar-Test-Signature FOUND\0" if b"EICAR" in data else b"stream: OK\0")

    threading.Thread(target=serve, daemon=True).start()
    eng = ClamAVEngine(path)
    assert eng.available()
    assert eng.scan(ScanObject("e", data=eicar))[0].name == "Eicar-Test-Signature"
    assert eng.scan(ScanObject("c", data=b"clean" * 100000)) == []
    srv.close()
