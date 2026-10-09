import os

import pytest

from sentinel_vision.quarantine import Quarantine, QuarantineError


def test_roundtrip_multi_chunk(workdir):
    q = Quarantine()
    data = os.urandom(3 * 1024 * 1024 + 123)
    f = workdir / "sample.bin"
    f.write_bytes(data)
    item = q.add(f, "Test.Threat", "hash")
    assert not f.exists()
    vault = q.root / f"{item.id}.svq"
    assert data[:64] not in vault.read_bytes()  # really encrypted
    restored = q.restore(item.id)
    assert restored.read_bytes() == data
    assert q.list() == []


def test_empty_file(workdir):
    q = Quarantine()
    f = workdir / "empty"
    f.write_bytes(b"")
    item = q.add(f, "T", "hash")
    assert q.restore(item.id).read_bytes() == b""


def test_tampering_is_detected(workdir):
    q = Quarantine()
    f = workdir / "s.bin"
    f.write_bytes(b"A" * 5000)
    item = q.add(f, "T", "yara")
    vault = q.root / f"{item.id}.svq"
    raw = bytearray(vault.read_bytes())
    raw[40] ^= 0xFF
    vault.write_bytes(bytes(raw))
    with pytest.raises(QuarantineError):
        q.restore(item.id)
    assert not f.exists()  # nothing half-written to the destination


def test_truncation_is_detected(workdir):
    q = Quarantine()
    f = workdir / "s.bin"
    f.write_bytes(os.urandom(2 * 1024 * 1024 + 10))
    item = q.add(f, "T", "yara")
    vault = q.root / f"{item.id}.svq"
    data = vault.read_bytes()
    first_chunk_end = 12 + 5 + (1024 * 1024 + 16)
    vault.write_bytes(data[:first_chunk_end])  # drop trailing chunks
    with pytest.raises(QuarantineError):
        q.restore(item.id)


def test_restore_does_not_overwrite(workdir):
    q = Quarantine()
    f = workdir / "doc.txt"
    f.write_text("original")
    item = q.add(f, "T", "hash")
    f.write_text("new file with same name")
    out = q.restore(item.id)
    assert out != f and f.read_text() == "new file with same name"
    assert out.read_text() == "original"


def test_invalid_ids_rejected():
    q = Quarantine()
    with pytest.raises(QuarantineError):
        q.get("../../etc/passwd")
