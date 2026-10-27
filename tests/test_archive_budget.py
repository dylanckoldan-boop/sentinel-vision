"""Audit finding SV-F05: listing a compressed tar archive has a decompression byte and time budget."""

import io
import lzma
import tarfile

from sentinel_vision import scanner as scanner_mod


def _tar_xz(path, member_mb=50):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        info = tarfile.TarInfo("zeros.bin")
        info.size = member_mb * 1024 * 1024
        tf.addfile(info, io.BytesIO(b"\0" * info.size))
        tail = tarfile.TarInfo("after.txt")
        tail.size = 5
        tf.addfile(tail, io.BytesIO(b"hello"))
    path.write_bytes(lzma.compress(raw.getvalue()))
    return path


def test_listing_stops_at_the_byte_budget(sentinel, tmp_path, monkeypatch):
    archive = _tar_xz(tmp_path / "big.tar.xz")
    sentinel.settings.archive_bomb_total_mb = 1
    read = []
    real = scanner_mod.CountingReader.read

    def counting(self, n=-1):
        data = real(self, n)
        read.append(len(data))
        return data

    monkeypatch.setattr(scanner_mod.CountingReader, "read", counting)
    res = sentinel.scanner.scan_file(archive, act=False)[0]
    assert [d.name for d in res.detections] == ["Archive.LimitReached"]
    assert res.detections[0].details.get("report_only")  # an item to review, never a threat
    assert sum(read) <= 2 * 1024 * 1024


def test_listing_stops_at_the_time_budget(sentinel, tmp_path, monkeypatch):
    archive = _tar_xz(tmp_path / "slow.tar.xz", member_mb=8)
    monkeypatch.setattr(scanner_mod, "LIST_SECONDS", 1e-9)
    res = sentinel.scanner.scan_file(archive, act=False)[0]
    assert [d.name for d in res.detections] == ["Archive.LimitReached"]


def test_ordinary_compressed_tars_are_still_scanned(sentinel, tmp_path, eicar):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tf:
        info = tarfile.TarInfo("inner/eicar.com")
        info.size = len(eicar)
        tf.addfile(info, io.BytesIO(eicar))
    p = tmp_path / "pack.tar.gz"
    p.write_bytes(raw.getvalue())
    results = sentinel.scanner.scan_file(p, act=False)
    assert any("EICAR" in d.name.upper() or d.engine == "hash" for r in results for d in r.detections)
