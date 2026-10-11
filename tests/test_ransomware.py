import io
import os
import subprocess
import sys
import time
import zipfile

import pytest

from sentinel_vision.ransomware import CANARY_NAMES, RansomwareShield
from sentinel_vision.vault import RollbackVault, VaultError, looks_encrypted


def _docx(text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", f"<w>{text}</w>")
    return buf.getvalue()


@pytest.fixture
def vault(tmp_path):
    v = RollbackVault(tmp_path / "vault", max_file_mb=5, max_total_mb=50, keep_versions=3)
    yield v
    v.close()


def test_looks_encrypted():
    assert not looks_encrypted(_docx("hi"), "docx")
    assert looks_encrypted(os.urandom(4096), "docx")
    assert not looks_encrypted("hello wörld\n".encode() * 100, "txt")
    assert not looks_encrypted("hello".encode("utf-16"), "txt")
    assert looks_encrypted(os.urandom(4096), "txt")
    assert not looks_encrypted(b"%PDF-1.7 ...", "pdf")
    assert looks_encrypted(b"\x00garbage", "pdf")
    assert not looks_encrypted(os.urandom(100), "unknownext")  # unknown types are never judged


def test_vault_versions_dedup_restore_and_encryption_at_rest(vault, tmp_path):
    doc = tmp_path / "docs" / "report.docx"
    doc.parent.mkdir()
    doc.write_bytes(_docx("v1"))
    v1 = vault.snapshot(doc)
    assert v1 is not None and vault.snapshot(doc) is None  # unchanged -> no new version
    doc.write_bytes(_docx("v2"))
    assert vault.snapshot(doc) is not None
    assert [v.id for v in vault.versions(doc)][-1] == v1.id
    blob = next((vault.root / "blobs").glob("*/*.svb")).read_bytes()
    assert b"word/document.xml" not in blob  # stored encrypted
    out = vault.restore(v1.id)
    assert out == doc and doc.read_bytes() == _docx("v1")
    # the replaced content was kept, so the restore can be undone
    assert any(v.size == len(_docx("v2")) for v in vault.versions(doc))


def test_vault_refuses_encrypted_content_and_keeps_limits(vault, tmp_path):
    doc = tmp_path / "a.docx"
    doc.write_bytes(_docx("good"))
    vault.snapshot(doc)
    doc.write_bytes(os.urandom(5000))  # ransomware output
    assert vault.snapshot(doc) is None
    for i in range(6):
        doc.write_bytes(_docx(f"rev{i}"))
        vault.snapshot(doc)
    assert len(vault.versions(doc)) == 3  # keep_versions
    big = tmp_path / "big.txt"
    big.write_bytes(b"a" * (6 * 1024 * 1024))
    assert vault.snapshot(big) is None  # above max_file_mb


def test_vault_detects_tampered_blob(vault, tmp_path):
    doc = tmp_path / "x.txt"
    doc.write_text("secret plans")
    v = vault.snapshot(doc)
    blob = next((vault.root / "blobs").glob("*/*.svb"))
    data = bytearray(blob.read_bytes())
    data[-1] ^= 1
    blob.write_bytes(bytes(data))
    with pytest.raises(VaultError):
        vault.restore(v.id)


def test_rollback_to_point_in_time(vault, tmp_path):
    folder = tmp_path / "docs"
    folder.mkdir()
    files = [folder / f"f{i}.txt" for i in range(5)]
    for f in files:
        f.write_text(f"original {f.name}")
        vault.snapshot(f)
    time.sleep(0.05)
    attack = time.time()
    time.sleep(0.05)
    for f in files[:3]:
        f.write_text(f"edited after attack {f.name}")  # recorded, then "encrypted"
        vault.snapshot(f)
        f.write_bytes(os.urandom(256))
    results = dict(vault.rollback(attack, folder))
    assert all(results[os.path.normcase(str(f))] == "restored" for f in files[:3])
    for f in files[:3]:
        assert f.read_text() == f"original {f.name}"


# ----------------------------------------------------------------------------- shield


@pytest.fixture
def shield(sentinel, tmp_path):
    folder = tmp_path / "Documents"
    folder.mkdir()
    sentinel.settings.ransomware_folders = [str(folder)]
    sh = RansomwareShield(sentinel.settings, sentinel.db, RollbackVault(tmp_path / "v"))
    sh.folders = [str(folder)]
    sh._plant_canaries()
    yield sh, folder
    sh.stop()
    sh.vault.close()


def test_decoys_are_planted_and_trip_on_modification(shield):
    sh, folder = shield
    assert len(sh.canaries) == len(CANARY_NAMES)
    canary = next(iter(sh.canaries))
    sh.handle_event("modified", canary)  # content unchanged -> no alarm
    assert not sh.incidents
    os.chmod(canary, 0o600)
    if sys.platform == "win32":
        import ctypes

        ctypes.windll.kernel32.SetFileAttributesW(canary, 0x80)
    with open(canary, "wb") as fh:
        fh.write(os.urandom(512))
    sh.handle_event("modified", canary)
    assert sh.incidents and sh.incidents[0].trigger == "decoy"
    assert sh.db.detection_count() == 1


def test_deleted_decoy_is_replanted_without_alarm(shield):
    sh, _folder = shield
    canary = next(iter(sh.canaries))
    if sys.platform == "win32":
        import ctypes

        ctypes.windll.kernel32.SetFileAttributesW(canary, 0x80)
    os.remove(canary)
    sh.handle_event("deleted", canary)
    assert os.path.exists(canary) and not sh.incidents


def test_mass_encryption_burst_trips_and_normal_edits_do_not(shield):
    sh, folder = shield
    docs = [folder / f"doc{i}.docx" for i in range(12)]
    for d in docs:
        d.write_bytes(_docx(d.name))
        sh.handle_event("created", str(d))
    assert sh.files_versioned == 12 and not sh.incidents
    for d in docs[:5]:  # ordinary edits
        d.write_bytes(_docx(d.name + " edited"))
        sh.handle_event("modified", str(d))
    assert not sh.incidents
    for d in docs:  # encryption + rename, like real ransomware
        d.write_bytes(os.urandom(4096))
        sh.handle_event("modified", str(d))
    assert sh.incidents and sh.incidents[0].trigger == "mass-encryption"
    restored = sh.vault.restore_latest_good([str(d) for d in docs])
    assert all(r == "restored" for _, r in restored)
    assert all(zipfile.is_zipfile(d) for d in docs)


def test_suspect_is_suspended_and_resumable(shield):
    sh, folder = shield
    target = folder / "victim.txt"
    target.write_text("x")
    code = f"import time\nf=open({str(target)!r},'a')\ntime.sleep(60)\n"
    proc = subprocess.Popen([sys.executable, "-c", code])
    try:
        time.sleep(1.5)
        suspects = sh.find_suspects()
        mine = [s for s in suspects if s.pid == proc.pid]
        if sys.platform == "darwin" and not mine:
            pytest.skip("open-file inspection of other processes is restricted on this macOS runner")
        assert mine, f"expected the writer to be a suspect, got {suspects}"
        s = mine[0]
        assert any("protected file" in r for r in s.reasons)
        sh._suspend(s)
        assert s.state == "suspended"
        import psutil

        if sys.platform != "win32":  # Windows suspends threads; psutil keeps reporting "running" there
            deadline = time.time() + 5
            while psutil.Process(proc.pid).status() != psutil.STATUS_STOPPED and time.time() < deadline:
                time.sleep(0.05)
            assert psutil.Process(proc.pid).status() == psutil.STATUS_STOPPED
        sh.resume(s)
        assert s.state == "resumed"
    finally:
        proc.kill()
        proc.wait()


def test_remove_canaries(shield):
    sh, folder = shield
    n = sh.remove_canaries()
    assert n == len(CANARY_NAMES)
    assert not any((folder / name).exists() for name in CANARY_NAMES)


def test_decoy_content_is_stable_over_time(monkeypatch):
    from sentinel_vision import ransomware

    first = {n: ransomware._decoy_bytes(n) for n in CANARY_NAMES}
    later = time.time() + 7 * 86400
    monkeypatch.setattr(time, "time", lambda: later)
    assert {n: ransomware._decoy_bytes(n) for n in CANARY_NAMES} == first


def test_cleanup_removes_current_and_legacy_decoys_only(tmp_path):
    from sentinel_vision import ransomware

    for name in CANARY_NAMES:
        (tmp_path / name).write_bytes(ransomware._decoy_bytes(name))
    # a decoy written by v0.3 pre-releases: same members and text, but a different zip timestamp
    zipped = [n for n in CANARY_NAMES if n.endswith((".docx", ".xlsx"))]
    if zipped:
        name = zipped[0]
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for member, text in ransomware._decoy_parts(name.rsplit(".", 1)[1]):
                z.writestr(zipfile.ZipInfo(member, date_time=(2025, 3, 4, 5, 6, 8)), text)
        (tmp_path / name).write_bytes(buf.getvalue())
    removed = RansomwareShield.cleanup_decoys([str(tmp_path)])
    assert removed == len(CANARY_NAMES)
    assert not any((tmp_path / n).exists() for n in CANARY_NAMES)

    # a user's real file with the same name is never deleted
    user = tmp_path / CANARY_NAMES[0]
    user.write_bytes(b"my real budget")
    assert RansomwareShield.cleanup_decoys([str(tmp_path)]) == 0
    assert user.read_bytes() == b"my real budget"


def test_planting_never_overwrites_a_user_file(shield):
    sh, folder = shield
    target = folder / CANARY_NAMES[0]
    target.unlink()
    target.write_bytes(b"user data")
    sh._plant_canaries()
    assert target.read_bytes() == b"user data"
    assert not sh.is_canary(str(target))
    assert len(sh.canaries) == len(CANARY_NAMES) - 1
