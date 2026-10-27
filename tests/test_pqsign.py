import base64
import json

import pytest

from sentinel_vision import pqsign
from sentinel_vision.trust import release_keys


def test_round_trip_and_key_encoding():
    key = pqsign.PrivateKey.generate()
    again = pqsign.PrivateKey.from_b64(key.to_b64())
    assert again.public_key() == key.public_key()
    pub = pqsign.PublicKey.from_b64(key.public_key().to_b64())
    env = pqsign.sign(key, b"payload", "test")
    assert pqsign.verify(env, b"payload", "test", [pub]).key_id == pub.key_id
    doc = json.loads(env)
    assert doc["alg"] == "ML-DSA-65+Ed25519"
    assert len(base64.b64decode(doc["mldsa65"])) == 3309  # FIPS 204 ML-DSA-65 signature size


def test_every_tampering_is_rejected():
    key = pqsign.PrivateKey.generate()
    trusted = [key.public_key()]
    env = pqsign.sign(key, b"payload", "test")
    doc = json.loads(env)
    with pytest.raises(pqsign.SignatureError):
        pqsign.verify(env, b"payload!", "test", trusted)  # data changed
    with pytest.raises(pqsign.SignatureError):
        pqsign.verify(env, b"payload", "other-purpose", trusted)  # replay in another context
    with pytest.raises(pqsign.SignatureError):
        pqsign.verify(env, b"payload", "test", [pqsign.PrivateKey.generate().public_key()])  # unknown key
    for part in ("mldsa65", "ed25519"):  # each half is required on its own
        bad = dict(doc)
        sig = bytearray(base64.b64decode(bad[part]))
        sig[10] ^= 1
        bad[part] = base64.b64encode(bytes(sig)).decode()
        with pytest.raises(pqsign.SignatureError):
            pqsign.verify(json.dumps(bad).encode(), b"payload", "test", trusted)
    with pytest.raises(pqsign.SignatureError):
        pqsign.verify(b"not json", b"payload", "test", trusted)
    with pytest.raises(pqsign.SignatureError):
        pqsign.verify(env, b"payload", "test", [])


def test_deterministic_seed_keys_and_self_test():
    seed = pqsign.PrivateKey(b"\x01" * 32, b"\x02" * 32)
    assert seed.public_key() == pqsign.PrivateKey(b"\x01" * 32, b"\x02" * 32).public_key()
    assert pqsign.self_test() is True


def test_pinned_release_key_is_well_formed():
    keys = release_keys()
    assert keys, "a release key must be pinned"
    assert all(len(k.mldsa65) == 1952 and len(k.ed25519) == 32 for k in keys)


def test_verify_release_cli(tmp_path, monkeypatch, capsys):
    import hashlib

    from sentinel_vision import cli, trust

    key = pqsign.PrivateKey.generate()
    monkeypatch.setattr(trust, "RELEASE_KEYS_B64", [key.public_key().to_b64()])
    setup = tmp_path / "SentinelVision-9.9.9-Setup.exe"
    setup.write_bytes(b"MZ installer bytes")
    sums = f"{hashlib.sha256(setup.read_bytes()).hexdigest()}  {setup.name}\n".encode()
    (tmp_path / "SHA256SUMS.txt").write_bytes(sums)
    (tmp_path / "SHA256SUMS.txt.sig").write_bytes(pqsign.sign(key, sums, pqsign.CONTEXT_RELEASE))
    assert cli.main(["verify-release", str(tmp_path)]) == 0
    setup.write_bytes(b"MZ tampered")
    assert cli.main(["verify-release", str(tmp_path)]) == 1
    (tmp_path / "SHA256SUMS.txt").write_bytes(sums.replace(b"  ", b" *"))  # checksum list altered
    assert cli.main(["verify-release", str(tmp_path)]) == 1
    assert "SIGNATURE INVALID" in capsys.readouterr().out


def test_release_key_command_writes_a_private_key_once_and_a_shareable_public_key(tmp_path, capsys):
    """Audit finding SV-L03: the owner creates the next release key on their own computer."""
    import stat
    import sys

    from sentinel_vision import cli
    from sentinel_vision.pqsign import PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, PrivateKey, PublicKey

    folder = tmp_path / "keys"
    assert cli.main(["release-key", "new", str(folder)]) == 0
    private = PrivateKey.from_b64((folder / PRIVATE_KEY_FILE).read_text())
    key_id, pub_b64 = (folder / PUBLIC_KEY_FILE).read_text().splitlines()
    assert PublicKey.from_b64(pub_b64) == private.public_key()
    assert key_id == f"key id: {private.public_key().key_id}"
    assert private.to_b64() not in capsys.readouterr().out  # the secret is never printed
    if sys.platform != "win32":
        assert stat.S_IMODE((folder / PRIVATE_KEY_FILE).stat().st_mode) == 0o600
    assert cli.main(["release-key", "new", str(folder)]) == 2  # never overwrites a key
    assert (folder / PRIVATE_KEY_FILE).read_text().strip() == private.to_b64()
    assert cli.main(["release-key", "list"]) == 0
    assert "trusted release key 0a5b8ebb9da90203" in capsys.readouterr().out
