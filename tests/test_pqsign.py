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
