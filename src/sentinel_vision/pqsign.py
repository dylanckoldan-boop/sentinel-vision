"""Hybrid post-quantum signatures: ML-DSA-65 (FIPS 204) + Ed25519.

A signature is valid only if **both** component signatures verify, so it stays secure as long as either
algorithm is unbroken: ML-DSA protects against future quantum computers, Ed25519 against any undiscovered
weakness in the much younger lattice scheme.

What is signed is a domain-separated SHA3-512 digest of the content, so a signature for one purpose
(e.g. a release's checksum list) can never be replayed for another.

Envelope (JSON, UTF-8):
    {"format": "sentinel-vision-sig/1", "alg": "ML-DSA-65+Ed25519", "context": "...",
     "key_id": "<hex>", "mldsa65": "<base64>", "ed25519": "<base64>"}

Private key (64 bytes, usually base64 in an environment variable): ML-DSA-65 seed (32) || Ed25519 seed (32).
Public key (1952 + 32 bytes): ML-DSA-65 public key || Ed25519 public key. key_id = first 16 hex chars of
SHA3-256(public key).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

FORMAT = "sentinel-vision-sig/1"
ALG = "ML-DSA-65+Ed25519"
MLDSA65_PUBLIC_LEN = 1952
ED25519_PUBLIC_LEN = 32
SEED_LEN = 32
CONTEXT_RELEASE = "release-checksums"
MAX_ENVELOPE = 64 * 1024


class SignatureError(ValueError):
    pass


@dataclass(frozen=True)
class PublicKey:
    mldsa65: bytes
    ed25519: bytes

    @property
    def raw(self) -> bytes:
        return self.mldsa65 + self.ed25519

    @property
    def key_id(self) -> str:
        return hashlib.sha3_256(self.raw).hexdigest()[:16]

    def to_b64(self) -> str:
        return base64.b64encode(self.raw).decode()

    @classmethod
    def from_b64(cls, text: str) -> PublicKey:
        try:
            raw = base64.b64decode(text.strip(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SignatureError("public key is not valid base64") from exc
        if len(raw) != MLDSA65_PUBLIC_LEN + ED25519_PUBLIC_LEN:
            raise SignatureError("public key has the wrong length")
        return cls(raw[:MLDSA65_PUBLIC_LEN], raw[MLDSA65_PUBLIC_LEN:])


@dataclass(frozen=True)
class PrivateKey:
    mldsa_seed: bytes
    ed25519_seed: bytes

    @classmethod
    def generate(cls) -> PrivateKey:
        return cls(secrets.token_bytes(SEED_LEN), secrets.token_bytes(SEED_LEN))

    @classmethod
    def from_b64(cls, text: str) -> PrivateKey:
        try:
            raw = base64.b64decode(text.strip(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SignatureError("private key is not valid base64") from exc
        if len(raw) != 2 * SEED_LEN:
            raise SignatureError("private key has the wrong length")
        return cls(raw[:SEED_LEN], raw[SEED_LEN:])

    def to_b64(self) -> str:
        return base64.b64encode(self.mldsa_seed + self.ed25519_seed).decode()

    def _keys(self) -> tuple[mldsa.MLDSA65PrivateKey, ed25519.Ed25519PrivateKey]:
        return (
            mldsa.MLDSA65PrivateKey.from_seed_bytes(self.mldsa_seed),
            ed25519.Ed25519PrivateKey.from_private_bytes(self.ed25519_seed),
        )

    def public_key(self) -> PublicKey:
        pq, classic = self._keys()
        return PublicKey(pq.public_key().public_bytes_raw(), classic.public_key().public_bytes_raw())


PRIVATE_KEY_FILE = "sentinel-vision-signing-key.txt"
PUBLIC_KEY_FILE = "sentinel-vision-signing-key.pub.txt"


def write_new_key(folder) -> PublicKey:
    """Create a new release-signing key in ``folder`` (audit finding SV-L03): the private key goes to
    PRIVATE_KEY_FILE (readable by the current account only, never overwritten) and the public key, which is safe to
    share, to PUBLIC_KEY_FILE. Returns the public key."""
    import os
    from pathlib import Path

    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    key = PrivateKey.generate()
    private = folder / PRIVATE_KEY_FILE
    fd = os.open(str(private), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(key.to_b64() + "\n")
    pub = key.public_key()
    (folder / PUBLIC_KEY_FILE).write_text(f"key id: {pub.key_id}\n{pub.to_b64()}\n", encoding="ascii")
    return pub


def _digest(context: str, data: bytes) -> bytes:
    if not context or "\0" in context:
        raise SignatureError("invalid signing context")
    h = hashlib.sha3_512()
    h.update(FORMAT.encode() + b"\0" + context.encode() + b"\0")
    h.update(len(data).to_bytes(8, "big"))
    h.update(data)
    return h.digest()


def sign(key: PrivateKey, data: bytes, context: str) -> bytes:
    """Return a JSON signature envelope for ``data``."""
    pq, classic = key._keys()
    msg = _digest(context, data)
    envelope = {
        "format": FORMAT,
        "alg": ALG,
        "context": context,
        "key_id": key.public_key().key_id,
        "mldsa65": base64.b64encode(pq.sign(msg)).decode(),
        "ed25519": base64.b64encode(classic.sign(msg)).decode(),
    }
    return (json.dumps(envelope, indent=2) + "\n").encode()


def verify(envelope: bytes, data: bytes, context: str, trusted: list[PublicKey]) -> PublicKey:
    """Verify ``envelope`` over ``data``. Returns the trusted key that signed it, raises SignatureError otherwise."""
    if not trusted:
        raise SignatureError("no trusted signing keys are configured")
    if len(envelope) > MAX_ENVELOPE:
        raise SignatureError("signature file is too large")
    try:
        env = json.loads(envelope.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SignatureError("signature file is not valid JSON") from exc
    if not isinstance(env, dict) or env.get("format") != FORMAT or env.get("alg") != ALG:
        raise SignatureError("unsupported signature format or algorithm")
    if env.get("context") != context:
        raise SignatureError("signature was made for a different purpose")
    key = next((k for k in trusted if k.key_id == env.get("key_id")), None)
    if key is None:
        raise SignatureError("signed by an unknown key")
    try:
        sig_pq = base64.b64decode(str(env.get("mldsa65", "")), validate=True)
        sig_classic = base64.b64decode(str(env.get("ed25519", "")), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureError("signature is not valid base64") from exc
    msg = _digest(context, data)
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(key.mldsa65).verify(sig_pq, msg)
        ed25519.Ed25519PublicKey.from_public_bytes(key.ed25519).verify(sig_classic, msg)
    except (InvalidSignature, ValueError) as exc:
        raise SignatureError("signature does not match") from exc
    return key


def self_test() -> bool:
    """Known-answer style round trip used at startup / in diagnostics to prove the PQ backend works."""
    k = PrivateKey(bytes(range(32)), bytes(range(32, 64)))
    env = sign(k, b"sentinel-vision self-test", "self-test")
    verify(env, b"sentinel-vision self-test", "self-test", [k.public_key()])
    try:
        verify(env, b"tampered", "self-test", [k.public_key()])
    except SignatureError:
        return True
    return False
