"""Pinned release-signing keys (hybrid ML-DSA-65 + Ed25519, see pqsign.py).

When this list is non-empty, the self-updater refuses any release whose SHA256SUMS.txt is not signed by one of
these keys, and the release workflow refuses to publish without signing. To rotate keys, add the new key here,
release once signed with the old key, then remove the old key in a later release.
"""

from __future__ import annotations

from sentinel_vision.pqsign import PublicKey

# base64(ML-DSA-65 public key || Ed25519 public key)
RELEASE_KEYS_B64: list[str] = [
    (
        "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"
    ),  # key id 0a5b8ebb9da90203
]


def release_keys() -> list[PublicKey]:
    return [PublicKey.from_b64(k) for k in RELEASE_KEYS_B64]
