"""Sign a release's SHA256SUMS.txt with the hybrid post-quantum key from $SV_SIGNING_KEY.

    SV_SIGNING_KEY=... python tools/pq_sign.py artifacts/SHA256SUMS.txt   # writes SHA256SUMS.txt.sig

Refuses to sign with a key that is not pinned in src/sentinel_vision/trust.py, and verifies the result.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main() -> int:
    from sentinel_vision.pqsign import CONTEXT_RELEASE, PrivateKey, sign, verify
    from sentinel_vision.trust import release_keys

    path = Path(sys.argv[1])
    secret = os.environ.get("SV_SIGNING_KEY", "").strip()
    if not secret:
        print("SV_SIGNING_KEY is not set", file=sys.stderr)
        return 2
    key = PrivateKey.from_b64(secret)
    pinned = release_keys()
    if key.public_key().key_id not in {k.key_id for k in pinned}:
        print("signing key is not pinned in sentinel_vision/trust.py", file=sys.stderr)
        return 2
    data = path.read_bytes()
    envelope = sign(key, data, CONTEXT_RELEASE)
    verify(envelope, data, CONTEXT_RELEASE, pinned)
    out = path.with_name(path.name + ".sig")
    out.write_bytes(envelope)
    print(f"signed {path.name} with key {key.public_key().key_id} -> {out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
