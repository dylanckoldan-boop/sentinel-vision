"""Create a hybrid ML-DSA-65 + Ed25519 release-signing key.

    python tools/pq_keygen.py OUTPUT_DIR

Writes OUTPUT_DIR/sentinel-vision-signing-key.txt (PRIVATE — add its contents as the GitHub Actions secret
SV_SIGNING_KEY, then delete the file) and prints the public key to add to src/sentinel_vision/trust.py.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main() -> int:
    from sentinel_vision.pqsign import PrivateKey

    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    key = PrivateKey.generate()
    target = out / "sentinel-vision-signing-key.txt"
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(key.to_b64() + "\n")
    pub = key.public_key()
    print(f"private key written to {target} (keep it secret)")
    print(f"key id: {pub.key_id}")
    print(f"public key (add to RELEASE_KEYS_B64 in src/sentinel_vision/trust.py):\n{pub.to_b64()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
