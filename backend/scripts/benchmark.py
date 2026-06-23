"""Crypto throughput & password-hashing benchmark.

Run from the backend directory:

    python scripts/benchmark.py            # 10MB + 100MB
    SDPP_BENCH_1GB=1 python scripts/benchmark.py   # also 1GB (slow, ~1GB RAM)

Writes a Markdown + JSON report to ./benchmark-results/.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.security.crypto import (  # noqa: E402
    DEFAULT_CHUNK_SIZE,
    decrypt_stream,
    encrypt_stream,
    generate_key,
)
from app.core.security.passwords import PasswordManager  # noqa: E402

MB = 1024 * 1024


def _bench_file(size_mb: int) -> dict[str, float]:
    data = os.urandom(size_mb * MB)
    key = generate_key()

    enc = io.BytesIO()
    t0 = time.perf_counter()
    encrypt_stream(key, io.BytesIO(data), enc, chunk_size=DEFAULT_CHUNK_SIZE)
    enc_time = time.perf_counter() - t0

    enc.seek(0)
    out = io.BytesIO()
    t0 = time.perf_counter()
    decrypt_stream(key, enc, out)
    dec_time = time.perf_counter() - t0

    assert out.getvalue() == data
    return {
        "size_mb": size_mb,
        "encrypt_s": round(enc_time, 4),
        "decrypt_s": round(dec_time, 4),
        "encrypt_mb_s": round(size_mb / enc_time, 1),
        "decrypt_mb_s": round(size_mb / dec_time, 1),
    }


def _bench_argon2() -> dict[str, float]:
    pm = PasswordManager()  # production-ish defaults
    t0 = time.perf_counter()
    h = pm.hash("Benchmark-P@ssw0rd!")
    hash_time = time.perf_counter() - t0
    t0 = time.perf_counter()
    pm.verify(h, "Benchmark-P@ssw0rd!")
    verify_time = time.perf_counter() - t0
    return {"hash_ms": round(hash_time * 1000, 1), "verify_ms": round(verify_time * 1000, 1)}


def main() -> None:
    sizes = [10, 100]
    if os.getenv("SDPP_BENCH_1GB"):
        sizes.append(1024)

    print("SDPP crypto benchmark — AES-256-GCM streaming\n")
    file_results = []
    for size in sizes:
        r = _bench_file(size)
        file_results.append(r)
        print(
            f"  {size:>5} MB | encrypt {r['encrypt_mb_s']:>7} MB/s "
            f"| decrypt {r['decrypt_mb_s']:>7} MB/s"
        )

    argon = _bench_argon2()
    print(f"\n  Argon2id hash: {argon['hash_ms']} ms | verify: {argon['verify_ms']} ms")

    out_dir = Path("benchmark-results")
    out_dir.mkdir(exist_ok=True)
    report = {"files": file_results, "argon2id": argon}
    (out_dir / "benchmark.json").write_text(json.dumps(report, indent=2))

    md = ["# SDPP Benchmark Report\n", "## AES-256-GCM streaming\n",
          "| Size | Encrypt (MB/s) | Decrypt (MB/s) |", "|------|----------------|----------------|"]
    md += [f"| {r['size_mb']} MB | {r['encrypt_mb_s']} | {r['decrypt_mb_s']} |" for r in file_results]
    md += ["\n## Argon2id\n", f"- hash: {argon['hash_ms']} ms\n- verify: {argon['verify_ms']} ms\n"]
    (out_dir / "benchmark.md").write_text("\n".join(md))
    print(f"\nReport written to {out_dir}/benchmark.json and benchmark.md")


if __name__ == "__main__":
    main()
