"""Lightweight crypto performance assertions.

Guards against accidental performance regressions (e.g. dropping AES-NI or adding
a per-chunk allocation). The full benchmark lives in scripts/benchmark.py.
"""

from __future__ import annotations

import io
import os
import time

import pytest

from app.core.security.crypto import decrypt_stream, encrypt_stream, generate_key

pytestmark = pytest.mark.performance


@pytest.mark.parametrize("size_mb", [10])
def test_streaming_throughput_floor(size_mb: int) -> None:
    data = os.urandom(size_mb * 1024 * 1024)
    key = generate_key()

    enc = io.BytesIO()
    t0 = time.perf_counter()
    encrypt_stream(key, io.BytesIO(data), enc)
    enc_mb_s = size_mb / (time.perf_counter() - t0)

    enc.seek(0)
    out = io.BytesIO()
    t0 = time.perf_counter()
    decrypt_stream(key, enc, out)
    dec_mb_s = size_mb / (time.perf_counter() - t0)

    assert out.getvalue() == data
    # Generous floor; real hardware sees 100+ MB/s. Catches gross regressions.
    assert enc_mb_s > 15, f"encrypt too slow: {enc_mb_s:.1f} MB/s"
    assert dec_mb_s > 15, f"decrypt too slow: {dec_mb_s:.1f} MB/s"
