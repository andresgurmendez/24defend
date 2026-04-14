"""Bloom filter generation and serving for on-device whitelist checks."""

import io
import math

import mmh3
from bitarray import bitarray

from app.config import settings
from app.domain_service import scan_by_type
from app.models import EntryType


def _optimal_params(n: int, fp_rate: float) -> tuple[int, int]:
    """Calculate optimal bloom filter size (m) and hash count (k)."""
    m = int(-n * math.log(fp_rate) / (math.log(2) ** 2))
    k = int((m / n) * math.log(2))
    return max(m, 64), max(k, 1)


def build_bloom_filter(domains: list[str], n: int | None = None,
                       fp_rate: float | None = None) -> bytes:
    """Build a bloom filter from a list of domains. Returns serialized bytes."""
    n = n or settings.bloom_filter_size
    fp_rate = fp_rate or settings.bloom_filter_fp_rate
    m, k = _optimal_params(max(n, len(domains)), fp_rate)

    bits = bitarray(m)
    bits.setall(0)

    for domain in domains:
        d = domain.lower()
        for i in range(k):
            idx = mmh3.hash(d, seed=i) % m
            bits[idx] = 1

    # Pack: 4 bytes for m, 4 bytes for k, then the bitarray
    buf = io.BytesIO()
    buf.write(m.to_bytes(4, "big"))
    buf.write(k.to_bytes(4, "big"))
    buf.write(bits.tobytes())
    return buf.getvalue()


def check_bloom_filter(data: bytes, domain: str) -> bool:
    """Check if a domain might be in the bloom filter."""
    m = int.from_bytes(data[:4], "big")
    k = int.from_bytes(data[4:8], "big")
    bits = bitarray()
    bits.frombytes(data[8:])

    d = domain.lower()
    for i in range(k):
        idx = mmh3.hash(d, seed=i) % m
        if not bits[idx]:
            return False
    return True  # probably in set (may be false positive)


async def generate_bloom_filter() -> bytes:
    """Generate a bloom filter from all whitelist + blacklist entries."""
    whitelist = await scan_by_type(EntryType.whitelist)
    blacklist = await scan_by_type(EntryType.blacklist)

    # Bloom filter contains ALL known domains (both safe and bad)
    # The device uses it to quickly determine: "do we know anything about this domain?"
    # If yes → check the verdict via API or local cache
    # If no → probably safe (unknown domain, not impersonating anyone)
    all_domains = [e.domain for e in whitelist + blacklist]

    return build_bloom_filter(all_domains)
