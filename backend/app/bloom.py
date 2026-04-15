"""Bloom filter generation and serving for on-device checks.

Two separate filters, both using base domains only (no subdomains):
  - Whitelist bloom: known-safe base domains → silent allow on device
  - Blacklist bloom: known-bad base domains → instant block on device, no API call
"""

import io
import math

import mmh3
from bitarray import bitarray

from app.config import settings
from app.domain_service import scan_by_type
from app.models import EntryType

# Two-part TLDs where the registrable domain is 3 parts (e.g., brou.com.uy)
_TWO_PART_TLDS = {"com.uy", "com.ar", "com.br", "com.mx", "com.co", "com.cl",
                  "co.uk", "com.au", "com.pe", "com.py", "com.bo", "com.ve",
                  "com.ec", "com.pa", "com.gt", "com.cr", "com.do", "com.sv",
                  "com.hn", "com.ni", "gob.uy", "org.uy", "edu.uy", "net.uy"}


def extract_base_domain(domain: str) -> str:
    """Extract the registrable base domain, stripping subdomains.

    Examples:
      homebanking.brou.com.uy → brou.com.uy
      www.google.com          → google.com
      sub.evil.xyz            → evil.xyz
      brou.com.uy             → brou.com.uy (unchanged)
    """
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    last_two = ".".join(parts[-2:])
    if last_two in _TWO_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _optimal_params(n: int, fp_rate: float) -> tuple[int, int]:
    """Calculate optimal bloom filter size (m) and hash count (k)."""
    n = max(n, 10)  # avoid division by zero for tiny sets
    m = int(-n * math.log(fp_rate) / (math.log(2) ** 2))
    k = int((m / n) * math.log(2))
    return max(m, 64), max(k, 1)


def build_bloom_filter(domains: list[str], fp_rate: float | None = None) -> bytes:
    """Build a bloom filter from a list of domains. Returns serialized bytes.

    Format: [4 bytes: m] [4 bytes: k] [bitarray bytes]
    """
    fp_rate = fp_rate or settings.bloom_filter_fp_rate
    n = max(len(domains), 10)
    m, k = _optimal_params(n, fp_rate)

    bits = bitarray(m)
    bits.setall(0)

    for domain in domains:
        d = domain.lower()
        for i in range(k):
            idx = mmh3.hash(d, seed=i) % m
            bits[idx] = 1

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
    return True


async def generate_whitelist_bloom() -> bytes:
    """Generate bloom filter of known-safe base domains."""
    entries = await scan_by_type(EntryType.whitelist)
    base_domains = set(extract_base_domain(e.domain) for e in entries)
    return build_bloom_filter(list(base_domains))


async def generate_blacklist_bloom() -> bytes:
    """Generate bloom filter of known-bad base domains."""
    entries = await scan_by_type(EntryType.blacklist)
    base_domains = set(extract_base_domain(e.domain) for e in entries)
    return build_bloom_filter(list(base_domains))


async def generate_bloom_filters() -> dict:
    """Generate both bloom filters and return stats."""
    whitelist_entries = await scan_by_type(EntryType.whitelist)
    blacklist_entries = await scan_by_type(EntryType.blacklist)

    wl_base = set(extract_base_domain(e.domain) for e in whitelist_entries)
    bl_base = set(extract_base_domain(e.domain) for e in blacklist_entries)

    wl_bloom = build_bloom_filter(list(wl_base))
    bl_bloom = build_bloom_filter(list(bl_base))

    return {
        "whitelist": {
            "data": wl_bloom,
            "total_entries": len(whitelist_entries),
            "unique_base_domains": len(wl_base),
            "bloom_size_bytes": len(wl_bloom),
        },
        "blacklist": {
            "data": bl_bloom,
            "total_entries": len(blacklist_entries),
            "unique_base_domains": len(bl_base),
            "bloom_size_bytes": len(bl_bloom),
        },
    }
