#!/usr/bin/env python3
"""Phase 2: Seed Uruguay financial institution data.

Discovers subdomains via CT logs and registers whitelists for all major
UY institutions. Run this once to bootstrap, then the daily scheduler
keeps it updated.

Usage:
    # Against local backend
    python3 scripts/seed_uruguay.py http://localhost:9147

    # Against production
    python3 scripts/seed_uruguay.py https://api.24defend.com
"""

import asyncio
import os
import sys

import httpx

# Uruguay financial institutions and their root domains
UY_INSTITUTIONS = [
    # Banks
    {"partner_id": "brou", "domains": ["brou.com.uy"]},
    {"partner_id": "itau", "domains": ["itau.com.uy", "itau.uy"]},
    {"partner_id": "santander", "domains": ["santander.com.uy"]},
    {"partner_id": "scotiabank", "domains": ["scotiabank.com.uy"]},
    {"partner_id": "bbva", "domains": ["bbva.com.uy"]},
    {"partner_id": "hsbc", "domains": ["hsbc.com.uy"]},
    {"partner_id": "heritage", "domains": ["heritage.com.uy"]},
    {"partner_id": "bandes", "domains": ["bandes.com.uy"]},
    {"partner_id": "citibank", "domains": ["citibank.com.uy"]},
    # Credit card / payment
    {"partner_id": "oca", "domains": ["oca.com.uy"]},
    {"partner_id": "prex", "domains": ["prex.com.uy", "prex.uy"]},
    {"partner_id": "mercadopago", "domains": ["mercadopago.com", "mercadopago.com.uy"]},
    {"partner_id": "mercadolibre", "domains": ["mercadolibre.com.uy", "mercadolibre.com"]},
    # Payment networks
    {"partner_id": "abitab", "domains": ["abitab.com.uy"]},
    {"partner_id": "redpagos", "domains": ["redpagos.com.uy"]},
    # Telecom
    {"partner_id": "antel", "domains": ["antel.com.uy"]},
    {"partner_id": "movistar", "domains": ["movistar.com.uy"]},
    {"partner_id": "claro", "domains": ["claro.com.uy"]},
    # E-commerce / services
    {"partner_id": "pedidosya", "domains": ["pedidosya.com", "pedidosya.com.uy"]},
    # Government
    {"partner_id": "gub", "domains": ["gub.uy"]},
    {"partner_id": "bps", "domains": ["bps.gub.uy"]},
    {"partner_id": "dgi", "domains": ["dgi.gub.uy"]},
    {"partner_id": "bcu", "domains": ["bcu.gub.uy"]},
    {"partner_id": "agesic", "domains": ["agesic.gub.uy"]},
]

API_KEY = os.environ.get("DEFEND_API_KEY", "dev-api-key-change-me")


async def discover_and_register(base_url: str, institution: dict):
    """Discover subdomains via CT logs and register as whitelist."""
    partner_id = institution["partner_id"]
    total_discovered = 0
    total_added = 0

    async with httpx.AsyncClient(timeout=60) as client:
        for domain in institution["domains"]:
            print(f"  Discovering subdomains for {domain}...", end=" ", flush=True)

            try:
                resp = await client.post(
                    f"{base_url}/admin/ingest/whitelist-discovery",
                    headers={"X-Api-Key": API_KEY, "Content-Type": "application/json"},
                    json={"root_domain": domain, "partner_id": partner_id},
                )

                if resp.status_code == 200:
                    data = resp.json()
                    discovered = data.get("discovered", 0)
                    added = data.get("new_added", 0)
                    total_discovered += discovered
                    total_added += added
                    print(f"found {discovered}, added {added} new")
                else:
                    print(f"ERROR {resp.status_code}: {resp.text[:100]}")
            except Exception as e:
                print(f"ERROR: {e}")

    return total_discovered, total_added


async def add_manual_whitelist(base_url: str, institution: dict):
    """Add root domains directly to whitelist (in case CT logs miss them)."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{base_url}/admin/domains",
            headers={"X-Api-Key": API_KEY, "Content-Type": "application/json"},
            json={
                "domains": institution["domains"],
                "entry_type": "whitelist",
                "partner_id": institution["partner_id"],
                "reason": f"Root domain for {institution['partner_id']}",
            },
        )
        return resp.status_code == 200


async def main():
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:9147"
    print(f"Seeding Uruguay institutions against {base_url}\n")

    grand_total_discovered = 0
    grand_total_added = 0

    for inst in UY_INSTITUTIONS:
        print(f"\n[{inst['partner_id'].upper()}]")

        # Add root domains
        await add_manual_whitelist(base_url, inst)

        # Discover subdomains via CT logs
        discovered, added = await discover_and_register(base_url, inst)
        grand_total_discovered += discovered
        grand_total_added += added

    print(f"\n{'='*50}")
    print(f"SUMMARY")
    print(f"{'='*50}")
    print(f"Institutions: {len(UY_INSTITUTIONS)}")
    print(f"Total subdomains discovered: {grand_total_discovered}")
    print(f"New domains added: {grand_total_added}")

    # Print stats
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{base_url}/admin/domains?entry_type=whitelist",
            headers={"X-Api-Key": API_KEY},
        )
        if resp.status_code == 200:
            entries = resp.json()
            partners = set(e.get("partner_id", "unknown") for e in entries)
            print(f"Total whitelist entries: {len(entries)}")
            print(f"Partners: {', '.join(sorted(p for p in partners if p))}")


if __name__ == "__main__":
    asyncio.run(main())
