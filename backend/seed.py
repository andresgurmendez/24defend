#!/usr/bin/env python3
"""Seed the local DynamoDB with test data."""

import asyncio

from app.domain_service import put_domains_bulk
from app.models import EntryType
from app.db import ensure_table


BLACKLIST = [
    "brou-seguro.com",
    "itau-homebanking.net",
    "santander-verificacion.com",
    "brou-actualizacion.com",
    "scotiabank-uy.net",
    "mi-brou.com",
    "itau-uruguay.net",
    "24defend-block-test.com",
]

WHITELIST_BROU = [
    "brou.com.uy",
    "ebrou.com.uy",
]

WHITELIST_ITAU = [
    "itau.com.uy",
    "itau.com",
]

WHITELIST_GENERAL = [
    "santander.com.uy",
    "scotiabank.com.uy",
    "hsbc.com.uy",
    "bbva.com.uy",
    "mercadolibre.com.uy",
    "mercadolibre.com",
    "mercadopago.com",
    "pedidosya.com",
    "antel.com.uy",
    "movistar.com.uy",
    "claro.com.uy",
]


async def main():
    await ensure_table()

    n = await put_domains_bulk(BLACKLIST, EntryType.blacklist, reason="Known phishing domain")
    print(f"Added {n} blacklist entries")

    n = await put_domains_bulk(WHITELIST_BROU, EntryType.whitelist, partner_id="brou", reason="BROU official")
    print(f"Added {n} BROU whitelist entries")

    n = await put_domains_bulk(WHITELIST_ITAU, EntryType.whitelist, partner_id="itau", reason="Itau official")
    print(f"Added {n} Itau whitelist entries")

    n = await put_domains_bulk(WHITELIST_GENERAL, EntryType.whitelist, reason="Verified institution")
    print(f"Added {n} general whitelist entries")

    print("Done!")


if __name__ == "__main__":
    asyncio.run(main())
