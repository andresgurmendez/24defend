"""Tools available to the domain investigation agent.

Each tool is a function that takes structured input and returns
a string summary. The LLM decides which tools to call and in what order.
"""

import asyncio
import json
import socket
import ssl
from datetime import datetime, timezone

import httpx
from langchain_core.tools import tool

from app.config import settings


@tool
def dns_lookup(domain: str) -> str:
    """Look up domain registration info via RDAP. Returns domain age, registrar, and registration date.
    Use this to check if a domain is suspiciously new (registered days ago = likely phishing)."""

    parts = domain.split(".")
    registrable = ".".join(parts[-2:]) if len(parts) > 2 else domain

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(f"https://rdap.org/domain/{registrable}")
            if resp.status_code != 200:
                return f"RDAP lookup failed (HTTP {resp.status_code}). Domain may not exist or RDAP not available for this TLD."

            data = resp.json()
            results = []

            # Registration date
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    reg_date = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                    days_old = (datetime.now(timezone.utc) - reg_date).days
                    results.append(f"Registration date: {reg_date.strftime('%Y-%m-%d')} ({days_old} days ago)")
                elif event.get("eventAction") == "expiration":
                    results.append(f"Expiration: {event['eventDate'][:10]}")

            # Registrar
            for entity in data.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    vcard = entity.get("vcardArray", [None, []])[1]
                    for item in vcard:
                        if item[0] == "fn":
                            results.append(f"Registrar: {item[3]}")

            # Nameservers
            ns = data.get("nameservers", [])
            if ns:
                ns_names = [n.get("ldhName", "") for n in ns[:3]]
                results.append(f"Nameservers: {', '.join(ns_names)}")

            return "\n".join(results) if results else "Domain exists but no detailed RDAP data available."

    except Exception as e:
        return f"DNS lookup error: {e}"


@tool
def ssl_certificate_check(domain: str) -> str:
    """Check the SSL/TLS certificate of a domain. Returns issuer, age, validity, and SANs.
    Free CAs (Let's Encrypt) on a domain impersonating a bank = suspicious.
    No HTTPS at all = suspicious for a financial site."""

    check_domain = domain[4:] if domain.startswith("www.") else domain

    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=check_domain)
        conn.settimeout(5)
        conn.connect((check_domain, 443))
        cert = conn.getpeercert()
        conn.close()

        if not cert:
            return "Connected via HTTPS but no certificate data available."

        results = []

        # Issuer
        issuer_parts = {k: v for item in cert.get("issuer", ()) for k, v in item}
        issuer_org = issuer_parts.get("organizationName", "Unknown")
        results.append(f"Issuer: {issuer_org}")

        free_cas = ["let's encrypt", "zerossl", "buypass", "ssl.com"]
        if any(ca in issuer_org.lower() for ca in free_cas):
            results.append("⚠ Free CA certificate (common for phishing sites)")

        # Cert dates
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        if not_before:
            from email.utils import parsedate_to_datetime
            try:
                nb = parsedate_to_datetime(not_before)
                age_days = (datetime.now(timezone.utc) - nb).days
                results.append(f"Cert issued: {nb.strftime('%Y-%m-%d')} ({age_days} days ago)")
            except Exception:
                results.append(f"Cert notBefore: {not_before}")
        if not_after:
            results.append(f"Cert expires: {not_after}")

        # SANs
        san = cert.get("subjectAltName", ())
        san_domains = [v for t, v in san if t == "DNS"]
        if san_domains:
            results.append(f"Certificate covers {len(san_domains)} domain(s): {', '.join(san_domains[:5])}")
            if len(san_domains) > 5:
                results.append(f"  ... and {len(san_domains) - 5} more")

        return "\n".join(results)

    except ssl.SSLCertVerificationError:
        return "SSL certificate verification FAILED (self-signed, expired, or invalid). Highly suspicious."
    except socket.timeout:
        return "HTTPS connection timed out. Domain may not serve HTTPS."
    except (ConnectionRefusedError, OSError):
        return "No HTTPS server found (connection refused). Domain only serves HTTP or doesn't resolve. Suspicious for a financial site."
    except Exception as e:
        return f"SSL check error: {type(e).__name__}: {e}"


@tool
def levenshtein_similarity(domain: str, whitelist_domains: list[str]) -> str:
    """Calculate Levenshtein edit distance between a domain and a list of known official domains.
    Low distance (1-3) to a bank domain = likely typosquatting/impersonation.
    Returns the closest matches with distances."""

    def _lev(s1: str, s2: str) -> int:
        m, n = len(s1), len(s2)
        if m == 0: return n
        if n == 0: return m
        prev = list(range(n + 1))
        for i in range(1, m + 1):
            curr = [i] + [0] * n
            for j in range(1, n + 1):
                cost = 0 if s1[i - 1] == s2[j - 1] else 1
                curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
            prev = curr
        return prev[n]

    def _base(d: str) -> str:
        parts = d.lower().split(".")
        if len(parts) <= 2: return d.lower()
        two_part = {"com.uy", "com.ar", "com.br", "com.mx", "com.co", "com.cl", "co.uk"}
        if ".".join(parts[-2:]) in two_part and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    base = _base(domain)
    results = []
    for official in whitelist_domains:
        off_base = _base(official)
        dist = _lev(base, off_base)
        if dist <= 5:
            similarity = 1.0 - (dist / max(len(base), len(off_base)))
            results.append(f"{official}: distance={dist}, similarity={similarity:.0%}")

    if not results:
        return f"No whitelist domains are similar to {domain} (all edit distances > 5)."

    return f"Levenshtein distances for {domain}:\n" + "\n".join(sorted(results))


@tool
def google_search(query: str) -> str:
    """Search Google for information about a domain. Useful to check if a domain
    is mentioned in scam reports, if it's a known business, or if it has no web presence.
    A domain with zero Google results that looks like a bank = suspicious."""

    if not settings.serper_api_key:
        return "Google search unavailable (no SERPER_API_KEY configured). Skipping this check."

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(
                "https://google.serper.dev/search",
                headers={"X-API-KEY": settings.serper_api_key, "Content-Type": "application/json"},
                json={"q": query, "num": 5},
            )
            if resp.status_code != 200:
                return f"Serper API error (HTTP {resp.status_code})"

            data = resp.json()
            results = []

            # Organic results
            for item in data.get("organic", [])[:5]:
                results.append(f"- {item.get('title', 'No title')}: {item.get('link', '')}")

            # Knowledge graph
            kg = data.get("knowledgeGraph", {})
            if kg:
                results.append(f"Knowledge Graph: {kg.get('title', '')} — {kg.get('description', '')}")

            if not results:
                return f"No Google results found for '{query}'. Domain has zero web presence — suspicious if it claims to be a known institution."

            return f"Google results for '{query}':\n" + "\n".join(results)

    except Exception as e:
        return f"Google search error: {e}"


@tool
def safe_browsing_check(domain: str) -> str:
    """Check if a domain is flagged in Google Safe Browsing database.
    This is a definitive signal — if flagged, the domain is known malicious."""

    # Using the free lookup via transparencyreport
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(
                f"https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status",
                params={"site": domain},
            )
            if resp.status_code == 200:
                body = resp.text
                if "No unsafe content found" in body or "no data" in body.lower():
                    return f"Google Safe Browsing: {domain} is NOT flagged. No known threats."
                else:
                    return f"Google Safe Browsing: {domain} MAY be flagged. Raw response: {body[:500]}"
            else:
                return f"Safe Browsing check returned HTTP {resp.status_code}. Unable to determine status."
    except Exception as e:
        return f"Safe Browsing check error: {e}"


@tool
def domain_heuristics(domain: str) -> str:
    """Analyze a domain's string characteristics for phishing signals.
    Checks: length, hyphens, digits, TLD risk, subdomain depth, character entropy."""

    signals = []
    d = domain.lower()

    if len(d) > 30:
        signals.append(f"Long domain ({len(d)} chars)")
    if d.count("-") >= 2:
        signals.append(f"Multiple hyphens ({d.count('-')})")
    elif d.count("-") == 1:
        signals.append("Contains one hyphen")

    digits = sum(1 for c in d if c.isdigit())
    if digits > 3:
        signals.append(f"Many digits ({digits})")

    tld = d.split(".")[-1]
    risky_tlds = {"xyz", "top", "click", "buzz", "gq", "ml", "cf", "tk", "pw", "cc", "club", "icu", "cam"}
    if tld in risky_tlds:
        signals.append(f"High-risk TLD (.{tld})")

    if d.count(".") >= 3:
        signals.append(f"Deep subdomain nesting ({d.count('.')} dots)")

    unique = len(set(d.replace(".", "")))
    total = len(d.replace(".", ""))
    if total > 0 and unique / total > 0.85:
        signals.append("High character entropy (random-looking)")

    # Brand impersonation check (Uruguay-specific)
    brands = {"brou", "bancorepublica", "itau", "santander", "scotiabank",
              "bbva", "hsbc", "prex", "oca", "mercadopago", "mercadolibre",
              "pedidosya", "abitab", "redpagos", "antel", "movistar", "claro",
              "bps", "dgi", "gub", "bcu"}
    phish_words = {"actualizar", "actualizacion", "verificar", "verificacion",
                   "confirmar", "seguridad", "bloqueo", "suspension", "urgente",
                   "homebanking", "transferencia", "clave", "pin", "token",
                   "tarjeta", "cuenta", "login", "acceso", "desbloquear"}

    name_part = d.split(".")[0] if "." in d else d
    found_brands = [b for b in brands if b in d]
    found_phish = [w for w in phish_words if w in d]

    if found_brands:
        signals.append(f"Contains brand keyword: {', '.join(found_brands)}")
    if found_phish:
        signals.append(f"Contains phishing vocabulary: {', '.join(found_phish[:3])}")
    if found_brands and found_phish:
        signals.append("CRITICAL: Brand + phishing word combination")

    import re
    if found_brands and re.search(r"202[4-9]", d):
        signals.append("Brand + year pattern (common in phishing campaigns)")

    if not signals:
        return f"No suspicious string characteristics found for {domain}."

    return f"Heuristic signals for {domain}:\n" + "\n".join(f"- {s}" for s in signals)


ALL_TOOLS = [
    dns_lookup,
    ssl_certificate_check,
    levenshtein_similarity,
    google_search,
    safe_browsing_check,
    domain_heuristics,
]
