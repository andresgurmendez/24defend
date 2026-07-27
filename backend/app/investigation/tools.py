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


def _extract_org_from_vcard(vcard: list) -> str | None:
    """Pull the organization / full-name field out of an RDAP vCard array.

    RDAP vCard structure is `[type, params, value_type, value]` per entry.
    We prefer "org" (org name) but fall back to "fn" (formatted name) which
    for corporate registrants usually equals the org.
    """
    org = None
    for item in vcard:
        if not isinstance(item, list) or len(item) < 4:
            continue
        key = item[0]
        if key == "org":
            # `org` value can be a string OR a list [org, dept, ...]
            v = item[3]
            org = v[0] if isinstance(v, list) and v else v
            if org:
                return str(org)
        elif key == "fn" and not org:
            org = str(item[3])
    return org


@tool
def dns_lookup(domain: str) -> str:
    """Look up domain registration info via RDAP.

    Returns: age (days since registration), registrar, registrant
    organization, admin/tech contact organizations, and ALL nameservers.

    Interpretation guide:
      - Domain < 30 days old and impersonating a bank/brand → very likely phishing.
      - Registrant organization matching a known corporate entity (Google,
        Meta, Amazon, Cloudflare, TikTok/ByteDance, Delivery Hero, banks,
        etc.) → strong evidence the domain is legit corporate infrastructure,
        even if a subdomain contains a brand keyword.
      - Nameservers ending in a known corporate domain (ns*.google.com,
        awsdns-*.aws, cloudflare, etc.) → also strong legit signal.
    """

    parts = domain.split(".")
    registrable = ".".join(parts[-2:]) if len(parts) > 2 else domain

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(f"https://rdap.org/domain/{registrable}")
            if resp.status_code != 200:
                return f"RDAP lookup failed (HTTP {resp.status_code}). Domain may not exist or RDAP not available for this TLD."

            data = resp.json()
            results: list[str] = []

            # Registration date
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    reg_date = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                    days_old = (datetime.now(timezone.utc) - reg_date).days
                    results.append(f"Registration date: {reg_date.strftime('%Y-%m-%d')} ({days_old} days ago)")
                elif event.get("eventAction") == "expiration":
                    results.append(f"Expiration: {event['eventDate'][:10]}")

            # Roles we care about — registrar identifies who sold the domain,
            # but the registrant/admin/technical contacts identify WHO OWNS
            # AND OPERATES it. Missing the latter was the root cause of the
            # dhmedia.io / ttdns2.com / adsensecustomsearchads.com FPs.
            role_labels = {
                "registrar": "Registrar",
                "registrant": "Registrant organization",
                "administrative": "Admin contact organization",
                "technical": "Tech contact organization",
            }
            for entity in data.get("entities", []):
                roles = entity.get("roles", []) or []
                vcard = entity.get("vcardArray", [None, []])[1] or []
                org = _extract_org_from_vcard(vcard)
                if not org:
                    continue
                for role in roles:
                    if role in role_labels:
                        results.append(f"{role_labels[role]}: {org}")

            # All nameservers — the corporate suffix (ns*.google.com,
            # awsdns-*, cloudflare.com etc.) is often the strongest signal
            # for who actually operates the domain.
            ns = data.get("nameservers", [])
            if ns:
                ns_names = [n.get("ldhName", "") for n in ns if n.get("ldhName")]
                if ns_names:
                    results.append(f"Nameservers: {', '.join(ns_names)}")

            return "\n".join(results) if results else "Domain exists but no detailed RDAP data available."

    except Exception as e:
        return f"DNS lookup error: {e}"


# ---------------------------------------------------------------------------
# resolve_domain helpers
# ---------------------------------------------------------------------------

# CDN customer-alias patterns. When a domain CNAMEs into <label>.<cdn_suffix>,
# the CDN operator has bound that <label> to a specific customer's account.
# The customer had to prove control of the origin hostname to Akamai / AWS /
# etc., so this is a strong "operated by that brand" signal.
_CDN_ALIAS_SUFFIXES = {
    "edgekey.net": "Akamai",
    "akamaiedge.net": "Akamai",
    "akamaized.net": "Akamai",
    "cloudfront.net": "AWS CloudFront",
    "azureedge.net": "Azure Front Door",
    "azurefd.net": "Azure Front Door",
    "b-cdn.net": "BunnyCDN",
    "fastly.net": "Fastly",
    "cdn.cloudflare.net": "Cloudflare",
    "netlifyglobalcdn.com": "Netlify",
    "vercel-dns.com": "Vercel",
}

# IP owner names that indicate "generic cloud/CDN network" — millions of
# unrelated customers share these. The agent must NOT read "IP owner is
# Cloudflare" as evidence of brand ownership; the signal is only meaningful
# when combined with a matching CDN alias or matching TLS cert.
_CLOUD_IP_OWNERS = (
    "cloudflare",
    "akamai",
    "amazon",
    "google llc",
    "google-cloud",
    "microsoft",
    "azure",
    "vercel",
    "netlify",
    "fastly",
    "digital ocean",
    "digitalocean",
    "linode",
    "ovh",
    "hetzner",
    "leaseweb",
)

# Reverse-DNS suffixes that identify generic hosting — the PTR names the
# infrastructure operator, NOT the customer.
_GENERIC_PTR_SUFFIXES = (
    ".compute.amazonaws.com",
    ".deploy.static.akamaitechnologies.com",
    ".googleusercontent.com",
    ".bc.googleusercontent.com",
    ".1e100.net",
    ".cloudfront.net",
    ".fastly.net",
    ".cloudapp.net",
    ".azurewebsites.net",
    ".herokuapp.com",
)


def _resolve_dns_via_doh(hostname: str, rrtype: str = "A") -> dict:
    """Resolve a hostname via Google Public DNS DoH endpoint.
    Returns the parsed JSON (with 'Answer' list) or {} on any failure.
    Isolated so a DoH outage doesn't break the whole tool."""
    try:
        with httpx.Client(timeout=3) as client:
            resp = client.get(
                "https://dns.google/resolve",
                params={"name": hostname, "type": rrtype},
                headers={"accept": "application/dns-json"},
            )
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {}


def _follow_cname_chain(hostname: str, max_hops: int = 5) -> tuple[list[str], list[str]]:
    """Follow the CNAME chain from `hostname`.
    Returns (cname_chain, ip_addresses). Both may be empty on failure.
    Loop-protected via visited-set; capped at max_hops."""
    chain: list[str] = []
    ips: list[str] = []
    visited: set[str] = set()
    current = hostname.rstrip(".").lower()
    for _ in range(max_hops):
        if current in visited:
            break
        visited.add(current)
        data = _resolve_dns_via_doh(current, "A")
        answers = data.get("Answer") or []
        # DoH returns CNAMEs (type=5) and A records (type=1) inline.
        cname_here = None
        for a in answers:
            atype = a.get("type")
            aname = (a.get("data") or "").rstrip(".").lower()
            if atype == 5 and aname and aname != current:
                cname_here = aname
            elif atype == 1 and aname:
                ips.append(aname)
        if cname_here and cname_here not in visited:
            chain.append(cname_here)
            current = cname_here
            continue
        break
    return chain, ips


def _detect_cdn_alias(chain: list[str]) -> tuple[str | None, str | None]:
    """If any hop in the CNAME chain matches a known CDN customer-alias
    pattern, return (cdn_provider, customer_label). Else (None, None).

    Example: 'www.walmart.com.edgekey.net' → ('Akamai', 'www.walmart.com')."""
    for hop in chain:
        for suffix, provider in _CDN_ALIAS_SUFFIXES.items():
            marker = "." + suffix
            if hop.endswith(marker):
                label = hop[: -len(marker)]
                if label:
                    return provider, label
    return None, None


def _lookup_ip_owner(ip: str) -> tuple[str | None, str | None]:
    """Return (owner_name, is_cloud_flag_reason).
    Tries ARIN RDAP first; ARIN redirects for non-ARIN space so this
    also picks up LACNIC / RIPE / APNIC / AFRINIC.
    Returns (None, None) on any failure — never raises."""
    try:
        with httpx.Client(timeout=3, follow_redirects=True) as client:
            resp = client.get(f"https://rdap.arin.net/registry/ip/{ip}")
            if resp.status_code != 200:
                return None, None
            data = resp.json()
        owner: str | None = None
        # Try 'name' at top-level (network name), then walk entities for org.
        owner = data.get("name") or None
        for entity in data.get("entities", []) or []:
            vcard = (entity.get("vcardArray") or [None, []])[1] or []
            org = _extract_org_from_vcard(vcard)
            if org:
                owner = org
                break
        if not owner:
            return None, None
        neutral = None
        ol = owner.lower()
        if any(k in ol for k in _CLOUD_IP_OWNERS):
            neutral = (
                "NEUTRAL — shared cloud/CDN network with millions of unrelated "
                "customers. Only weight this signal if a CNAME alias or TLS "
                "certificate additionally links to a specific brand."
            )
        return owner, neutral
    except Exception:
        return None, None


def _reverse_dns(ip: str) -> tuple[str | None, bool]:
    """Return (ptr_hostname, is_generic_hosting_flag). Isolated + timed."""
    try:
        socket.setdefaulttimeout(2)
        host, _, _ = socket.gethostbyaddr(ip)
        host = host.rstrip(".").lower()
        generic = any(host.endswith(s) for s in _GENERIC_PTR_SUFFIXES)
        return host, generic
    except Exception:
        return None, False
    finally:
        socket.setdefaulttimeout(None)


def _tls_cert_subject(hostname: str) -> dict:
    """Fetch the served TLS cert for `hostname`. Returns a dict with keys
    subject_cn, san_dns, issuer_org, is_free_ca. Empty dict on failure."""
    check = hostname[4:] if hostname.startswith("www.") else hostname
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=check)
        conn.settimeout(3)
        conn.connect((check, 443))
        cert = conn.getpeercert()
        conn.close()
        if not cert:
            return {}
        subject_parts = {k: v for item in cert.get("subject", ()) for k, v in item}
        issuer_parts = {k: v for item in cert.get("issuer", ()) for k, v in item}
        san = cert.get("subjectAltName", ()) or ()
        san_dns = [v for t, v in san if t == "DNS"]
        issuer_org = issuer_parts.get("organizationName", "")
        free_cas = ("let's encrypt", "zerossl", "buypass", "ssl.com")
        return {
            "subject_cn": subject_parts.get("commonName"),
            "san_dns": san_dns,
            "issuer_org": issuer_org,
            "is_free_ca": any(ca in issuer_org.lower() for ca in free_cas),
        }
    except Exception:
        return {}


@tool
def resolve_domain(domain: str) -> str:
    """Follow DNS resolution end-to-end and report who actually operates
    the destination.

    Runs four independent checks (each fails gracefully — a slow or
    unavailable check does not block the others):
    1. CNAME chain (up to 5 hops, loop-protected)
    2. Terminal IP owner via IP RDAP (LACNIC/ARIN/RIPE/APNIC/AFRINIC)
    3. Reverse DNS (PTR), flagged as GENERIC when it just names the
       hosting operator instead of the customer
    4. TLS certificate Subject / SAN / Issuer

    STRONG legit-infra signals (report each independently so the model
    can combine them):
    - CNAME terminates in <brand>.edgekey.net / .cloudfront.net etc.
      where <brand> matches the brand named in the queried subdomain
      (the CDN issued that alias only after ownership proof).
    - IP owner is a specific named company matching the brand
      (e.g. "CLIENTE ANTEL URUGUAY" for anteltv.com.uy).
    - TLS Subject/SAN lists the real brand's canonical hostname.

    NEUTRAL / weak signals:
    - IP owner is a shared cloud/CDN (Cloudflare/Akamai/AWS/Azure/GCP/
      Vercel/Netlify/etc.) — this alone tells you nothing; millions of
      unrelated customers share these networks.
    - Reverse DNS is a generic hosting PTR (*.compute.amazonaws.com,
      *.deploy.static.akamaitechnologies.com, *.googleusercontent.com,
      *.1e100.net, etc.) — again names the operator, not the customer.
    - Let's Encrypt / ZeroSSL / free CA cert alone is not suspicious;
      it becomes suspicious only when combined with a fresh domain
      AND a brand keyword in the domain name.

    Use this tool when the domain has a brand keyword in a subdomain
    but the base domain isn't recognized — this is the highest-yield
    check for that class of case (dhmedia.io, cdn-wal.net, anteltv.com.uy,
    ttdns2.com, adsensecustomsearchads.com are all recent examples).
    """
    hostname = domain.strip(".").lower()
    if not hostname:
        return "resolve_domain: empty input."

    results: list[str] = []

    # 1. CNAME chain + terminal IPs
    chain, ips = _follow_cname_chain(hostname)
    if chain:
        results.append(f"CNAME chain: {hostname} → " + " → ".join(chain))
    elif not ips:
        results.append(f"DNS resolution failed for {hostname} (no A / no CNAME).")
    else:
        results.append(f"No CNAME chain (direct A record): {hostname}")

    # CDN customer alias detection
    cdn_provider, cdn_customer = _detect_cdn_alias(chain)
    if cdn_provider:
        results.append(
            f"CDN alias: {cdn_provider} customer '{cdn_customer}'. "
            f"CDN issued this alias only after verifying '{cdn_customer}' "
            f"was operated by the requester — strong legit-infra signal "
            f"if it matches the brand in the queried domain."
        )

    if ips:
        results.append(f"Terminal IPs: {', '.join(ips[:3])}")

        # 2. IP owner (only look up first IP — usually enough)
        owner, neutral_note = _lookup_ip_owner(ips[0])
        if owner:
            results.append(f"IP owner: {owner}")
            if neutral_note:
                results.append(f"  → {neutral_note}")

        # 3. Reverse DNS
        ptr, is_generic = _reverse_dns(ips[0])
        if ptr:
            if is_generic:
                results.append(
                    f"Reverse DNS: {ptr} (GENERIC hosting hostname — "
                    f"identifies the operator, not the customer)"
                )
            else:
                results.append(f"Reverse DNS: {ptr}")

    # 4. TLS certificate
    cert = _tls_cert_subject(hostname)
    if cert:
        cn = cert.get("subject_cn") or "?"
        issuer = cert.get("issuer_org") or "?"
        results.append(f"TLS cert Subject CN: {cn}")
        san = cert.get("san_dns") or []
        if san:
            shown = ", ".join(san[:6])
            more = f" (+{len(san)-6} more)" if len(san) > 6 else ""
            results.append(f"TLS cert SAN DNS: {shown}{more}")
        results.append(f"TLS cert issuer: {issuer}")
        if cert.get("is_free_ca"):
            results.append(
                "  → Free CA (Let's Encrypt / ZeroSSL / etc.). "
                "NOT suspicious by itself; only concerning when combined "
                "with a fresh domain AND a brand keyword in the domain name."
            )
    else:
        results.append("TLS certificate: could not fetch (no HTTPS, timeout, or invalid).")

    return "\n".join(results) if results else "resolve_domain: no data collected."


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
    Note: this check is best-effort. A negative result is reliable, but
    inconclusive results should NOT be treated as a positive flag."""

    # The Transparency Report web API blocks server requests with CAPTCHAs.
    # Use the Safe Browsing Lookup API v4 if we have a key, otherwise skip.
    if not settings.safe_browsing_api_key:
        return f"Google Safe Browsing: check unavailable (no API key configured). Do NOT treat this as a flag — assume clean unless other signals are strong."

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": settings.safe_browsing_api_key},
                json={
                    "client": {"clientId": "24defend", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": f"https://{domain}/"}],
                    },
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    threats = [m.get("threatType", "UNKNOWN") for m in matches]
                    return f"Google Safe Browsing: {domain} IS FLAGGED. Threats: {', '.join(threats)}"
                else:
                    return f"Google Safe Browsing: {domain} is NOT flagged. No known threats."
            else:
                return f"Safe Browsing API returned HTTP {resp.status_code}. Unable to determine status — do NOT treat as a flag."
    except Exception as e:
        return f"Safe Browsing check error: {e}. Do NOT treat as a flag."


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
                   "tarjeta", "cuenta", "login", "acceso", "desbloquear",
                   "puntos", "premio", "ganaste", "sorteo", "regalo",
                   "promocion", "oferta", "descuento", "canje"}

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
    resolve_domain,
    ssl_certificate_check,
    levenshtein_similarity,
    google_search,
    safe_browsing_check,
    domain_heuristics,
]
