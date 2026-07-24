"""In-memory popular-domain allowlist (Majestic top 100K + curated vendors).

Loaded on startup as a background task. Used by /check to short-circuit
obvious infrastructure domains before invoking the agent — cheaper, faster,
and eliminates the class of agent false-positives on legitimate CDN /
email-marketing / cloud-hosting subdomains.
"""

import asyncio
import logging
from typing import Optional

import httpx

from app.bloom import extract_base_domain

logger = logging.getLogger(__name__)

# Curated vendor allowlist. Always included regardless of Majestic status.
# Grows with observed agent FPs.
VENDOR_ALLOWLIST: set[str] = {
    # CDN / edge / DNS
    "cloudflare.com", "cloudflare.net", "cloudfront.net", "akamai.net",
    "akamaiedge.net", "akamaized.net", "akamaihd.net", "akahost.net",
    "fastly.net", "edgekey.net", "edgesuite.net", "jsdelivr.net", "cdnjs.com",
    "unpkg.com", "azurefd.net", "azureedge.net", "impervadns.net", "incapdns.net",
    # Cloud hosting
    "amazonaws.com", "awstrack.me", "azurewebsites.net", "cloudapp.net",
    "appspot.com", "herokuapp.com", "netlify.app", "vercel.app",
    "googleapis.com", "googleusercontent.com", "gstatic.com",
    "digitaloceanspaces.com",
    # Email marketing / delivery
    "zetaglobal.net", "sendgrid.net", "mailgun.org", "mailgun.com",
    "mailchimp.com", "list-manage.com", "mcusercontent.com",
    "constantcontact.com", "exacttarget.com", "sfmc-marketing.com",
    "marketingcloud.com", "mktdns.com", "mktoresp.com", "marketo.com",
    "responsys.net", "responsys.com", "sailthru.com", "bronto.com",
    "emarsys.net", "emarsys.com", "hubspotemail.net", "hubspot.com",
    "emlfiles4.com", "emltrk.com", "substack.com", "klaviyo.com",
    "iterable.com", "braze.com", "movable-ink-1505.com",
    # Deep-linking / attribution
    "branch.io", "bnc.lt", "appsflyer.com", "adjust.com",
    "kochava.com", "singular.net",
    # Ad tech
    "adnxs.com", "demdex.net", "omtrdc.net", "moatads.com", "ltmsphrcl.net",
    "adzonestatic.com", "adsrvr.org", "rubiconproject.com", "pubmatic.com",
    "criteo.com", "taboola.com", "outbrain.com", "quantserve.com",
    "2mdn.net", "serving-sys.com", "doubleclick.net",
    "googlesyndication.com", "googleadservices.com",
    # Registrars / CAs
    "godaddy.com", "gandi.net", "namecheap.com", "name.com", "register.com",
    "digicert.com", "letsencrypt.org", "verisign.com",
    # Big-brand marketing subdomains
    "aa.com", "delta.com", "united.com", "hilton.com", "marriott.com",
    "expedia.com", "nytimes.com", "washingtonpost.com", "cnn.com",
    # Developer APIs / dev tools — long-tail legit sites that threat feeds
    # sometimes misclassify (e.g. PhishTank tagged pokeapi.co with target=Other).
    # Belt-and-suspenders in case the Majestic 1M fetch fails on startup.
    "pokeapi.co",
}

MAJESTIC_URL = "https://downloads.majestic.com/majestic_million.csv"
# Top 1M is the well-known "reputable domain" floor — a site with enough
# backlinks to make Majestic's top 1M is very rarely phishing. We prefer
# this over the top 100K because threat feeds occasionally misclassify
# long-tail legit domains (e.g. PhishTank once flagged pokeapi.co at #150K
# with target=Other), and the popular-domain check is our safety net.
MAJESTIC_LIMIT = 1_000_000


class PopularDomains:
    """Singleton providing an in-memory set of popular domains."""

    def __init__(self):
        # Start with the curated vendor list so is_popular() works even before
        # the Majestic fetch completes.
        self._domains: set[str] = set(VENDOR_ALLOWLIST)

    async def load_majestic(self, url: str = MAJESTIC_URL, limit: int = MAJESTIC_LIMIT) -> int:
        """Load Majestic Million and merge into the popular set.

        Falls back silently to the vendor list only on any error.
        Returns the total size of the popular set after loading.
        """
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    logger.warning(f"Majestic returned {resp.status_code}, keeping vendor list only")
                    return len(self._domains)
                majestic: set[str] = set()
                for i, line in enumerate(resp.text.strip().split("\n")):
                    if i == 0:
                        continue  # header
                    if i > limit:
                        break
                    parts = line.split(",")
                    if len(parts) >= 3:
                        majestic.add(parts[2].lower().strip())
                self._domains = majestic | VENDOR_ALLOWLIST
                logger.info(
                    f"Loaded {len(majestic)} Majestic domains, "
                    f"total popular set: {len(self._domains)}"
                )
        except Exception as e:
            logger.warning(f"Failed to load Majestic, keeping vendor list only: {e}")
        return len(self._domains)

    def is_popular(self, domain: str) -> bool:
        """True if the domain's eTLD+1 is in the popular set.

        Matches on eTLD+1 so any subdomain — however deep or hash-tokened —
        of a popular vendor root inherits the allow. This is what catches
        `l.loyalty.ms.aa.com`, `tlbrb54....sfmc-marketing.com`, etc.
        """
        if not domain:
            return False
        base = extract_base_domain(domain)
        return base in self._domains

    def size(self) -> int:
        return len(self._domains)


# Module-level singleton
_instance: Optional[PopularDomains] = None


def get_instance() -> PopularDomains:
    """Return the process-wide singleton."""
    global _instance
    if _instance is None:
        _instance = PopularDomains()
    return _instance


def reset_for_tests() -> None:
    """Test helper: clear the singleton so each test can start fresh."""
    global _instance
    _instance = None
