"""Feature extraction from domain strings for phishing classification.

All features are extractable from the domain string alone — no network calls.
Designed to run on-device in <1ms.
"""

import math
import re

BRANDS = {
    "brou", "bancorepublica", "itau", "santander", "scotiabank",
    "bbva", "hsbc", "heritage", "bandes", "prex", "oca",
    "mercadopago", "mercadolibre", "pedidosya", "abitab",
    "redpagos", "antel", "movistar", "claro", "bps", "dgi", "gub",
}

PHISHING_WORDS = {
    "actualizar", "actualizacion", "verificar", "verificacion",
    "confirmar", "confirmacion", "validar", "validacion",
    "restablecer", "recuperar", "desbloquear", "reactivar",
    "urgente", "inmediato", "suspension", "suspendido",
    "bloqueo", "bloqueado", "bloquear", "cancelar", "cancelado",
    "seguro", "seguridad", "proteccion", "alerta",
    "soporte", "ayuda", "centro", "servicio",
    "homebanking", "ebanking", "onlinebanking", "banca",
    "transferencia", "clave", "contrasena", "password",
    "pin", "token", "tarjeta", "credencial", "acceso",
    "cuenta", "usuario", "login", "signin", "ingreso",
    "formulario", "datos", "informacion",
    "puntos", "premio", "ganaste", "sorteo", "regalo",
    "beneficio", "promocion", "oferta", "descuento", "cupon",
    "recompensa", "canje", "redimir",
}

HIGH_RISK_TLDS = {
    "xyz", "top", "click", "buzz", "gq", "ml", "cf", "tk",
    "pw", "cc", "club", "icu", "cam", "link", "online",
    "site", "website", "space", "info", "bid", "win", "loan",
}

LOW_RISK_TLDS = {
    "com.uy", "uy", "gub.uy", "edu.uy", "org.uy",
    "com.ar", "com.br", "com.cl", "com.co", "com.mx",
}

FEATURE_NAMES = [
    "domain_length",
    "name_length",            # length without TLD
    "dot_count",
    "hyphen_count",
    "digit_count",
    "digit_ratio",
    "unique_char_ratio",      # entropy proxy
    "consonant_ratio",
    "max_consecutive_consonants",
    "has_brand",              # 1 if contains a brand keyword
    "brand_count",            # how many brand keywords found
    "has_phishing_word",      # 1 if contains a phishing vocabulary word
    "phishing_word_count",
    "brand_phishing_combo",   # 1 if both brand + phishing word
    "has_year_pattern",       # 1 if contains 202X
    "brand_year_combo",       # 1 if brand + year
    "tld_risk",               # 1.0 = high risk, 0.0 = low risk, 0.5 = neutral
    "brand_on_risky_tld",     # 1 if brand + high-risk TLD
    "has_homoglyph",          # 1 if contains 0/1 that could be o/i substitution
    "subdomain_depth",        # number of dots beyond base domain
]


def extract_features(domain: str) -> list[float]:
    """Extract all features from a domain string. Returns list of floats."""
    d = domain.lower().strip(".")
    parts = d.split(".")
    tld = _get_tld(d)
    name = _get_name_part(d, tld)

    # Basic string features
    domain_length = float(len(d))
    name_length = float(len(name))
    dot_count = float(d.count("."))
    hyphen_count = float(name.count("-"))
    digit_count = float(sum(1 for c in name if c.isdigit()))
    digit_ratio = digit_count / max(len(name), 1)

    # Character diversity (entropy proxy)
    name_alpha = name.replace("-", "").replace(".", "")
    unique_chars = len(set(name_alpha))
    unique_char_ratio = unique_chars / max(len(name_alpha), 1)

    # Consonant analysis
    vowels = set("aeiou")
    consonants = [c for c in name_alpha if c.isalpha() and c not in vowels]
    consonant_ratio = len(consonants) / max(len(name_alpha), 1)
    max_consec = _max_consecutive_consonants(name_alpha)

    # Brand detection
    found_brands = [b for b in BRANDS if b in d]
    has_brand = 1.0 if found_brands else 0.0
    brand_count = float(len(found_brands))

    # Phishing word detection
    found_phish = [w for w in PHISHING_WORDS if w in d]
    has_phishing_word = 1.0 if found_phish else 0.0
    phishing_word_count = float(len(found_phish))

    # Combo signals
    brand_phishing_combo = 1.0 if found_brands and found_phish else 0.0
    has_year = 1.0 if re.search(r"202[4-9]", d) else 0.0
    brand_year = 1.0 if found_brands and has_year else 0.0

    # TLD risk
    if tld in HIGH_RISK_TLDS:
        tld_risk = 1.0
    elif tld in LOW_RISK_TLDS:
        tld_risk = 0.0
    else:
        tld_risk = 0.5
    brand_on_risky_tld = 1.0 if found_brands and tld_risk == 1.0 else 0.0

    # Homoglyph detection (0 that could be o, 1 that could be i/l)
    has_homoglyph = 1.0 if _detect_homoglyphs(name) else 0.0

    # Subdomain depth
    base_dots = 1 if tld in LOW_RISK_TLDS and "." in tld else 0
    subdomain_depth = max(0, dot_count - 1 - base_dots)

    return [
        domain_length,
        name_length,
        dot_count,
        hyphen_count,
        digit_count,
        digit_ratio,
        unique_char_ratio,
        consonant_ratio,
        float(max_consec),
        has_brand,
        brand_count,
        has_phishing_word,
        phishing_word_count,
        brand_phishing_combo,
        has_year,
        brand_year,
        tld_risk,
        brand_on_risky_tld,
        has_homoglyph,
        subdomain_depth,
    ]


def _get_tld(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) <= 1:
        return ""
    two_part = ".".join(parts[-2:])
    two_part_tlds = {"com.uy", "com.ar", "com.br", "com.mx", "com.co", "com.cl",
                     "co.uk", "com.au", "gub.uy", "org.uy", "edu.uy"}
    if two_part in two_part_tlds:
        return two_part
    return parts[-1]


def _get_name_part(domain: str, tld: str) -> str:
    if tld and domain.endswith(tld):
        name = domain[:-(len(tld) + 1)]  # remove .tld
    else:
        name = domain.rsplit(".", 1)[0] if "." in domain else domain
    return name


def _max_consecutive_consonants(s: str) -> int:
    vowels = set("aeiou0123456789-.")
    max_c = 0
    current = 0
    for c in s:
        if c.isalpha() and c not in vowels:
            current += 1
            max_c = max(max_c, current)
        else:
            current = 0
    return max_c


def _detect_homoglyphs(name: str) -> bool:
    """Detect potential homoglyph substitutions.

    Returns True if replacing digits (0→o, 1→i/l) in the name would create
    a brand match that doesn't exist in the original string.
    """
    # Only worth checking if name contains digits that could be substitutions
    if "0" not in name and "1" not in name:
        return False

    test1 = name.replace("0", "o").replace("1", "i")
    test2 = name.replace("0", "o").replace("1", "l")

    for brand in BRANDS:
        # Skip brands already present in the original (not a homoglyph)
        if brand in name:
            continue
        # Check if substitution reveals a brand
        if brand in test1 or brand in test2:
            return True
    return False
