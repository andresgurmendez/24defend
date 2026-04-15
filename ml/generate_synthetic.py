#!/usr/bin/env python3
"""Generate synthetic phishing domains based on UY/LatAm patterns.

Uses the 7 documented attack patterns from research/uy-latam-phishing-patterns.md
to create realistic training data.
"""

import itertools
import random

BRANDS = [
    "brou", "bancorepublica", "itau", "santander", "scotiabank",
    "bbva", "hsbc", "heritage", "bandes", "prex", "oca",
    "mercadopago", "mercadolibre", "pedidosya", "abitab",
    "redpagos", "antel", "movistar", "claro", "bps", "dgi", "gub",
]

PHISHING_WORDS = [
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
]

HIGH_RISK_TLDS = [
    "xyz", "top", "click", "buzz", "gq", "ml", "cf", "tk",
    "pw", "cc", "club", "icu", "cam", "link", "online",
    "site", "space", "info", "bid", "win",
]

NEUTRAL_TLDS = ["com", "net", "org", "io"]

YEARS = ["2024", "2025", "2026", "2027"]

PREFIXES = ["mi", "app", "web", "login", "secure", "portal", "online", "nuevo", "nueva"]

HOMOGLYPH_MAP = {
    "o": ["0"],
    "i": ["1", "l"],
    "l": ["1", "i"],
    "a": ["4"],
    "e": ["3"],
    "s": ["5"],
}


def pattern1_brand_action(n: int) -> list[str]:
    """Pattern 1: brand-action.tld and action-brand.tld"""
    domains = set()
    for _ in range(n * 3):
        brand = random.choice(BRANDS)
        word = random.choice(PHISHING_WORDS)
        tld = random.choice(HIGH_RISK_TLDS + NEUTRAL_TLDS)
        sep = random.choice(["-", ""])

        if random.random() < 0.5:
            d = f"{brand}{sep}{word}.{tld}"
        else:
            d = f"{word}{sep}{brand}.{tld}"
        domains.add(d)
        if len(domains) >= n:
            break
    return list(domains)[:n]


def pattern2_tld_swap(n: int) -> list[str]:
    """Pattern 2: Official .com.uy swapped to other TLDs"""
    domains = set()
    for _ in range(n * 3):
        brand = random.choice(BRANDS)
        tld = random.choice(HIGH_RISK_TLDS + NEUTRAL_TLDS + ["uy"])
        variants = [
            f"{brand}.{tld}",
            f"{brand}-uy.{tld}",
            f"{brand}-uruguay.{tld}",
        ]
        domains.add(random.choice(variants))
        if len(domains) >= n:
            break
    return list(domains)[:n]


def pattern3_homoglyphs(n: int) -> list[str]:
    """Pattern 3: Character substitution (0 for o, 1 for i, etc.)"""
    domains = set()
    for _ in range(n * 5):
        brand = random.choice(BRANDS)
        # Apply 1-2 homoglyph substitutions
        chars = list(brand)
        substitutable = [(i, c) for i, c in enumerate(chars) if c in HOMOGLYPH_MAP]
        if not substitutable:
            continue
        num_subs = min(random.randint(1, 2), len(substitutable))
        for i, c in random.sample(substitutable, num_subs):
            chars[i] = random.choice(HOMOGLYPH_MAP[c])
        modified = "".join(chars)
        if modified == brand:
            continue
        tld = random.choice(["com.uy", "com", "uy", "net"] + HIGH_RISK_TLDS[:5])
        domains.add(f"{modified}.{tld}")
        if len(domains) >= n:
            break
    return list(domains)[:n]


def pattern4_subdomain_trick(n: int) -> list[str]:
    """Pattern 4: Brand buried in subdomain of attacker domain"""
    domains = set()
    attacker_bases = [
        "secure-login", "verify-now", "account-check", "update-info",
        "portal-seguro", "acceso-rapido", "centro-ayuda", "soporte-online",
        "auth-service", "validar-datos",
    ]
    for _ in range(n * 3):
        brand = random.choice(BRANDS)
        attacker = random.choice(attacker_bases)
        tld = random.choice(HIGH_RISK_TLDS[:8] + NEUTRAL_TLDS)
        variants = [
            f"{brand}.com.uy.{attacker}.{tld}",
            f"login.{brand}-{random.choice(PHISHING_WORDS[:10])}.{tld}",
            f"secure.{brand}.{attacker}.{tld}",
            f"www.{brand}.com.uy.{attacker}.{tld}",
            f"homebanking.{brand}.{attacker}.{tld}",
        ]
        domains.add(random.choice(variants))
        if len(domains) >= n:
            break
    return list(domains)[:n]


def pattern5_urgency_combo(n: int) -> list[str]:
    """Pattern 5: Brand + urgency vocabulary + optional year"""
    domains = set()
    for _ in range(n * 3):
        brand = random.choice(BRANDS)
        w1 = random.choice(PHISHING_WORDS)
        tld = random.choice(HIGH_RISK_TLDS + NEUTRAL_TLDS)

        templates = [
            f"{w1}-{brand}-{random.choice(YEARS)}.{tld}",
            f"{brand}-{w1}-{random.choice(YEARS)}.{tld}",
            f"{w1}-{brand}.{tld}",
            f"alerta-{brand}-{w1}.{tld}",
            f"{brand}-cuenta-{w1}.{tld}",
        ]
        domains.add(random.choice(templates))
        if len(domains) >= n:
            break
    return list(domains)[:n]


def pattern6_year_brand(n: int) -> list[str]:
    """Pattern 6: Year appended to brand"""
    domains = set()
    for _ in range(n * 3):
        brand = random.choice(BRANDS)
        year = random.choice(YEARS)
        tld = random.choice(HIGH_RISK_TLDS + NEUTRAL_TLDS)
        sep = random.choice(["-", ""])
        variants = [
            f"{brand}{sep}{year}.{tld}",
            f"{brand}{sep}{year}{sep}{random.choice(PHISHING_WORDS[:10])}.{tld}",
        ]
        domains.add(random.choice(variants))
        if len(domains) >= n:
            break
    return list(domains)[:n]


def pattern7_service_subdomain(n: int) -> list[str]:
    """Pattern 7: Mimic real service subdomains"""
    domains = set()
    services = ["homebanking", "ebrou", "ebanking", "app", "mi", "portal",
                "online", "movil", "digital", "pagos", "transferencias"]
    for _ in range(n * 3):
        brand = random.choice(BRANDS)
        service = random.choice(services)
        tld = random.choice(HIGH_RISK_TLDS[:8] + NEUTRAL_TLDS)
        sep = random.choice(["-", ""])
        variants = [
            f"{service}{sep}{brand}.{tld}",
            f"{brand}{sep}{service}.{tld}",
            f"mi{sep}{brand}{sep}{service}.{tld}",
        ]
        domains.add(random.choice(variants))
        if len(domains) >= n:
            break
    return list(domains)[:n]


def generate_legitimate_domains(n: int) -> list[str]:
    """Generate realistic legitimate domains (not phishing)."""
    legit_patterns = [
        # News/media
        "elobservador.com.uy", "elpais.com.uy", "montevideo.com.uy",
        "ladiaria.com.uy", "subrayado.com.uy", "telenoche.com.uy",
        # E-commerce / services
        "tiendamia.com.uy", "woow.com.uy", "groupon.com.uy",
        # Tech
        "github.com", "stackoverflow.com", "medium.com", "dev.to",
        # Social
        "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
        "tiktok.com", "youtube.com", "whatsapp.com", "telegram.org",
        # Utilities
        "ute.com.uy", "ose.com.uy", "gaseba.com.uy",
        # Education
        "udelar.edu.uy", "ort.edu.uy", "um.edu.uy", "ucudal.edu.uy",
        # Random legit-looking domains
    ]

    random_legit = []
    words = ["solar", "verde", "costa", "playa", "campo", "rio", "monte",
             "piedra", "luna", "tierra", "fuego", "agua", "viento", "nube",
             "flor", "arbol", "bosque", "mar", "lago", "cerro", "valle",
             "cumbre", "norte", "sur", "este", "oeste", "centro", "plaza",
             "calle", "puente", "torre", "casa", "tienda", "cafe", "bar",
             "cocina", "jardin", "taller", "estudio", "grupo", "red"]
    tlds = ["com.uy", "uy", "com", "net", "org", "io"]

    for _ in range(n - len(legit_patterns)):
        w1 = random.choice(words)
        w2 = random.choice(words)
        tld = random.choice(tlds)
        sep = random.choice(["-", "", ""])
        random_legit.append(f"{w1}{sep}{w2}.{tld}")

    return (legit_patterns + random_legit)[:n]


def generate_dataset(
    n_phishing_per_pattern: int = 1000,
    n_legitimate: int = 5000,
) -> list[tuple[str, int]]:
    """Generate full training dataset.

    Returns list of (domain, label) where label=1 is phishing, label=0 is legitimate.
    """
    phishing = []
    phishing += [(d, 1) for d in pattern1_brand_action(n_phishing_per_pattern)]
    phishing += [(d, 1) for d in pattern2_tld_swap(n_phishing_per_pattern)]
    phishing += [(d, 1) for d in pattern3_homoglyphs(n_phishing_per_pattern)]
    phishing += [(d, 1) for d in pattern4_subdomain_trick(n_phishing_per_pattern)]
    phishing += [(d, 1) for d in pattern5_urgency_combo(n_phishing_per_pattern)]
    phishing += [(d, 1) for d in pattern6_year_brand(n_phishing_per_pattern)]
    phishing += [(d, 1) for d in pattern7_service_subdomain(n_phishing_per_pattern)]

    legitimate = [(d, 0) for d in generate_legitimate_domains(n_legitimate)]

    dataset = phishing + legitimate
    random.shuffle(dataset)

    return dataset


if __name__ == "__main__":
    import csv
    import sys

    n_per_pattern = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    n_legit = int(sys.argv[2]) if len(sys.argv) > 2 else 5000

    print(f"Generating synthetic dataset: {n_per_pattern} per pattern, {n_legit} legitimate...")

    dataset = generate_dataset(n_per_pattern, n_legit)

    output = "ml/data/synthetic_domains.csv"
    import os
    os.makedirs(os.path.dirname(output), exist_ok=True)

    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "label"])
        writer.writerows(dataset)

    n_phish = sum(1 for _, l in dataset if l == 1)
    n_legit = sum(1 for _, l in dataset if l == 0)
    print(f"Total: {len(dataset)} domains ({n_phish} phishing, {n_legit} legitimate)")
    print(f"Saved to {output}")

    # Show samples
    print("\nPhishing samples:")
    for d, l in dataset:
        if l == 1:
            print(f"  {d}")
        if sum(1 for dd, ll in dataset[:dataset.index((d, l))+1] if ll == 1) >= 10:
            break

    print("\nLegitimate samples:")
    for d, l in dataset:
        if l == 0:
            print(f"  {d}")
        if sum(1 for dd, ll in dataset[:dataset.index((d, l))+1] if ll == 0) >= 10:
            break
