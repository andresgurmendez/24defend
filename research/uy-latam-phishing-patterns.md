# Uruguay & LatAm Phishing Domain Patterns

Research conducted April 2026. Sources: WeLiveSecurity (ESET), CERTuy, Axur, BioCatch,
Hackmetrix, NoCaigas.uy, Kaspersky, El Observador, PhishTank, OpenPhish.

---

## 1. Market context

### Uruguay
- 14,264 cyber incidents in 2024, phishing as the #1 modality (CERTuy 2025)
- Only 12% of scams are formally reported (INE estimate)
- BROU and Itau are the most impersonated institutions
- Attackers typically request: cedula number, password, and 6-digit token
- NoCaigas.uy is the national phishing reporting platform (coordinated with CERTuy)
- In 2025, more cyberattacks against sensitive UY government agencies than in the previous five years combined

### LatAm
- 155% increase in social engineering scams in 2025 (BioCatch)
- 397 million phishing attempts blocked in 12 months across LatAm (Kaspersky 2024)
- Account takeover attempts almost tripled between end of 2024 and beginning of 2026
- Mexico saw 324% increase in account takeover cases
- WhatsApp is the #1 delivery channel in the region
- Financial services are the #1 target vertical
- Phishing kits have lowered the barrier — non-technical attackers can launch campaigns

---

## 2. Domain generation patterns observed in the wild

### Pattern 1: Brand + action word
The most common pattern. Combines a known brand name with a Spanish action/urgency word.

    brou-seguro.com
    itau-homebanking.net
    santander-verificacion.uy
    brou-actualizacion.com
    confirmar-datos-itau.click
    verificar-brou.top
    desbloquear-santander.xyz
    cuenta-brou-suspendida.com

Structure: `{brand}-{action}.{tld}` or `{action}-{brand}.{tld}` or `{action}-{brand}-{action}.{tld}`

### Pattern 2: TLD swapping
Official domain uses `.com.uy` but the fake uses a different TLD.

    Official: brou.com.uy    → Fake: brou.com, brou.net, brou.uy, brou.xyz
    Official: itau.com.uy    → Fake: itau-uy.com, itau.xyz, itau.top
    Official: banco.com.uy   → Fake: banco-uy.com (documented by NoCaigas.uy)

This is the simplest attack. The domain looks almost right but the TLD is wrong.

### Pattern 3: Homoglyphs / character substitution
Replace characters with visually similar ones.

    brou.com.uy  → br0u.com.uy (zero for 'o')
    itau.com.uy  → 1tau.com.uy (one for 'i')
    itau.com.uy  → ltau.com.uy (lowercase L for 'i')
    santander    → sаntander (cyrillic 'а' for latin 'a')
    brou         → brоu (cyrillic 'о' for latin 'o')

Documented by Axur and WeLiveSecurity as common in LatAm. Hard to detect visually,
especially on mobile screens.

### Pattern 4: Subdomain tricks
The real brand appears as a subdomain of an attacker-controlled domain.

    brou.com.uy.login.evil.com
    login.brou-seguro.com
    secure.homebanking-brou.com
    www.brou.com.uy.verify.attacker.xyz
    homebanking.brou.fake-domain.com

The user sees "brou.com.uy" in the URL but the actual domain is `evil.com` or `attacker.xyz`.

### Pattern 5: Spanish urgency vocabulary + brand
Domains designed to create panic. Combine brand names with urgency words.

    actualizacion-brou-2026.com
    verificar-itau.xyz
    bloqueo-santander.top
    cuenta-suspendida-brou.com
    alerta-seguridad-itau.net
    soporte-brou-urgente.com
    reactivar-cuenta-santander.click
    confirmar-tarjeta-brou.xyz

Common urgency words observed in UY/LatAm campaigns:
- actualizar, actualizacion
- verificar, verificacion
- confirmar, confirmacion
- bloqueo, bloqueado, bloquear
- suspension, suspendido
- urgente, inmediato
- desbloquear, reactivar
- vencido, vencimiento, expira

### Pattern 6: Year + brand (campaign-specific)
Attackers append the current year to make domains look timely.

    brou-2026.com
    itau2025.net
    santander-actualizacion-2026.xyz
    prex-verificar-2026.top
    oca-seguridad-2026.com

Year patterns rotate annually. Domains are registered cheaply and used for 24-72 hours
before being abandoned.

### Pattern 7: Service-specific subdomains
Mimic the structure of real banking subdomains.

    homebanking-brou.com (real: homebanking.brou.com.uy)
    ebrou-login.com (real: ebrou.com.uy)
    itau-online.net (real: online.itau.com.uy)
    mi-santander.xyz (real: misantander.santander.com.uy)
    app-brou.com (real: app.brou.com.uy)

---

## 3. Email sender patterns (not domain-based but contextually relevant)

- Phishing emails for BROU campaigns were sent from Hotmail/Gmail addresses, not
  official bank domains (WeLiveSecurity 2022)
- Sender addresses like: soporte@brou-seguro.com, seguridad@itau-verificar.com
- The email body typically claims: "temporary account block", "unauthorized access attempt",
  "verify your identity within 24 hours"
- After credential entry, fake sites show a "verifying data" timer while the attacker
  attempts real-time login to the legitimate bank site and triggers 2FA codes

---

## 4. Attack lifecycle

1. Attacker registers domain (cheap TLD, often .xyz, .top, .click — under $2)
2. Sets up Let's Encrypt certificate (free, automated, issued in minutes)
3. Clones the bank's login page (kits available for $50-200)
4. Distributes link via WhatsApp, SMS, or email with urgency message
5. Collects credentials + 2FA codes in real-time
6. Domain is active for 24-72 hours, then abandoned
7. New domain registered, cycle repeats

Implications for detection:
- Domain age < 7 days + brand keyword = extremely high risk
- Free CA cert + brand keyword = high risk
- Domain lifespan is short — detection must be fast (minutes, not days)

---

## 5. Institutions most targeted in Uruguay

Ranked by frequency of observed campaigns:

1. BROU (Banco de la Republica Oriental del Uruguay) — by far the most targeted
2. Itau Uruguay
3. Santander Uruguay
4. Scotiabank Uruguay
5. OCA (credit card)
6. Prex (fintech)
7. MercadoPago / MercadoLibre
8. Abitab / RedPagos (payment networks)
9. Antel (telecom — SIM/account fraud)
10. Government services (BPS, DGI) — tax refund scams

---

## 6. Key vocabulary for synthetic data generation

### Brand keywords (25)
brou, bancorepublica, itau, santander, scotiabank, bbva, hsbc, heritage, bandes,
prex, oca, visa, mastercard, mercadopago, mercadolibre, pedidosya, abitab,
redpagos, antel, movistar, claro, bps, dgi, agesic, gub

### Spanish phishing words (40+)
actualizar, actualizacion, verificar, verificacion, confirmar, confirmacion,
validar, validacion, restablecer, recuperar, desbloquear, reactivar,
urgente, inmediato, suspension, suspendido, bloqueo, bloqueado, bloquear,
cancelar, cancelado, vencido, vencimiento, expira, expirado,
homebanking, ebanking, onlinebanking, banca, transferencia, clave,
contrasena, password, pin, token, tarjeta, credencial, acceso, cuenta,
usuario, seguro, seguridad, proteccion, alerta, soporte, ayuda, centro,
servicio, login, signin, ingreso, ingresar, formulario, datos, informacion

### High-risk TLDs
xyz, top, click, buzz, gq, ml, cf, tk, pw, cc, club, icu, cam, link,
online, site, website, space, info, bid, win, loan

### Connecting patterns
- Hyphens between words: `brand-action.tld`
- No separator: `brandaction.tld`
- Dot separator (subdomain): `action.brand.tld`
- Year suffix: `brand-action-2026.tld`
- Country hint: `brand-uy.tld`, `mi-brand.tld`

---

## 7. Implications for model training

### Feature engineering priorities
1. **Brand keyword presence** — strongest single signal
2. **Phishing vocabulary presence** — second strongest
3. **Brand + phishing combo** — near-certain indicator
4. **TLD risk** — .xyz/.top/.click with brand = very high risk
5. **Domain age** — <7 days with brand = critical
6. **Hyphen count** — legitimate domains rarely have 2+ hyphens
7. **Year pattern** — 202X in domain + brand = campaign indicator
8. **Homoglyph detection** — character substitution (0/o, 1/i/l)
9. **Subdomain depth** — deep nesting with brand buried inside
10. **Certificate issuer** — free CA on brand domain = suspicious

### Training data composition
- Positive (legitimate): 652 UY institution domains from CT logs
- Negative (phishing): ~28K global phishing from public feeds + synthetic UY-specific
- Synthetic negative: generated from patterns 1-7 above, ~5K-10K domains
- The model should achieve >95% recall on brand impersonation with <0.1% FP rate on
  Tranco top 100K

---

## Sources

- WeLiveSecurity (ESET) - BROU phishing wave, August 2022
  https://www.welivesecurity.com/la-es/2022/08/17/correos-phishing-suplantando-identidad-banco-republica-uruguay/
- WeLiveSecurity (ESET) - Itau fake sites, January 2023
  https://www.welivesecurity.com/la-es/2023/01/24/sitios-falsos-banco-itau-buscan-robar-credenciales-bancarias/
- NoCaigas.uy - Uruguay national phishing reporting platform
  https://nocaigas.uy/
- BioCatch - 155% increase in LatAm scam attempts, April 2026
  https://www.biocatch.com/press-release/latin-american-banks-see-155-increase-in-scam-attempts
- Hackmetrix - 5 most common phishing types in LatAm
  https://blog.hackmetrix.com/los-5-tipos-de-phishing-mas-comunes-en-latinoamerica/
- Axur - Spear phishing and deceptive domain names
  https://blog.axur.com/es-es/spear-phishing-dominios-enganosos
- El Observador - UY cyberattacks 2025 surpass previous 5 years
  https://www.elobservador.com.uy/nacional/en-2025-hubo-mas-ciberataques-contra-organismos-sensibles-uruguay-que-la-suma-los-cinco-anos-anteriores-n6029760
- Inversion.uy - How to protect against electronic fraud in UY
  https://inversion.uy/como-protegerse-de-estafas-electronicas-phishing-y-fraudes-en-uruguay/
- CERTuy - Phishing prevention guide
  https://www.gub.uy/centro-nacional-respuesta-incidentes-seguridad-informatica/comunicacion/publicaciones/phishing-como-evitarlo-y-que-hacer-en-caso-de-ser-victima-de-un-ataque
- BROU - Fraud information page
  https://www.brou.com.uy/institucional/seguridad/fraudes
- Itau Uruguay - Cybersecurity page
  https://www.itau.com.uy/inst/ciberseguridad.html
- DarkReading - Fraud in mobile-first Latin America
  https://www.darkreading.com/cyberattacks-data-breaches/fraud-mobile-first-latin-america
- Correo Uruguayo - Digital fraud alerts
  https://www.correo.com.uy/noticias/-/asset_publisher/x68NfmqmDEKm/content/comunicado-fraudes-electronicos-correo-uruguayo
