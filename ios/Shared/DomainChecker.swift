import Foundation

public final class DomainChecker {

    // Known phishing domains — in production, covered by bloom filter blacklist
    static let blacklist: Set<String> = [
        "brou-seguro.com",
        "itau-homebanking.net",
        "santander-verificacion.com",
        "brou-actualizacion.com",
        "scotiabank-uy.net",
        "mi-brou.com",
        "itau-uruguay.net",
        "phishing-test.example.com",
        "24defend-block-test.com",
    ]

    // Official domains — in production, covered by bloom filter whitelist.
    // Multi-country brand roots are ALL listed explicitly, because the BK-tree
    // fuzzy pass (step 4) will otherwise flag legit regional variants as
    // "similar to" the Uruguayan root (e.g. itau.com.br vs itau.com.uy has
    // Levenshtein distance 2 → similarity 0.83 → false-positive yellow).
    static let whitelist: [String] = [
        // BROU (UY only)
        "brou.com.uy",
        // Itaú — UY + regional. Chile serves under BOTH itau.cl AND itau.com.cl
        // (bare ccTLD and commercial form) — list both to skip the fuzzy check.
        "itau.com.uy",
        "itau.com.br", "itau.com.ar", "itau.cl", "itau.com.cl",
        "itau.com.co", "itau.com.py",
        // Santander — UY + regional. Same duplication for .cl variants.
        "santander.com.uy",
        "santander.com.br", "santander.com.ar", "santander.com.mx",
        "santander.cl", "santander.com.cl", "santander.com.pe", "santander.com",
        // Scotiabank — UY + regional
        "scotiabank.com.uy",
        "scotiabank.com", "scotiabank.com.ar", "scotiabank.com.mx",
        "scotiabank.com.pe", "scotiabank.cl", "scotiabank.com.cl",
        "scotiabank.com.co",
        // HSBC — UY + regional
        "hsbc.com.uy",
        "hsbc.com", "hsbc.com.ar", "hsbc.com.mx", "hsbc.com.br",
        // BBVA — UY + regional
        "bbva.com.uy",
        "bbva.com", "bbva.com.ar", "bbva.com.mx", "bbva.com.co",
        "bbva.com.pe", "bbva.cl", "bbva.com.cl", "bbva.es",
        // Mercado Libre / Mercado Pago — LATAM-wide
        "mercadolibre.com.uy", "mercadolibre.com",
        "mercadolibre.com.ar", "mercadolibre.com.br", "mercadolibre.com.mx",
        "mercadolibre.com.co", "mercadolibre.cl", "mercadolibre.com.pe",
        "mercadopago.com", "mercadopago.com.uy",
        "mercadopago.com.ar", "mercadopago.com.br", "mercadopago.com.mx",
        "mercadopago.com.co", "mercadopago.cl", "mercadopago.com.pe",
        // PedidosYa — LATAM-wide
        "pedidosya.com", "pedidosya.com.uy",
        "pedidosya.com.ar", "pedidosya.com.bo", "pedidosya.com.pa",
        "pedidosya.com.py", "pedidosya.com.pe",
        // Telcos
        "antel.com.uy",
        "movistar.com.uy", "movistar.com", "movistar.com.ar",
        "movistar.es", "movistar.com.pe", "movistar.com.mx",
        "claro.com.uy", "claro.com", "claro.com.ar", "claro.com.br",
        "claro.com.mx", "claro.com.co", "claro.com.pe", "claro.cl",
    ]

    // BK-tree built from whitelist base domains — O(log n) fuzzy search
    private static let whitelistTree: BKTree = {
        let tree = BKTree()
        for domain in whitelist {
            tree.insert(BloomFilterStore.extractBaseDomain(domain))
        }
        return tree
    }()

    public enum Result {
        case blocked(reason: String)
        case warned(reason: String)
        case allowed
    }

    public static func check(domain: String) -> Result {
        let normalized = domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))

        if normalized.isEmpty || normalized.hasSuffix(".local") || normalized.hasSuffix(".arpa") {
            return .allowed
        }

        // 1. Exact blacklist match
        if blacklist.contains(normalized) {
            return .blocked(reason: "Known phishing domain")
        }

        // 2. Subdomain of blacklisted domain
        for bad in blacklist {
            if normalized.hasSuffix(".\(bad)") {
                return .blocked(reason: "Subdomain of known phishing domain")
            }
        }

        // 3. Exact whitelist match
        for official in whitelist {
            if normalized == official || normalized.hasSuffix(".\(official)") {
                return .allowed
            }
        }

        // 4. BK-tree fuzzy search: find whitelist domains within edit distance 3
        let baseDomain = BloomFilterStore.extractBaseDomain(normalized)
        let matches = whitelistTree.search(baseDomain, maxDistance: 3)

        for (match, distance) in matches {
            guard distance > 0 else { continue }
            let maxLen = max(baseDomain.count, match.count)
            guard maxLen > 0 else { continue }
            let similarity = 1.0 - (Double(distance) / Double(maxLen))
            if similarity >= 0.70 {
                return .warned(reason: "Unverified domain similar to \(match)")
            }
        }

        // 5. Skip known infrastructure/CDN domains — never flag these
        if isInfrastructureDomain(normalized) {
            return .allowed
        }

        // 6. Brand rule engine: catches brand impersonation that Levenshtein misses
        //    ONLY flag if there's a brand match — don't flag random infrastructure domains
        let risk = BrandRuleEngine.assess(normalized)
        if risk.isHighRisk && risk.matchedBrand != nil {
            return .warned(reason: "Suspicious: \(risk.signals.first ?? "brand impersonation detected")")
        }

        // 7. ML classifier: runs on ALL domains (infrastructure already filtered above)
        //    Now a silent screener — returns .warned which the tunnel handles silently
        //    (submits to API in background, no user-facing action)
        let prediction = PhishingClassifier.predict(normalized)
        if prediction.isHighRisk {
            return .warned(reason: "ML model: phishing probability \(Int(prediction.score * 100))%")
        }

        // 8. Silent allow
        return .allowed
    }

    // MARK: - Infrastructure domain filter

    /// Known CDN, system, and infrastructure domains that should never be flagged.
    /// Stored as a Set for O(1) lookup via base domain extraction.
    private static let infrastructureSet: Set<String> = [
        // CDNs
        "akamaiedge.net", "akamai.net", "akadns.net", "akamaized.net", "akamaihd.net",
        "cloudfront.net", "cloudflare.com", "cloudflare.net", "fastly.net",
        "edgekey.net", "edgesuite.net", "llnwd.net", "footprint.net",
        "jsdelivr.net", "cdnjs.com", "unpkg.com",
        // Apple
        "apple.com", "apple-dns.net", "icloud.com", "mzstatic.com",
        "aaplimg.com", "cdn-apple.com", "apple-cloudkit.com",
        // Google
        "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
        "googleusercontent.com", "google-analytics.com", "googletagmanager.com",
        "googlesyndication.com", "googleadservices.com", "gvt1.com",
        "gvt2.com", "1e100.net", "google.co", "google.com.uy",
        // Microsoft
        "microsoft.com", "msedge.net", "azure.com", "azurefd.net",
        "windows.net", "office.com", "office365.com",
        // Meta
        "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.net",
        // Amazon
        "amazonaws.com", "amazon.com", "cloudfront.net", "aws.amazon.com",
        // Ads / analytics / tracking (legitimate infra, not phishing)
        "doubleclick.net", "crashlytics.com", "firebaseio.com",
        "appsflyer.com", "branch.io", "adjust.com",
        "app-measurement.com", "sentry.io", "bugsnag.com",
        "newrelic.com", "datadoghq.com", "segment.io", "mixpanel.com",
        "amplitude.com", "hotjar.com", "clarity.ms",
        "adzonestatic.com", "ltmsphrcl.net", "adnxs.com",
        "adsrvr.org", "demdex.net", "omtrdc.net", "scorecardresearch.com",
        "taboola.com", "outbrain.com", "criteo.com", "rubiconproject.com",
        "pubmatic.com", "openx.net", "moatads.com", "serving-sys.com",
        // Social / messaging
        "twitter.com", "x.com", "tiktok.com", "snapchat.com",
        "linkedin.com", "pinterest.com", "reddit.com", "discord.com",
        "telegram.org", "signal.org",
        // Video / streaming
        "youtube.com", "netflix.com", "spotify.com", "twitch.tv",
        // Commerce
        "paypal.com", "stripe.com", "shopify.com", "ebay.com",
        // Common services
        "github.com", "gitlab.com", "stackoverflow.com",
        "wikipedia.org", "wikimedia.org",
        "zoom.us", "slack.com", "notion.so", "figma.com",
        "dropbox.com", "icloud-content.com",
        // DNS / security
        "cloudflare-dns.com", "one.one.one.one",
        "opendns.com", "quad9.net",
        // Uruguay common
        "elobservador.com.uy", "elpais.com.uy", "montevideo.com.uy",
        "subrayado.com.uy", "lr21.com.uy",
        // Our own domain
        "24defend.com",
    ]

    public static func isInfrastructureDomain(_ domain: String) -> Bool {
        // O(1) Set lookup via base domain extraction instead of O(n) suffix scan
        let base = BloomFilterStore.extractBaseDomain(domain)
        return infrastructureSet.contains(base)
    }
}
