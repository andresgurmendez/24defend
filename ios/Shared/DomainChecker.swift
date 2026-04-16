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

    // Official domains — in production, covered by bloom filter whitelist
    static let whitelist: [String] = [
        "brou.com.uy",
        "itau.com.uy",
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

        // 7. ML classifier: ONLY run if brand rule engine found a brand keyword
        //    This prevents false positives on CDN/infrastructure domains
        if risk.matchedBrand != nil {
            let prediction = PhishingClassifier.predict(normalized)
            if prediction.isHighRisk {
                return .warned(reason: "ML model: phishing probability \(Int(prediction.score * 100))%")
            }
        }

        // 8. Silent allow
        return .allowed
    }

    // MARK: - Infrastructure domain filter

    /// Known CDN, system, and infrastructure domain suffixes that should never be flagged.
    private static let infrastructureSuffixes: [String] = [
        // CDNs
        "akamaiedge.net", "akamai.net", "akadns.net", "akamaized.net",
        "cloudfront.net", "cloudflare.com", "fastly.net", "edgekey.net",
        "edgesuite.net", "llnwd.net", "footprint.net",
        // Apple
        "apple.com", "apple-dns.net", "icloud.com", "mzstatic.com",
        "aaplimg.com", "cdn-apple.com", "apple-cloudkit.com",
        // Google
        "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
        "googleusercontent.com", "google-analytics.com", "gvt1.com",
        "gvt2.com", "1e100.net",
        // Microsoft
        "microsoft.com", "msedge.net", "azure.com", "azurefd.net",
        "windows.net", "office.com", "office365.com",
        // Meta
        "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.net",
        // Amazon
        "amazonaws.com", "amazon.com", "cloudfront.net",
        // Other common infra
        "doubleclick.net", "crashlytics.com", "firebaseio.com",
        "appsflyer.com", "branch.io", "adjust.com",
    ]

    private static func isInfrastructureDomain(_ domain: String) -> Bool {
        for suffix in infrastructureSuffixes {
            if domain == suffix || domain.hasSuffix(".\(suffix)") {
                return true
            }
        }
        return false
    }
}
