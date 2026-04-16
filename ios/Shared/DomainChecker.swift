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

        // 5. Brand rule engine: catches brand impersonation that Levenshtein misses
        //    e.g., "actualizacion-brou-2026.com", "itau-verificar-cuenta.xyz"
        let risk = BrandRuleEngine.assess(normalized)
        if risk.isHighRisk {
            return .warned(reason: "Suspicious: \(risk.signals.first ?? "brand impersonation detected")")
        }

        // 6. ML classifier: logistic regression on 20 domain features (AUC 0.9974)
        let prediction = PhishingClassifier.predict(normalized)
        if prediction.isHighRisk {
            return .warned(reason: "ML model: phishing probability \(Int(prediction.score * 100))%")
        }

        // 7. Silent allow
        return .allowed
    }
}
