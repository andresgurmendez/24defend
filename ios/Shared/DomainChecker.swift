import Foundation

public final class DomainChecker {

    // Known phishing domains — in production, fetched from Redis server
    static let blacklist: Set<String> = [
        // Fake Uruguayan bank domains (demo)
        "brou-seguro.com",
        "itau-homebanking.net",
        "santander-verificacion.com",
        "brou-actualizacion.com",
        "scotiabank-uy.net",
        "mi-brou.com",
        "itau-uruguay.net",
        // Test domains — use these to verify blocking works
        "phishing-test.example.com",
        "24defend-block-test.com",
    ]

    // Official domains — contractual whitelist from partner institutions
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

    public enum Result {
        /// Red: blacklisted domain — DNS blocked
        case blocked(reason: String)
        /// Yellow: not in any list but similar to a whitelisted domain — allow but warn
        case warned(reason: String)
        /// Silent: whitelisted, no list + no similarity, or system domain
        case allowed
    }

    public static func check(domain: String) -> Result {
        let normalized = domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))

        // Skip internal / system domains
        if normalized.isEmpty || normalized.hasSuffix(".local") || normalized.hasSuffix(".arpa") {
            return .allowed
        }

        // 1. Exact blacklist match → RED block
        if blacklist.contains(normalized) {
            return .blocked(reason: "Known phishing domain")
        }

        // 2. Subdomain of a blacklisted domain → RED block
        for bad in blacklist {
            if normalized.hasSuffix(".\(bad)") {
                return .blocked(reason: "Subdomain of known phishing domain")
            }
        }

        // 3. Exact whitelist match → silent allow
        for official in whitelist {
            if normalized == official || normalized.hasSuffix(".\(official)") {
                return .allowed
            }
        }

        // 4. Similar to whitelisted domain → YELLOW warn (allow but notify)
        let baseDomain = extractBaseDomain(normalized)
        for official in whitelist {
            let officialBase = extractBaseDomain(official)
            guard baseDomain != officialBase else { continue }

            let distance = levenshtein(baseDomain, officialBase)
            let maxLen = max(baseDomain.count, officialBase.count)
            guard maxLen > 0 else { continue }

            if distance > 0 && distance <= 3 {
                let similarity = 1.0 - (Double(distance) / Double(maxLen))
                if similarity >= 0.70 {
                    return .warned(reason: "Unverified domain similar to \(official)")
                }
            }
        }

        // 5. No list, no similarity → silent allow
        return .allowed
    }

    // MARK: - Helpers

    private static func extractBaseDomain(_ domain: String) -> String {
        let parts = domain.split(separator: ".")
        if parts.count <= 2 { return domain }
        let twoPartTLDs: Set<String> = ["com.uy", "com.ar", "com.br", "com.mx", "com.co", "com.cl", "co.uk", "com.au"]
        let lastTwo = parts.suffix(2).joined(separator: ".")
        if twoPartTLDs.contains(lastTwo) && parts.count >= 3 {
            return parts.suffix(3).joined(separator: ".")
        }
        return parts.suffix(2).joined(separator: ".")
    }

    private static func levenshtein(_ s1: String, _ s2: String) -> Int {
        let a = Array(s1)
        let b = Array(s2)
        let m = a.count, n = b.count
        if m == 0 { return n }
        if n == 0 { return m }

        var prev = Array(0...n)
        var curr = Array(repeating: 0, count: n + 1)

        for i in 1...m {
            curr[0] = i
            for j in 1...n {
                let cost = a[i - 1] == b[j - 1] ? 0 : 1
                curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
            }
            swap(&prev, &curr)
        }
        return prev[n]
    }
}
