import Foundation

/// Phase 1: Uruguay-specific rule engine for on-device phishing detection.
/// Catches domains that Levenshtein misses by detecting brand impersonation patterns.
/// Runs in <1ms, no network, no ML model needed.
public final class BrandRuleEngine {

    // MARK: - Uruguay financial institution brands

    static let brands: Set<String> = [
        // Banks
        "brou", "bancorepublica", "itau", "santander", "scotiabank",
        "bbva", "hsbc", "heritage", "bandes",
        // Payment / fintech
        "prex", "oca", "visa", "mastercard", "mercadopago", "mercadolibre",
        // Services
        "pedidosya", "abitab", "redpagos",
        // Telecom
        "antel", "movistar", "claro",
        // Government
        "bps", "dgi", "agesic", "gub",
    ]

    // MARK: - Spanish phishing vocabulary

    static let phishingWords: Set<String> = [
        // Action words
        "actualizar", "actualizacion", "verificar", "verificacion",
        "confirmar", "confirmacion", "validar", "validacion",
        "restablecer", "recuperar", "desbloquear", "reactivar",
        // Urgency
        "urgente", "inmediato", "suspension", "suspendido",
        "bloqueo", "bloqueado", "bloquear", "cancelar", "cancelado",
        "vencido", "vencimiento", "expira", "expirado",
        // Credentials
        "homebanking", "ebanking", "onlinebanking", "banca",
        "transferencia", "clave", "contrasena", "password",
        "pin", "token", "tarjeta", "credencial", "acceso",
        "cuenta", "usuario",
        // Security theater
        "seguro", "seguridad", "proteccion", "alerta",
        "soporte", "ayuda", "centro", "servicio",
        // Common phishing patterns
        "login", "signin", "logon", "ingreso", "ingresar",
        "formulario", "datos", "informacion",
    ]

    // MARK: - TLD risk scores

    static let highRiskTLDs: Set<String> = [
        "xyz", "top", "click", "buzz", "gq", "ml", "cf", "tk",
        "pw", "cc", "club", "icu", "cam", "link", "online",
        "site", "website", "space", "info", "bid", "win", "loan",
        "racing", "review", "download", "stream", "trade", "date",
    ]

    static let lowRiskTLDs: Set<String> = [
        "com.uy", "uy", "gub.uy", "edu.uy", "org.uy", "mil.uy",
    ]

    // MARK: - Risk scoring

    public struct RiskAssessment {
        public let score: Double        // 0.0 to 1.0
        public let signals: [String]
        public let matchedBrand: String?

        public var isHighRisk: Bool { score >= 0.7 }
        public var isSuspicious: Bool { score >= 0.4 }
    }

    /// Analyze a domain for brand impersonation patterns.
    /// Returns a risk assessment with score and signals.
    public static func assess(_ domain: String) -> RiskAssessment {
        let normalized = domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let baseDomain = BloomFilterStore.extractBaseDomain(normalized)

        // Strip TLD to get the "name" part
        let namePart = extractNamePart(normalized)
        let nameTokens = tokenize(namePart)

        var score = 0.0
        var signals: [String] = []
        var matchedBrand: String? = nil

        // 1. Brand keyword detection
        let foundBrands = brands.filter { brand in
            namePart.contains(brand)
        }

        if !foundBrands.isEmpty {
            matchedBrand = foundBrands.first

            // Check if the domain IS the official brand domain (whitelist check upstream handles this,
            // but double-check here: brand as the only name component = probably legitimate)
            let isBrandAlone = foundBrands.contains { brand in
                namePart == brand || namePart == "www\(brand)"
            }

            if !isBrandAlone {
                score += 0.35
                signals.append("Contains brand keyword: \(foundBrands.joined(separator: ", "))")
            }
        }

        // 2. Phishing word detection
        let foundPhishWords = phishingWords.filter { word in
            namePart.contains(word)
        }

        if !foundPhishWords.isEmpty {
            score += 0.2
            signals.append("Contains phishing vocabulary: \(foundPhishWords.prefix(3).joined(separator: ", "))")
        }

        // 3. Brand + phishing word combo (strongest signal)
        if !foundBrands.isEmpty && !foundPhishWords.isEmpty {
            score += 0.25
            signals.append("Brand + phishing word combination")
        }

        // 4. TLD risk
        let tld = extractTLD(normalized)
        if highRiskTLDs.contains(tld) {
            score += 0.15
            signals.append("High-risk TLD (.\(tld))")

            // Brand on high-risk TLD = very suspicious
            if !foundBrands.isEmpty {
                score += 0.15
                signals.append("Brand keyword on high-risk TLD")
            }
        }

        // 5. Structural signals
        let hyphens = namePart.filter { $0 == "-" }.count
        if hyphens >= 2 {
            score += 0.1
            signals.append("Multiple hyphens (\(hyphens))")
        }

        let digits = namePart.filter { $0.isNumber }.count
        if digits >= 3 {
            score += 0.05
            signals.append("Contains \(digits) digits")
        }

        if namePart.count > 25 {
            score += 0.05
            signals.append("Long domain name (\(namePart.count) chars)")
        }

        // 6. Year patterns (brou-2026, itau2025) — common in phishing
        let yearPattern = namePart.range(of: "202[4-9]", options: .regularExpression)
        if yearPattern != nil && !foundBrands.isEmpty {
            score += 0.15
            signals.append("Brand + year pattern (common in phishing campaigns)")
        }

        return RiskAssessment(
            score: min(score, 1.0),
            signals: signals,
            matchedBrand: matchedBrand
        )
    }

    // MARK: - Helpers

    /// Extract the "name" part of a domain (everything before the TLD).
    /// brou-seguro.com.uy → brou-seguro
    /// login.itau-verificar.xyz → login.itau-verificar
    private static func extractNamePart(_ domain: String) -> String {
        let parts = domain.split(separator: ".")
        if parts.count <= 1 { return domain }

        let twoPartTLDs: Set<String> = ["com.uy", "com.ar", "com.br", "com.mx", "com.co", "com.cl",
                                         "co.uk", "com.au", "gub.uy", "org.uy", "edu.uy"]
        let lastTwo = parts.suffix(2).joined(separator: ".")
        if twoPartTLDs.contains(lastTwo) {
            return parts.dropLast(2).joined(separator: ".")
        }
        return parts.dropLast(1).joined(separator: ".")
    }

    /// Extract the TLD of a domain.
    private static func extractTLD(_ domain: String) -> String {
        let parts = domain.split(separator: ".")
        if parts.count <= 1 { return domain }
        let lastTwo = parts.suffix(2).joined(separator: ".")
        let twoPartTLDs: Set<String> = ["com.uy", "com.ar", "com.br", "com.mx", "com.co", "com.cl",
                                         "co.uk", "com.au", "gub.uy", "org.uy", "edu.uy"]
        if twoPartTLDs.contains(lastTwo) { return lastTwo }
        return String(parts.last ?? "")
    }

    /// Tokenize a domain name part by hyphens, dots, and digit/letter boundaries.
    private static func tokenize(_ name: String) -> [String] {
        let separators = CharacterSet(charactersIn: "-._")
        return name.components(separatedBy: separators).filter { !$0.isEmpty }
    }
}
