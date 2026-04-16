import Foundation

/// On-device logistic regression phishing classifier.
/// Trained on 17.5K synthetic domains (7 attack patterns). AUC 0.9974.
/// 20 features, 1 KB model. Runs in <1ms.
public final class PhishingClassifier {

    // MARK: - Model weights

    /// Hardcoded fallback weights (from ml/models/phishing_classifier_logistic.json)
    private static let defaultCoefficients: [Double] = [
        0.1515754896293396, -0.17687062190652342, 0.4251215061805213,
        0.6522107335346615, 8.720099093690225, 1.168831306654816,
        1.6534057467548318, 0.48358291642889606, 1.0413817120788775,
        2.2560370434233863, 2.52623892330409, -1.481912543680876,
        0.5269276493085449, 1.8739844777853785, 0.012820477554654004,
        0.012820477554654004, 4.674802613911455, 2.0929952382316026,
        1.9273927957533727, 0.9272854399688297,
    ]
    private static let defaultIntercept: Double = -11.079669393324433

    /// CDN-loaded weights (overrides defaults when available)
    private static var loadedCoefficients: [Double]?
    private static var loadedIntercept: Double?
    private static var modelVersion: Int = 0

    /// Active weights (CDN or fallback)
    private static var coefficients: [Double] { loadedCoefficients ?? defaultCoefficients }
    private static var intercept: Double { loadedIntercept ?? defaultIntercept }

    // MARK: - Feature vocabulary (mirrors ml/features.py and BrandRuleEngine)

    private static let brands: Set<String> = BrandRuleEngine.brands

    private static let phishingWords: Set<String> = BrandRuleEngine.phishingWords

    private static let highRiskTLDs: Set<String> = BrandRuleEngine.highRiskTLDs

    private static let lowRiskTLDs: Set<String> = BrandRuleEngine.lowRiskTLDs

    // MARK: - Public API

    public struct Prediction {
        public let score: Double       // 0.0 to 1.0 (probability of phishing)
        public let isPhishing: Bool    // score >= 0.5
        public let isHighRisk: Bool    // score >= 0.7
    }

    /// Classify a domain. Returns phishing probability.
    public static func predict(_ domain: String) -> Prediction {
        let features = extractFeatures(domain)
        let logit = zip(features, coefficients).reduce(intercept) { $0 + $1.0 * $1.1 }
        let score = sigmoid(logit)
        return Prediction(score: score, isPhishing: score >= 0.5, isHighRisk: score >= 0.7)
    }

    // MARK: - CDN weight loading

    private static let suiteName = "group.com.24defend.app"
    private static let cacheKey = "classifier_weights"

    /// Download latest model weights from backend. Call on app/tunnel start.
    public static func refreshWeights() async {
        // Try CDN first
        if let weights = await fetchWeights() {
            loadedCoefficients = weights.coefficients
            loadedIntercept = weights.intercept
            modelVersion = weights.version
            saveToCache(weights)
            return
        }
        // Fall back to cached
        if let cached = loadFromCache() {
            loadedCoefficients = cached.coefficients
            loadedIntercept = cached.intercept
            modelVersion = cached.version
        }
        // Otherwise use hardcoded defaults
    }

    private struct ModelWeights: Codable {
        let version: Int
        let coefficients: [Double]
        let intercept: Double
    }

    private static func fetchWeights() async -> ModelWeights? {
        guard let url = URL(string: "\(APIClient.baseURL)/admin/model/classifier") else { return nil }
        var request = URLRequest(url: url)
        request.timeoutInterval = 10
        // No API key needed — model weights aren't secret
        let config = URLSessionConfiguration.default
        config.connectionProxyDictionary = [:]
        let session = URLSession(configuration: config)

        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return nil }
            let decoded = try JSONDecoder().decode(ModelWeightsResponse.self, from: data)
            guard decoded.coefficients.count == defaultCoefficients.count else { return nil }
            return ModelWeights(
                version: decoded.version ?? 0,
                coefficients: decoded.coefficients,
                intercept: decoded.intercept
            )
        } catch {
            return nil
        }
    }

    private struct ModelWeightsResponse: Codable {
        let version: Int?
        let coefficients: [Double]
        let intercept: Double
    }

    private static func saveToCache(_ weights: ModelWeights) {
        guard let defaults = UserDefaults(suiteName: suiteName),
              let data = try? JSONEncoder().encode(weights) else { return }
        defaults.set(data, forKey: cacheKey)
    }

    private static func loadFromCache() -> ModelWeights? {
        guard let defaults = UserDefaults(suiteName: suiteName),
              let data = defaults.data(forKey: cacheKey) else { return nil }
        return try? JSONDecoder().decode(ModelWeights.self, from: data)
    }

    // MARK: - Feature extraction

    private static func extractFeatures(_ domain: String) -> [Double] {
        let d = domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let tld = getTLD(d)
        let name = getNamePart(d, tld: tld)
        let nameAlpha = name.replacingOccurrences(of: "-", with: "")
                            .replacingOccurrences(of: ".", with: "")

        // Basic string features
        let domainLength = Double(d.count)
        let nameLength = Double(name.count)
        let dotCount = Double(d.filter { $0 == "." }.count)
        let hyphenCount = Double(name.filter { $0 == "-" }.count)
        let digitCount = Double(name.filter { $0.isNumber }.count)
        let digitRatio = nameLength > 0 ? digitCount / nameLength : 0

        // Character diversity
        let uniqueChars = Double(Set(nameAlpha).count)
        let totalChars = Double(nameAlpha.count)
        let uniqueCharRatio = totalChars > 0 ? uniqueChars / totalChars : 0

        // Consonant analysis
        let vowels: Set<Character> = ["a", "e", "i", "o", "u"]
        let consonants = nameAlpha.filter { $0.isLetter && !vowels.contains($0) }
        let consonantRatio = totalChars > 0 ? Double(consonants.count) / totalChars : 0
        let maxConsec = Double(maxConsecutiveConsonants(nameAlpha))

        // Brand detection
        let foundBrands = brands.filter { d.contains($0) }
        let hasBrand: Double = foundBrands.isEmpty ? 0 : 1
        let brandCount = Double(foundBrands.count)

        // Phishing word detection
        let foundPhish = phishingWords.filter { d.contains($0) }
        let hasPhishingWord: Double = foundPhish.isEmpty ? 0 : 1
        let phishingWordCount = Double(foundPhish.count)

        // Combo signals
        let brandPhishingCombo: Double = (!foundBrands.isEmpty && !foundPhish.isEmpty) ? 1 : 0
        let hasYear: Double = d.range(of: "202[4-9]", options: .regularExpression) != nil ? 1 : 0
        let brandYear: Double = (!foundBrands.isEmpty && hasYear > 0) ? 1 : 0

        // TLD risk
        let tldRisk: Double
        if highRiskTLDs.contains(tld) { tldRisk = 1.0 }
        else if lowRiskTLDs.contains(tld) { tldRisk = 0.0 }
        else { tldRisk = 0.5 }
        let brandOnRiskyTLD: Double = (!foundBrands.isEmpty && tldRisk == 1.0) ? 1 : 0

        // Homoglyph detection
        let hasHomoglyph: Double = detectHomoglyphs(name) ? 1 : 0

        // Subdomain depth
        let baseDots: Double = lowRiskTLDs.contains(tld) && tld.contains(".") ? 1 : 0
        let subdomainDepth = max(0, dotCount - 1 - baseDots)

        return [
            domainLength, nameLength, dotCount, hyphenCount,
            digitCount, digitRatio, uniqueCharRatio, consonantRatio,
            maxConsec, hasBrand, brandCount, hasPhishingWord,
            phishingWordCount, brandPhishingCombo, hasYear, brandYear,
            tldRisk, brandOnRiskyTLD, hasHomoglyph, subdomainDepth,
        ]
    }

    // MARK: - Helpers

    private static func sigmoid(_ x: Double) -> Double {
        1.0 / (1.0 + exp(-x))
    }

    private static func getTLD(_ domain: String) -> String {
        let parts = domain.split(separator: ".")
        guard parts.count > 1 else { return "" }
        let lastTwo = parts.suffix(2).joined(separator: ".")
        let twoPartTLDs: Set<String> = ["com.uy", "com.ar", "com.br", "com.mx", "com.co",
                                         "com.cl", "co.uk", "com.au", "gub.uy", "org.uy", "edu.uy"]
        if twoPartTLDs.contains(lastTwo) { return lastTwo }
        return String(parts.last!)
    }

    private static func getNamePart(_ domain: String, tld: String) -> String {
        if !tld.isEmpty && domain.hasSuffix(tld) {
            let end = domain.index(domain.endIndex, offsetBy: -(tld.count + 1))
            return String(domain[domain.startIndex..<end])
        }
        if let dot = domain.lastIndex(of: ".") {
            return String(domain[domain.startIndex..<dot])
        }
        return domain
    }

    private static func maxConsecutiveConsonants(_ s: String) -> Int {
        let vowels: Set<Character> = ["a", "e", "i", "o", "u"]
        var maxC = 0, current = 0
        for c in s {
            if c.isLetter && !vowels.contains(c) {
                current += 1
                maxC = max(maxC, current)
            } else {
                current = 0
            }
        }
        return maxC
    }

    private static func detectHomoglyphs(_ name: String) -> Bool {
        // Only worth checking if name contains digits that could be substitutions
        guard name.contains("0") || name.contains("1") else { return false }

        let test1 = name.replacingOccurrences(of: "0", with: "o")
                        .replacingOccurrences(of: "1", with: "i")
        let test2 = name.replacingOccurrences(of: "0", with: "o")
                        .replacingOccurrences(of: "1", with: "l")
        for brand in brands {
            if name.contains(brand) { continue }
            if test1.contains(brand) || test2.contains(brand) {
                return true
            }
        }
        return false
    }
}
