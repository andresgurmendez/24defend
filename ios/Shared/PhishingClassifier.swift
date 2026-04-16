import Foundation

/// On-device logistic regression phishing classifier.
/// Trained on 17.5K synthetic domains (7 attack patterns). AUC 0.9974.
/// 20 features, 1 KB model. Runs in <1ms.
public final class PhishingClassifier {

    // MARK: - Model weights (from ml/models/phishing_classifier_logistic.json)

    private static let coefficients: [Double] = [
        0.1515754896293396,    // domain_length
       -0.17687062190652342,   // name_length
        0.4251215061805213,    // dot_count
        0.6522107335346615,    // hyphen_count
        8.720099093690225,     // digit_count
        1.168831306654816,     // digit_ratio
        1.6534057467548318,    // unique_char_ratio
        0.48358291642889606,   // consonant_ratio
        1.0413817120788775,    // max_consecutive_consonants
        2.2560370434233863,    // has_brand
        2.52623892330409,      // brand_count
       -1.481912543680876,     // has_phishing_word
        0.5269276493085449,    // phishing_word_count
        1.8739844777853785,    // brand_phishing_combo
        0.012820477554654004,  // has_year_pattern
        0.012820477554654004,  // brand_year_combo
        4.674802613911455,     // tld_risk
        2.0929952382316026,    // brand_on_risky_tld
        1.9273927957533727,    // has_homoglyph
        0.9272854399688297,    // subdomain_depth
    ]

    private static let intercept: Double = -11.079669393324433

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
        let test1 = name.replacingOccurrences(of: "0", with: "o")
                        .replacingOccurrences(of: "1", with: "i")
        let test2 = name.replacingOccurrences(of: "0", with: "o")
                        .replacingOccurrences(of: "1", with: "l")
        for brand in brands {
            if !name.contains(brand) && (test1.contains(brand) || test2.contains(brand)) {
                return true
            }
        }
        return false
    }
}
