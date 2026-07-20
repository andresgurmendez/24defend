import XCTest
@testable import Shared

/// Regression tests for BrandRuleEngine, focused on FNs that previously
/// slipped past into the silent ML-classifier path (no yellow notification).
final class BrandRuleEngineTests: XCTestCase {

    // MARK: - Regressions from actual on-device observations

    /// `devolucion.dgi.hk` — DGI (Uruguayan tax authority) impersonation with
    /// a refund lure and a .hk TLD. Before the fix, this scored 0.35 (brand
    /// keyword only) and dropped below the isSuspicious threshold, so it fell
    /// through to the silent ML path. User got a red notification later but
    /// no yellow warning at browse time.
    func test_devolucion_dgi_hk_is_high_risk() {
        let risk = BrandRuleEngine.assess("devolucion.dgi.hk")
        XCTAssertTrue(risk.isHighRisk, "score=\(risk.score) signals=\(risk.signals)")
        XCTAssertEqual(risk.matchedBrand, "dgi")
    }

    /// `promocion.oca.hk` — OCA + promocion word + .hk. Was already high-risk
    /// (because "promocion" is in phishingWords). Guard against regression.
    func test_promocion_oca_hk_is_high_risk() {
        let risk = BrandRuleEngine.assess("promocion.oca.hk")
        XCTAssertTrue(risk.isHighRisk)
    }

    /// `sorteo.brou.hk` — BROU + sorteo + .hk. Similar shape.
    func test_sorteo_brou_hk_is_high_risk() {
        let risk = BrandRuleEngine.assess("sorteo.brou.hk")
        XCTAssertTrue(risk.isHighRisk)
    }

    /// `www.puntos.santader.st` — Santander typo'd (santader) but the "santader"
    /// substring doesn't match the "santander" brand keyword. Verify current
    /// behavior — this one relies on the ML classifier by design.
    func test_typosquat_santader_not_matched_by_brand_rule() {
        let risk = BrandRuleEngine.assess("www.puntos.santader.st")
        // Doesn't match any brand keyword (santander != santader).
        XCTAssertNil(risk.matchedBrand)
    }

    // MARK: - New refund vocabulary must count as phishing words

    func test_refund_vocabulary_is_phishing_words() {
        for word in ["devolucion", "reintegro", "reembolso", "impuesto", "iva"] {
            XCTAssertTrue(
                BrandRuleEngine.phishingWords.contains(word),
                "\(word) should be in phishingWords for refund-scam coverage"
            )
        }
    }

    // MARK: - New high-risk TLDs

    func test_hk_is_high_risk_tld() {
        XCTAssertTrue(BrandRuleEngine.highRiskTLDs.contains("hk"),
                      "All observed OCA/BROU phishing FNs used .hk — must be high-risk")
    }

    // MARK: - Negative cases (must not regress)

    /// Real BROU homepage — must not be flagged.
    func test_real_brou_is_not_suspicious() {
        let risk = BrandRuleEngine.assess("brou.com.uy")
        XCTAssertFalse(risk.isSuspicious, "brou.com.uy should be treated as legit")
    }

    /// Real OCA homepage.
    func test_real_oca_is_not_suspicious() {
        let risk = BrandRuleEngine.assess("oca.com.uy")
        XCTAssertFalse(risk.isSuspicious)
    }

    /// Random legitimate site with no brand keyword.
    func test_unrelated_domain_scores_zero() {
        let risk = BrandRuleEngine.assess("example.com")
        XCTAssertEqual(risk.score, 0.0)
        XCTAssertNil(risk.matchedBrand)
    }

    /// Marketing subdomain of AA — shouldn't score high on brand rules
    /// (aa is not in our Uruguayan brand list). Handled by popular-domain
    /// short-circuit on the backend instead.
    func test_aa_marketing_subdomain_no_brand_match() {
        let risk = BrandRuleEngine.assess("l.loyalty.ms.aa.com")
        XCTAssertNil(risk.matchedBrand)
    }
}
