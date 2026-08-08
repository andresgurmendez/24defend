import XCTest
@testable import Shared

/// Pins the precedence between the hardcoded whitelist and blacklist in
/// `DomainChecker.check`. Whitelist is checked first (matches the
/// bloom-filter order in the tunnel), so a whitelisted root always wins
/// over a blacklist entry that happens to be one of its subdomains.
final class DomainCheckerTests: XCTestCase {

    func test_whitelisted_domain_is_allowed() {
        let result = DomainChecker.check(domain: "brou.com.uy")
        guard case .allowed = result else {
            return XCTFail("expected .allowed, got \(result)")
        }
    }

    func test_blacklisted_domain_not_under_whitelist_parent_is_blocked() {
        let result = DomainChecker.check(domain: "24defend-block-test.com")
        guard case .blocked = result else {
            return XCTFail("expected .blocked, got \(result)")
        }
    }

    /// Pinning case: `login.brou.com.uy` is BOTH an exact blacklist entry
    /// AND a subdomain of the whitelisted `brou.com.uy`. This is the one
    /// input that actually discriminates the two orderings — under
    /// blacklist-first it would resolve to `.blocked`, under
    /// whitelist-first (the real behavior) it resolves to `.allowed`. The
    /// static `blacklist`/`whitelist` sets have no such overlapping pair
    /// today, so the lists are injected directly into `precedenceResult`
    /// rather than going through `check(domain:)`.
    func test_blacklist_entry_under_whitelisted_parent_is_masked_by_whitelist() {
        let result = DomainChecker.precedenceResult(
            domain: "login.brou.com.uy",
            whitelist: ["brou.com.uy"],
            blacklist: ["login.brou.com.uy"]
        )
        guard case .allowed = result else {
            return XCTFail("expected .allowed (whitelist parent wins even though blacklist has an exact match), got \(String(describing: result))")
        }
    }
}
