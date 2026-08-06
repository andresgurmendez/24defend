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

    /// Pinning case: `login.brou.com.uy` is a subdomain of the whitelisted
    /// `brou.com.uy`. Even if such a pattern were added to `blacklist`
    /// (it currently isn't), whitelist-first precedence means it resolves
    /// to .allowed, not .blocked. Documents the invariant in
    /// `DomainChecker.check` so a future refactor doesn't silently assume
    /// blacklist wins.
    func test_blacklist_entry_under_whitelisted_parent_is_masked_by_whitelist() {
        XCTAssertFalse(
            DomainChecker.blacklist.contains("login.brou.com.uy"),
            "this test pins current precedence assuming this domain is NOT already blacklisted"
        )
        let result = DomainChecker.check(domain: "login.brou.com.uy")
        guard case .allowed = result else {
            return XCTFail("expected .allowed (whitelist parent wins), got \(result)")
        }
    }
}
