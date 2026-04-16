import XCTest
@testable import TwentyFourDefend

final class DNSCacheTests: XCTestCase {

    // MARK: - Basic operations

    func testGetReturnsNilForUnknownDomain() {
        let cache = DNSCache(maxSize: 10, ttl: 60)
        XCTAssertNil(cache.get("unknown.com"))
    }

    func testSetAndGet() {
        let cache = DNSCache(maxSize: 10, ttl: 60)
        cache.set("google.com", verdict: .allow)
        cache.set("evil.com", verdict: .block)

        XCTAssertEqual(cache.get("google.com"), .allow)
        XCTAssertEqual(cache.get("evil.com"), .block)
    }

    func testCaseInsensitive() {
        let cache = DNSCache(maxSize: 10, ttl: 60)
        cache.set("Google.COM", verdict: .allow)
        XCTAssertEqual(cache.get("google.com"), .allow)
        XCTAssertEqual(cache.get("GOOGLE.COM"), .allow)
    }

    func testOverwriteVerdict() {
        let cache = DNSCache(maxSize: 10, ttl: 60)
        cache.set("test.com", verdict: .allow)
        XCTAssertEqual(cache.get("test.com"), .allow)

        cache.set("test.com", verdict: .block)
        XCTAssertEqual(cache.get("test.com"), .block)
    }

    // MARK: - TTL expiration

    func testExpiredEntryReturnsNil() {
        let cache = DNSCache(maxSize: 10, ttl: 0.1) // 100ms TTL
        cache.set("test.com", verdict: .allow)
        XCTAssertEqual(cache.get("test.com"), .allow)

        // Wait for expiry
        Thread.sleep(forTimeInterval: 0.2)
        XCTAssertNil(cache.get("test.com"))
    }

    func testNonExpiredEntryReturns() {
        let cache = DNSCache(maxSize: 10, ttl: 60)
        cache.set("test.com", verdict: .allow)
        XCTAssertEqual(cache.get("test.com"), .allow)
    }

    // MARK: - LRU eviction

    func testEvictsLRUWhenFull() {
        let cache = DNSCache(maxSize: 3, ttl: 60)
        cache.set("a.com", verdict: .allow)
        cache.set("b.com", verdict: .allow)
        cache.set("c.com", verdict: .allow)

        // Cache is full (3/3). Adding d.com should evict a.com (LRU)
        cache.set("d.com", verdict: .allow)

        XCTAssertNil(cache.get("a.com"), "LRU entry should be evicted")
        XCTAssertEqual(cache.get("b.com"), .allow)
        XCTAssertEqual(cache.get("c.com"), .allow)
        XCTAssertEqual(cache.get("d.com"), .allow)
    }

    func testAccessPromotesEntry() {
        let cache = DNSCache(maxSize: 3, ttl: 60)
        cache.set("a.com", verdict: .allow)
        cache.set("b.com", verdict: .allow)
        cache.set("c.com", verdict: .allow)

        // Access a.com — promotes it from LRU
        _ = cache.get("a.com")

        // Adding d.com should now evict b.com (new LRU), not a.com
        cache.set("d.com", verdict: .allow)

        XCTAssertEqual(cache.get("a.com"), .allow, "Accessed entry should survive")
        XCTAssertNil(cache.get("b.com"), "LRU entry should be evicted")
        XCTAssertEqual(cache.get("c.com"), .allow)
        XCTAssertEqual(cache.get("d.com"), .allow)
    }

    func testMaxSizeRespected() {
        let cache = DNSCache(maxSize: 5, ttl: 60)
        for i in 0..<100 {
            cache.set("domain\(i).com", verdict: .allow)
        }
        XCTAssertLessThanOrEqual(cache.count, 5)
    }

    // MARK: - Clear

    func testClearRemovesAll() {
        let cache = DNSCache(maxSize: 10, ttl: 60)
        cache.set("a.com", verdict: .allow)
        cache.set("b.com", verdict: .block)
        XCTAssertEqual(cache.count, 2)

        cache.clear()

        XCTAssertEqual(cache.count, 0)
        XCTAssertNil(cache.get("a.com"))
        XCTAssertNil(cache.get("b.com"))
    }

    // MARK: - Thread safety

    func testConcurrentAccess() {
        let cache = DNSCache(maxSize: 1000, ttl: 60)
        let group = DispatchGroup()

        // Concurrent writes
        for i in 0..<100 {
            group.enter()
            DispatchQueue.global().async {
                cache.set("domain\(i).com", verdict: i % 2 == 0 ? .allow : .block)
                group.leave()
            }
        }

        // Concurrent reads
        for i in 0..<100 {
            group.enter()
            DispatchQueue.global().async {
                _ = cache.get("domain\(i).com")
                group.leave()
            }
        }

        let result = group.wait(timeout: .now() + 5)
        XCTAssertEqual(result, .success, "Concurrent access should not deadlock")
    }
}

// Make CachedVerdict equatable for tests
extension DNSCache.CachedVerdict: Equatable {}
