import Foundation

/// Thread-safe LRU cache with TTL for DNS verdict caching.
/// Avoids re-running the 7-layer check for domains the user visits repeatedly.
public final class DNSCache {

    public enum CachedVerdict {
        case allow
        case block
    }

    private struct Entry {
        let verdict: CachedVerdict
        let expiresAt: TimeInterval
    }

    private var cache: [String: Entry] = [:]
    private var accessOrder: [String] = []  // most recent at end
    private let maxSize: Int
    private let ttl: TimeInterval
    private let lock = NSLock()

    /// - Parameters:
    ///   - maxSize: Maximum number of cached entries (default 2000)
    ///   - ttl: Time-to-live in seconds (default 1 hour)
    public init(maxSize: Int = 2000, ttl: TimeInterval = 3600) {
        self.maxSize = maxSize
        self.ttl = ttl
    }

    /// Look up a domain in the cache. Returns nil if not cached or expired.
    public func get(_ domain: String) -> CachedVerdict? {
        let key = domain.lowercased()
        lock.lock()
        defer { lock.unlock() }

        guard let entry = cache[key] else { return nil }

        // Check TTL
        if entry.expiresAt < Date().timeIntervalSince1970 {
            cache.removeValue(forKey: key)
            accessOrder.removeAll { $0 == key }
            return nil
        }

        // Move to end (most recently used)
        accessOrder.removeAll { $0 == key }
        accessOrder.append(key)

        return entry.verdict
    }

    /// Cache a verdict for a domain.
    public func set(_ domain: String, verdict: CachedVerdict) {
        let key = domain.lowercased()
        lock.lock()
        defer { lock.unlock() }

        // Remove old entry if exists
        if cache[key] != nil {
            accessOrder.removeAll { $0 == key }
        }

        // Evict LRU if at capacity
        while cache.count >= maxSize, let oldest = accessOrder.first {
            accessOrder.removeFirst()
            cache.removeValue(forKey: oldest)
        }

        cache[key] = Entry(
            verdict: verdict,
            expiresAt: Date().timeIntervalSince1970 + ttl
        )
        accessOrder.append(key)
    }

    /// Clear all cached entries. Called on bloom filter / classifier refresh.
    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        cache.removeAll()
        accessOrder.removeAll()
    }

    /// Number of cached entries.
    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return cache.count
    }
}
