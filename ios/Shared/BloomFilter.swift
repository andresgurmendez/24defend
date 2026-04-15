import Foundation

/// On-device bloom filter for fast domain lookups without network calls.
/// Binary format: [4 bytes: m (filter size)] [4 bytes: k (hash count)] [bitarray bytes]
public final class BloomFilter {

    private let m: Int
    private let k: Int
    private let bits: [UInt8]

    public init?(data: Data) {
        guard data.count >= 8 else { return nil }
        m = Int(data[0]) << 24 | Int(data[1]) << 16 | Int(data[2]) << 8 | Int(data[3])
        k = Int(data[4]) << 24 | Int(data[5]) << 16 | Int(data[6]) << 8 | Int(data[7])
        bits = Array(data[8...])
        guard m > 0 && k > 0 && !bits.isEmpty else { return nil }
    }

    public func mightContain(_ element: String) -> Bool {
        let d = element.lowercased()
        for i in 0..<k {
            let hash = murmurhash3(d, seed: UInt32(i))
            let idx = Int(hash) % m
            let byteIdx = idx / 8
            let bitIdx = idx % 8
            guard byteIdx < bits.count else { return false }
            if bits[byteIdx] & (1 << (7 - bitIdx)) == 0 {
                return false
            }
        }
        return true
    }

    /// MurmurHash3 32-bit — must match mmh3.hash(key, seed=i) from Python
    private func murmurhash3(_ key: String, seed: UInt32) -> UInt32 {
        let data = Array(key.utf8)
        let len = data.count
        let nblocks = len / 4

        var h1 = seed
        let c1: UInt32 = 0xcc9e2d51
        let c2: UInt32 = 0x1b873593

        // body
        for i in 0..<nblocks {
            var k1 = UInt32(data[i * 4])
                | UInt32(data[i * 4 + 1]) << 8
                | UInt32(data[i * 4 + 2]) << 16
                | UInt32(data[i * 4 + 3]) << 24

            k1 &*= c1
            k1 = (k1 << 15) | (k1 >> 17)
            k1 &*= c2

            h1 ^= k1
            h1 = (h1 << 13) | (h1 >> 19)
            h1 = h1 &* 5 &+ 0xe6546b64
        }

        // tail
        let tail = nblocks * 4
        var k1: UInt32 = 0
        switch len & 3 {
        case 3:
            k1 ^= UInt32(data[tail + 2]) << 16
            fallthrough
        case 2:
            k1 ^= UInt32(data[tail + 1]) << 8
            fallthrough
        case 1:
            k1 ^= UInt32(data[tail])
            k1 &*= c1
            k1 = (k1 << 15) | (k1 >> 17)
            k1 &*= c2
            h1 ^= k1
        default:
            break
        }

        // finalization
        h1 ^= UInt32(len)
        h1 ^= h1 >> 16
        h1 &*= 0x85ebca6b
        h1 ^= h1 >> 13
        h1 &*= 0xc2b2ae35
        h1 ^= h1 >> 16

        return h1
    }
}

/// Manages downloading, caching, and accessing bloom filters.
public final class BloomFilterStore {

    private static let suiteName = "group.com.24defend.app"
    private static let whitelistKey = "bloom_whitelist"
    private static let blacklistKey = "bloom_blacklist"
    private static let lastFetchKey = "bloom_last_fetch"

    private(set) var whitelist: BloomFilter?
    private(set) var blacklist: BloomFilter?

    public static let shared = BloomFilterStore()

    private init() {
        loadFromDisk()
    }

    /// Download fresh bloom filters from the backend. Call on app launch and daily.
    public func refresh() async {
        let apiKey = "dev-api-key-change-me" // TODO: move to config
        let baseURL = APIClient.baseURL

        async let wlData = fetchBloom(url: "\(baseURL)/admin/bloom-filter/whitelist", apiKey: apiKey)
        async let blData = fetchBloom(url: "\(baseURL)/admin/bloom-filter/blacklist", apiKey: apiKey)

        let (wl, bl) = await (wlData, blData)

        if let wl {
            whitelist = BloomFilter(data: wl)
            saveToDisk(data: wl, key: Self.whitelistKey)
        }
        if let bl {
            blacklist = BloomFilter(data: bl)
            saveToDisk(data: bl, key: Self.blacklistKey)
        }

        if wl != nil || bl != nil {
            UserDefaults(suiteName: Self.suiteName)?
                .set(Date().timeIntervalSince1970, forKey: Self.lastFetchKey)
        }
    }

    /// Check if refresh is needed (more than 24h since last fetch).
    public var needsRefresh: Bool {
        guard let defaults = UserDefaults(suiteName: Self.suiteName) else { return true }
        let lastFetch = defaults.double(forKey: Self.lastFetchKey)
        if lastFetch == 0 { return true }
        return Date().timeIntervalSince1970 - lastFetch > 86400 // 24 hours
    }

    // MARK: - Base domain extraction (mirrors backend logic)

    private static let twoPartTLDs: Set<String> = [
        "com.uy", "com.ar", "com.br", "com.mx", "com.co", "com.cl",
        "co.uk", "com.au", "com.pe", "com.py", "com.bo", "com.ve",
        "com.ec", "com.pa", "com.gt", "com.cr", "com.do", "com.sv",
        "com.hn", "com.ni", "gob.uy", "org.uy", "edu.uy", "net.uy"
    ]

    public static func extractBaseDomain(_ domain: String) -> String {
        let parts = domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")).split(separator: ".")
        if parts.count <= 2 { return parts.joined(separator: ".") }
        let lastTwo = parts.suffix(2).joined(separator: ".")
        if twoPartTLDs.contains(lastTwo) && parts.count >= 3 {
            return parts.suffix(3).joined(separator: ".")
        }
        return parts.suffix(2).joined(separator: ".")
    }

    /// Check domain against whitelist bloom (base domain only).
    public func isWhitelisted(_ domain: String) -> Bool {
        guard let wl = whitelist else { return false }
        let base = Self.extractBaseDomain(domain)
        return wl.mightContain(base)
    }

    /// Check domain against blacklist bloom (base domain only).
    public func isBlacklisted(_ domain: String) -> Bool {
        guard let bl = blacklist else { return false }
        let base = Self.extractBaseDomain(domain)
        return bl.mightContain(base)
    }

    // MARK: - Disk persistence via App Group

    private func loadFromDisk() {
        guard let defaults = UserDefaults(suiteName: Self.suiteName) else { return }
        if let wlData = defaults.data(forKey: Self.whitelistKey) {
            whitelist = BloomFilter(data: wlData)
        }
        if let blData = defaults.data(forKey: Self.blacklistKey) {
            blacklist = BloomFilter(data: blData)
        }
    }

    private func saveToDisk(data: Data, key: String) {
        UserDefaults(suiteName: Self.suiteName)?.set(data, forKey: key)
    }

    // MARK: - Network

    private func fetchBloom(url: String, apiKey: String) async -> Data? {
        guard let url = URL(string: url) else { return nil }
        var request = URLRequest(url: url)
        request.setValue(apiKey, forHTTPHeaderField: "X-Api-Key")
        request.setValue("true", forHTTPHeaderField: "ngrok-skip-browser-warning")
        request.timeoutInterval = 15

        let config = URLSessionConfiguration.default
        config.connectionProxyDictionary = [:]
        let session = URLSession(configuration: config)

        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return nil }
            return data
        } catch {
            return nil
        }
    }
}
