import Foundation

/// Downloads and caches the daily blacklist + false positive list from the backend.
///
/// The daily blacklist contains domains confirmed malicious in the last 48 hours.
/// The false positive list contains domains that bloom filters flagged but the API
/// confirmed as legitimate — prevents repeated API checks for the same FP domain.
///
/// Refreshes every 30 minutes. Stores in App Group UserDefaults.
public final class DailyBlacklist {

    private static let suiteName = "group.com.24defend.app"
    private static let domainsKey = "daily_blacklist_domains"
    private static let fpDomainsKey = "daily_blacklist_false_positives"
    private static let lastFetchKey = "daily_blacklist_last_fetch"
    private static let refreshIntervalSeconds: TimeInterval = 1800  // 30 minutes

    public static let shared = DailyBlacklist()

    private var domainSet: Set<String> = []
    private var falsePositiveSet: Set<String> = []

    private let session: URLSession = {
        let config = URLSessionConfiguration.default
        config.connectionProxyDictionary = [:]
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 15
        return URLSession(configuration: config)
    }()

    private init() {
        loadFromDisk()
    }

    /// Check if a domain is in the daily blacklist.
    public func contains(_ domain: String) -> Bool {
        let base = BloomFilterStore.extractBaseDomain(domain)
        return domainSet.contains(base)
    }

    /// Check if a domain is a known bloom filter false positive.
    public func isFalsePositive(_ domain: String) -> Bool {
        let base = BloomFilterStore.extractBaseDomain(domain)
        return falsePositiveSet.contains(base)
    }

    public var needsRefresh: Bool {
        guard let defaults = UserDefaults(suiteName: Self.suiteName) else { return true }
        let lastFetch = defaults.double(forKey: Self.lastFetchKey)
        if lastFetch == 0 { return true }
        return Date().timeIntervalSince1970 - lastFetch > Self.refreshIntervalSeconds
    }

    /// Download both the daily blacklist and false positive list from the backend.
    public func refresh() async {
        async let blacklistResult = fetchList(path: "/daily-blacklist", key: "domains")
        async let fpResult = fetchList(path: "/daily-false-positives", key: "domains")

        let (bl, fp) = await (blacklistResult, fpResult)

        if let bl {
            let bases = Set(bl.map { BloomFilterStore.extractBaseDomain($0) })
            domainSet = bases
            UserDefaults(suiteName: Self.suiteName)?.set(Array(bases), forKey: Self.domainsKey)
        }

        if let fp {
            let bases = Set(fp.map { BloomFilterStore.extractBaseDomain($0) })
            falsePositiveSet = bases
            UserDefaults(suiteName: Self.suiteName)?.set(Array(bases), forKey: Self.fpDomainsKey)
        }

        if bl != nil || fp != nil {
            UserDefaults(suiteName: Self.suiteName)?
                .set(Date().timeIntervalSince1970, forKey: Self.lastFetchKey)
        }
    }

    // MARK: - Network

    private func fetchList(path: String, key: String) async -> [String]? {
        guard let url = URL(string: "\(APIClient.baseURL)\(path)") else { return nil }
        var request = URLRequest(url: url)
        request.timeoutInterval = 10

        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return nil }
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let domains = json[key] as? [String] else { return nil }
            return domains
        } catch {
            return nil
        }
    }

    // MARK: - Disk persistence

    private func loadFromDisk() {
        guard let defaults = UserDefaults(suiteName: Self.suiteName) else { return }
        if let domains = defaults.stringArray(forKey: Self.domainsKey) {
            domainSet = Set(domains)
        }
        if let fpDomains = defaults.stringArray(forKey: Self.fpDomainsKey) {
            falsePositiveSet = Set(fpDomains)
        }
    }
}
