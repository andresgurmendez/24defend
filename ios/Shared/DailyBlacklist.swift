import Foundation

/// Downloads and caches the daily blacklist from the backend.
///
/// The daily blacklist contains domains that were flagged by the ML classifier,
/// silently submitted to the backend, investigated by the agent, and confirmed
/// as malicious (verdict=block) within the last 48 hours.
///
/// Refreshes every 30 minutes. Stores the domain list in App Group UserDefaults.
public final class DailyBlacklist {

    private static let suiteName = "group.com.24defend.app"
    private static let domainsKey = "daily_blacklist_domains"
    private static let lastFetchKey = "daily_blacklist_last_fetch"
    private static let refreshIntervalSeconds: TimeInterval = 1800  // 30 minutes

    public static let shared = DailyBlacklist()

    private var domainSet: Set<String> = []

    /// URLSession that bypasses our VPN tunnel.
    private let session: URLSession = {
        let config = URLSessionConfiguration.default
        config.connectionProxyDictionary = [:]  // bypass proxy/VPN
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 15
        return URLSession(configuration: config)
    }()

    private init() {
        loadFromDisk()
    }

    /// Check if a domain is in the daily blacklist (uses base domain extraction).
    public func contains(_ domain: String) -> Bool {
        let base = BloomFilterStore.extractBaseDomain(domain)
        return domainSet.contains(base)
    }

    /// Whether a refresh is needed (more than 30 minutes since last fetch).
    public var needsRefresh: Bool {
        guard let defaults = UserDefaults(suiteName: Self.suiteName) else { return true }
        let lastFetch = defaults.double(forKey: Self.lastFetchKey)
        if lastFetch == 0 { return true }
        return Date().timeIntervalSince1970 - lastFetch > Self.refreshIntervalSeconds
    }

    /// Download the daily blacklist from the backend.
    public func refresh() async {
        guard let url = URL(string: "\(APIClient.baseURL)/daily-blacklist") else { return }

        var request = URLRequest(url: url)
        request.timeoutInterval = 10

        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return }
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let domains = json["domains"] as? [String] else { return }

            // Extract base domains and store
            let baseDomains = domains.map { BloomFilterStore.extractBaseDomain($0) }
            domainSet = Set(baseDomains)

            // Persist to disk
            let defaults = UserDefaults(suiteName: Self.suiteName)
            defaults?.set(baseDomains, forKey: Self.domainsKey)
            defaults?.set(Date().timeIntervalSince1970, forKey: Self.lastFetchKey)
        } catch {
            // Silently ignore -- daily blacklist refresh is best-effort
        }
    }

    // MARK: - Disk persistence

    private func loadFromDisk() {
        guard let defaults = UserDefaults(suiteName: Self.suiteName),
              let domains = defaults.stringArray(forKey: Self.domainsKey) else { return }
        domainSet = Set(domains)
    }
}
