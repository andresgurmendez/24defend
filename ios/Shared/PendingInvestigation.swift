import Foundation

/// Tracks domains submitted to the backend for AI investigation.
///
/// When the ML classifier silently flags a domain, the DNS is forwarded
/// (user sees the page) and the domain is submitted to the backend agent.
/// This class polls every 30 seconds for the result. If the agent confirms
/// it's malicious, a retroactive warning notification is sent.
///
/// This protects the "first user" — the one who visits a novel phishing
/// domain before it's in any blacklist.
public final class PendingInvestigation {

    public static let shared = PendingInvestigation()

    private struct Entry: Codable {
        let domain: String
        let submittedAt: Date
    }

    // Persistence: iOS restarts packet-tunnel extensions frequently (device
    // sleep, network transitions, jetsam, etc.). Without persistence, every
    // restart wipes `pending` and any yellow-flagged domain that hasn't
    // resolved yet gets silently dropped — the user never sees a
    // green/blue/red follow-up.
    private static let suiteName = "group.com.24defend.app"
    private static let storageKey = "pending_investigations_v1"

    private var pending: [Entry] = []
    // Bumped 20 → 50 so a burst of yellows doesn't evict older entries
    // before their agent runs finish.
    private let maxEntries = 50
    // Bumped 600 → 1800 (30 min) so cold agent runs / rate-limit backoff
    // still fire the resolution notification. If we truly can't decide in
    // 30 min, silent-drop is the honest outcome.
    private let expirySeconds: TimeInterval = 1800

    private init() {
        pending = Self.load()
    }

    /// Record a domain that was silently submitted for investigation.
    public func add(domain: String) {
        let d = domain.lowercased()
        guard !pending.contains(where: { $0.domain == d }) else { return }

        pending.append(Entry(domain: d, submittedAt: Date()))

        if pending.count > maxEntries {
            pending.removeFirst()
        }
        save()
    }

    /// Result of a poll pass: which domains resolved to what.
    ///
    /// The caller decides how to notify — the poll loop only reports the
    /// verdicts. Three terminal states are surfaced:
    ///   - confirmedThreats: agent said block AND recommended notifying
    ///   - cleared:          agent said allow (fire green if we had a yellow)
    ///   - inconclusive:     agent said warn (fire "checked but couldn't confirm"
    ///                       if we had a yellow — otherwise the user has no
    ///                       context for the notification)
    public struct PollResult {
        public let confirmedThreats: [String]
        public let cleared: [String]
        public let inconclusive: [String]
    }

    /// Poll all pending domains. Returns confirmed threats, cleared domains,
    /// and domains the agent investigated but couldn't decide on.
    public func pollAll() async -> PollResult {
        let now = Date()
        pending.removeAll { now.timeIntervalSince($0.submittedAt) > expirySeconds }

        guard !pending.isEmpty else {
            return PollResult(confirmedThreats: [], cleared: [], inconclusive: [])
        }

        var confirmedThreats: [String] = []
        var cleared: [String] = []
        var inconclusive: [String] = []
        var toRemove: [String] = []

        for entry in pending {
            guard let response = await APIClient.checkDomain(entry.domain) else {
                continue // API unreachable — keep pending, retry next tick
            }

            if response.verdict == "block" && (response.shouldNotify ?? false) {
                // Agent or blacklist explicitly recommends notifying the user.
                // The agent only sets shouldNotify=true when confident AND
                // the domain impersonates a specific brand with strong evidence.
                confirmedThreats.append(entry.domain)
                toRemove.append(entry.domain)
            } else if response.verdict == "block" {
                // Blocked but agent didn't recommend notification (ambiguous case).
                // Domain will be caught by daily blacklist on next visit.
                toRemove.append(entry.domain)
            } else if response.verdict == "allow" {
                cleared.append(entry.domain)
                toRemove.append(entry.domain)
            } else if response.verdict == "warn" {
                // Agent investigated and committed to warn — no strong fraud
                // signals but also not conclusively legit. Treat as terminal
                // so the yellow gets closed by the "checked but inconclusive"
                // notification, instead of the previous behavior of polling
                // forever (silent user experience).
                inconclusive.append(entry.domain)
                toRemove.append(entry.domain)
            }
            // Unknown verdict → keep polling (defensive)
        }

        pending.removeAll { entry in toRemove.contains(entry.domain) }
        save()

        return PollResult(
            confirmedThreats: confirmedThreats,
            cleared: cleared,
            inconclusive: inconclusive,
        )
    }

    /// Number of domains currently pending.
    public var count: Int { pending.count }

    // MARK: - Persistence

    private func save() {
        guard let defaults = UserDefaults(suiteName: Self.suiteName),
              let data = try? JSONEncoder().encode(pending) else { return }
        defaults.set(data, forKey: Self.storageKey)
    }

    private static func load() -> [Entry] {
        guard let defaults = UserDefaults(suiteName: suiteName),
              let data = defaults.data(forKey: storageKey),
              let entries = try? JSONDecoder().decode([Entry].self, from: data) else {
            return []
        }
        return entries
    }
}
