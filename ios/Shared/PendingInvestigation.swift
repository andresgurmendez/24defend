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

    private struct Entry {
        let domain: String
        let submittedAt: Date
    }

    private var pending: [Entry] = []
    private let maxEntries = 20
    private let expirySeconds: TimeInterval = 600 // 10 minutes

    private init() {}

    /// Record a domain that was silently submitted for investigation.
    public func add(domain: String) {
        let d = domain.lowercased()
        guard !pending.contains(where: { $0.domain == d }) else { return }

        pending.append(Entry(domain: d, submittedAt: Date()))

        if pending.count > maxEntries {
            pending.removeFirst()
        }
    }

    /// Result of a poll pass: which domains were confirmed bad and which were cleared.
    /// The caller decides how to notify — for cleared domains, we only want to fire
    /// a "verified safe" green notification if the tunnel already yellow-flagged that
    /// base domain (so the user sees closure on their earlier warning).
    public struct PollResult {
        public let confirmedThreats: [String]
        public let cleared: [String]
    }

    /// Poll all pending domains. Returns confirmed threats and cleared domains.
    public func pollAll() async -> PollResult {
        let now = Date()
        pending.removeAll { now.timeIntervalSince($0.submittedAt) > expirySeconds }

        guard !pending.isEmpty else { return PollResult(confirmedThreats: [], cleared: []) }

        var confirmedThreats: [String] = []
        var cleared: [String] = []
        var toRemove: [String] = []

        for entry in pending {
            guard let response = await APIClient.checkDomain(entry.domain) else {
                continue // API unreachable — keep pending
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
            }
            // "warn" = agent still investigating — keep polling
        }

        pending.removeAll { entry in toRemove.contains(entry.domain) }

        return PollResult(confirmedThreats: confirmedThreats, cleared: cleared)
    }

    /// Number of domains currently pending.
    public var count: Int { pending.count }
}
