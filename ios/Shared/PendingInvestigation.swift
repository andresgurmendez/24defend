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

    /// Poll all pending domains. Returns domains confirmed as malicious.
    public func pollAll() async -> [String] {
        let now = Date()
        pending.removeAll { now.timeIntervalSince($0.submittedAt) > expirySeconds }

        guard !pending.isEmpty else { return [] }

        var confirmedThreats: [String] = []
        var toRemove: [String] = []

        for entry in pending {
            guard let response = await APIClient.checkDomain(entry.domain) else {
                continue // API unreachable — keep pending
            }

            if response.verdict == "block" && response.confidence >= 0.9 {
                // Only alert for high-confidence blocks.
                // Low-confidence agent verdicts may be wrong — don't scare the user.
                confirmedThreats.append(entry.domain)
                toRemove.append(entry.domain)
            } else if response.verdict == "block" {
                // Low-confidence block — add to runtime blacklist silently
                // but don't send a retroactive "your data may be stolen" notification
                toRemove.append(entry.domain)
            } else if response.verdict == "allow" {
                toRemove.append(entry.domain) // cleared
            }
            // "warn" = agent still investigating — keep polling
        }

        pending.removeAll { entry in toRemove.contains(entry.domain) }

        return confirmedThreats
    }

    /// Number of domains currently pending.
    public var count: Int { pending.count }
}
