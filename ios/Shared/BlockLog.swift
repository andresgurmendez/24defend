import Foundation

public enum EventSeverity: String, Codable {
    case red     // blacklisted — blocked
    case yellow  // similar to whitelist — warned
    case green   // previously yellow-flagged, cleared by backend after investigation
    case checked // agent investigated and returned warn — no fraud signals but
                 // also not confirmed legit. Close the loop honestly instead of
                 // leaving the user stuck on the yellow.
}

public struct BlockEvent: Codable, Identifiable {
    public let id: UUID
    public let domain: String
    public let reason: String
    public let severity: EventSeverity
    public let timestamp: Date

    public init(domain: String, reason: String, severity: EventSeverity) {
        self.id = UUID()
        self.domain = domain
        self.reason = reason
        self.severity = severity
        self.timestamp = Date()
    }
}

public final class BlockLog {
    private static let suiteName = "group.com.24defend.app"
    private static let key = "blocked_domains"
    private static let maxEntries = 200

    public static func append(_ event: BlockEvent) {
        var events = load()
        events.insert(event, at: 0)
        if events.count > maxEntries {
            events = Array(events.prefix(maxEntries))
        }
        save(events)
    }

    public static func load() -> [BlockEvent] {
        guard let defaults = UserDefaults(suiteName: suiteName),
              let data = defaults.data(forKey: key) else {
            return []
        }
        return (try? JSONDecoder().decode([BlockEvent].self, from: data)) ?? []
    }

    public static func clear() {
        guard let defaults = UserDefaults(suiteName: suiteName) else { return }
        defaults.removeObject(forKey: key)
    }

    /// `to` is exclusive (half-open interval). Custom ranges compute `to` as
    /// the day AFTER the selected end date at midnight; an inclusive `<=`
    /// let an event timestamped exactly at that midnight boundary (the start
    /// of the following day) count as part of the prior day's range.
    public static func events(from: Date, to: Date = Date()) -> [BlockEvent] {
        load().filter { $0.timestamp >= from && $0.timestamp < to }
    }

    private static func save(_ events: [BlockEvent]) {
        guard let defaults = UserDefaults(suiteName: suiteName),
              let data = try? JSONEncoder().encode(events) else { return }
        defaults.set(data, forKey: key)
    }
}
