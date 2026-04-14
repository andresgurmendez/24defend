import Foundation

public enum EventSeverity: String, Codable {
    case red    // blacklisted — blocked
    case yellow // similar to whitelist — warned
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

    private static func save(_ events: [BlockEvent]) {
        guard let defaults = UserDefaults(suiteName: suiteName),
              let data = try? JSONEncoder().encode(events) else { return }
        defaults.set(data, forKey: key)
    }
}
