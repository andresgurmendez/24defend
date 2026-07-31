import Foundation

/// Persistent diagnostic log — writable from BOTH the app and the packet-tunnel
/// extension via the shared App Group. Meant to be surfaced by the hidden
/// diagnostic view (7 taps on the app title) so testers and internal users can
/// grab a record of what the tunnel is actually doing in the wild, without
/// needing Console.app / Xcode attached.
///
/// Cap: 500 entries, oldest dropped on overflow. Kept small so serialize /
/// deserialize cost stays sub-millisecond and UserDefaults stays healthy.
public final class DiagnosticLog {

    public enum Category: String, Codable {
        case dnsUpstream = "dns"       // upstream DNS failures + failover
        case tunnel = "tunnel"         // tunnel lifecycle (start/stop reasons)
        case notification = "notif"    // yellow/red/green/blue fires
        case api = "api"               // /check failures + backend calls
        case memory = "mem"            // memory watchdog samples
        case other = "other"
    }

    public struct Entry: Codable, Identifiable {
        public let id: UUID
        public let timestamp: Date
        public let category: Category
        public let message: String

        public init(category: Category, message: String) {
            self.id = UUID()
            self.timestamp = Date()
            self.category = category
            self.message = message
        }
    }

    private static let suiteName = "group.com.24defend.app"
    private static let storageKey = "diagnostic_log_v1"
    private static let maxEntries = 500
    // Serial queue so concurrent tunnel + app writes don't race. Non-blocking
    // reads (load()) don't need it since UserDefaults is thread-safe for read.
    private static let queue = DispatchQueue(label: "com.24defend.diaglog", qos: .utility)

    public static func record(_ category: Category, _ message: String) {
        queue.async {
            guard let defaults = UserDefaults(suiteName: suiteName) else { return }
            var entries = _loadUnsafe(from: defaults)
            entries.insert(Entry(category: category, message: message), at: 0)
            if entries.count > maxEntries {
                entries = Array(entries.prefix(maxEntries))
            }
            if let data = try? JSONEncoder().encode(entries) {
                defaults.set(data, forKey: storageKey)
            }
        }
    }

    public static func load() -> [Entry] {
        guard let defaults = UserDefaults(suiteName: suiteName) else { return [] }
        return _loadUnsafe(from: defaults)
    }

    public static func clear() {
        queue.async {
            guard let defaults = UserDefaults(suiteName: suiteName) else { return }
            defaults.removeObject(forKey: storageKey)
        }
    }

    private static func _loadUnsafe(from defaults: UserDefaults) -> [Entry] {
        guard let data = defaults.data(forKey: storageKey),
              let entries = try? JSONDecoder().decode([Entry].self, from: data) else {
            return []
        }
        return entries
    }
}
