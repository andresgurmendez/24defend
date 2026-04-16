import Foundation

// MARK: - Telemetry event model

public struct TelemetryEvent: Codable {
    public let eventType: String   // "blocked", "warned", "false_positive_report"
    public let domain: String      // base domain only
    public let layer: String       // "bloom_blacklist", "brand_rules", "ml_classifier", "agent", "runtime_blacklist"
    public let verdict: String     // "block", "warn"
    public let timestamp: String   // ISO 8601

    enum CodingKeys: String, CodingKey {
        case eventType = "event_type"
        case domain
        case layer
        case verdict
        case timestamp
    }

    public init(eventType: String, domain: String, layer: String, verdict: String) {
        self.eventType = eventType
        self.domain = domain
        self.layer = layer
        self.verdict = verdict
        self.timestamp = ISO8601DateFormatter().string(from: Date())
    }
}

// MARK: - Session stats

public struct SessionStats: Codable {
    public var totalQueries: Int = 0
    public var cacheHits: Int = 0
    public var bloomWhitelistHits: Int = 0
    public var bloomBlacklistHits: Int = 0
    public var infrastructureAllowed: Int = 0
    public var brandRuleWarns: Int = 0
    public var mlWarns: Int = 0
    public var apiCalls: Int = 0
    public var blocks: Int = 0
    public var warns: Int = 0
    public var periodSeconds: Int = 3600

    enum CodingKeys: String, CodingKey {
        case totalQueries = "total_queries"
        case cacheHits = "cache_hits"
        case bloomWhitelistHits = "bloom_whitelist_hits"
        case bloomBlacklistHits = "bloom_blacklist_hits"
        case infrastructureAllowed = "infrastructure_allowed"
        case brandRuleWarns = "brand_rule_warns"
        case mlWarns = "ml_warns"
        case apiCalls = "api_calls"
        case blocks
        case warns
        case periodSeconds = "period_seconds"
    }
}

// MARK: - Batch payload

private struct TelemetryBatch: Codable {
    let events: [TelemetryEvent]
    let sessionStats: SessionStats?
    let deviceId: String?

    enum CodingKeys: String, CodingKey {
        case events
        case sessionStats = "session_stats"
        case deviceId = "device_id"
    }
}

// MARK: - TelemetryClient

/// Collects blocked/warned events in memory and batch-uploads them periodically.
///
/// Design principles:
/// - NEVER records allowed/normal domains (privacy).
/// - Fire-and-forget: failures are silently ignored, never block DNS.
/// - Anonymous: uses a random device UUID stored in App Group, no user identity.
/// - Batches uploads every 60 minutes or when 50 events accumulate.
public final class TelemetryClient {

    public static let shared = TelemetryClient()

    private static let suiteName = "group.com.24defend.app"
    private static let deviceIdKey = "telemetry_device_id"
    private static let maxQueueSize = 200
    private static let uploadThreshold = 50
    private static let uploadIntervalSeconds: TimeInterval = 3600  // 60 minutes

    // Thread-safe access via a serial queue
    private let queue = DispatchQueue(label: "com.24defend.telemetry", qos: .utility)

    private var eventQueue: [TelemetryEvent] = []
    private var stats = SessionStats()
    private var statsStartTime = Date()
    private var uploadTimer: DispatchSourceTimer?

    /// Anonymous device identifier — generated once, persisted in App Group.
    private let deviceId: String

    /// URLSession that bypasses our VPN tunnel (same pattern as APIClient).
    private let session: URLSession = {
        let config = URLSessionConfiguration.default
        config.connectionProxyDictionary = [:]  // bypass proxy/VPN
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 30
        return URLSession(configuration: config)
    }()

    private init() {
        let defaults = UserDefaults(suiteName: Self.suiteName)
        if let existing = defaults?.string(forKey: Self.deviceIdKey) {
            deviceId = existing
        } else {
            let newId = UUID().uuidString
            defaults?.set(newId, forKey: Self.deviceIdKey)
            deviceId = newId
        }
    }

    // MARK: - Event recording (called from packet tunnel hot path)

    /// Record a blocked domain event. Safe to call from any thread.
    public func recordBlock(domain: String, layer: String) {
        let baseDomain = BloomFilterStore.extractBaseDomain(domain)
        let event = TelemetryEvent(eventType: "blocked", domain: baseDomain, layer: layer, verdict: "block")
        enqueue(event)

        queue.async { self.stats.blocks += 1 }
    }

    /// Record a warned domain event. Safe to call from any thread.
    public func recordWarn(domain: String, layer: String) {
        let baseDomain = BloomFilterStore.extractBaseDomain(domain)
        let event = TelemetryEvent(eventType: "warned", domain: baseDomain, layer: layer, verdict: "warn")
        enqueue(event)

        queue.async { self.stats.warns += 1 }
    }

    // MARK: - Session stat counters (called from packet tunnel hot path)

    public func incrementTotalQueries() {
        queue.async { self.stats.totalQueries += 1 }
    }

    public func incrementCacheHits() {
        queue.async { self.stats.cacheHits += 1 }
    }

    public func incrementBloomWhitelistHits() {
        queue.async { self.stats.bloomWhitelistHits += 1 }
    }

    public func incrementBloomBlacklistHits() {
        queue.async { self.stats.bloomBlacklistHits += 1 }
    }

    public func incrementInfrastructureAllowed() {
        queue.async { self.stats.infrastructureAllowed += 1 }
    }

    public func incrementBrandRuleWarns() {
        queue.async { self.stats.brandRuleWarns += 1 }
    }

    public func incrementMLWarns() {
        queue.async { self.stats.mlWarns += 1 }
    }

    public func incrementAPICalls() {
        queue.async { self.stats.apiCalls += 1 }
    }

    // MARK: - Upload timer

    /// Start the periodic upload timer. Call once when the tunnel starts.
    public func startUploadTimer() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(
            deadline: .now() + Self.uploadIntervalSeconds,
            repeating: Self.uploadIntervalSeconds
        )
        timer.setEventHandler { [weak self] in
            self?.flushAsync()
        }
        timer.resume()
        uploadTimer = timer
    }

    /// Stop the upload timer and flush remaining events. Call when tunnel stops.
    public func stopAndFlush() {
        uploadTimer?.cancel()
        uploadTimer = nil
        flushAsync()
    }

    // MARK: - Internal

    private func enqueue(_ event: TelemetryEvent) {
        queue.async {
            if self.eventQueue.count >= Self.maxQueueSize {
                // Drop oldest events to stay within cap
                self.eventQueue.removeFirst(self.eventQueue.count - Self.maxQueueSize + 1)
            }
            self.eventQueue.append(event)

            // Trigger upload if threshold reached
            if self.eventQueue.count >= Self.uploadThreshold {
                self.flushAsync()
            }
        }
    }

    /// Flush events off the serial queue, fire-and-forget.
    private func flushAsync() {
        // Already on self.queue or called from timer on self.queue
        let events = self.eventQueue
        let currentStats = self.stats
        let elapsed = Int(Date().timeIntervalSince(self.statsStartTime))

        // Reset state
        self.eventQueue.removeAll()
        self.stats = SessionStats()
        self.statsStartTime = Date()

        guard !events.isEmpty || currentStats.totalQueries > 0 else { return }

        var statsToSend = currentStats
        statsToSend.periodSeconds = max(elapsed, 1)

        let batch = TelemetryBatch(
            events: events,
            sessionStats: currentStats.totalQueries > 0 ? statsToSend : nil,
            deviceId: deviceId
        )

        // Fire-and-forget upload on a detached task
        Task.detached(priority: .utility) { [weak self] in
            await self?.upload(batch)
        }
    }

    private func upload(_ batch: TelemetryBatch) async {
        guard let url = URL(string: "\(APIClient.baseURL)/telemetry/events") else { return }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        guard let body = try? JSONEncoder().encode(batch) else { return }
        request.httpBody = body

        do {
            let (_, response) = try await session.data(for: request)
            if let http = response as? HTTPURLResponse, http.statusCode != 200 {
                // Silently ignore — telemetry is best-effort
            }
        } catch {
            // Silently ignore — telemetry must never affect DNS filtering
        }
    }
}
