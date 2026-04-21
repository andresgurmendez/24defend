import NetworkExtension
import Network
import UserNotifications
import os

class PacketTunnelProvider: NEPacketTunnelProvider {

    private let logger = Logger(subsystem: "com.24defend.app.packet-tunnel", category: "dns")
    private let upstreamDNS = "1.1.1.1"
    private var recentNotifications: Set<String> = []  // debounce: one notification per domain
    private var runtimeBlacklist: Set<String> = []    // domains confirmed bad by backend
    private var httpListener: NWListener?
    private var httpsRejectListener: NWListener?
    private var refreshTimer: DispatchSourceTimer?
    private var dailyBlacklistTimer: DispatchSourceTimer?
    private let dnsCache = DNSCache(maxSize: 2000, ttl: 3600) // 2K entries, 1 hour TTL
    private let telemetry = TelemetryClient.shared
    private var lastWhitelistHitTime: Date?
    private var lastWhitelistDomain: String?
    private var lastNotificationTime: Date?

    // MARK: - Tunnel lifecycle

    override func startTunnel(options: [String: NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting 24Defend DNS filter tunnel")

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        // TUN interface — only DNS traffic is routed here
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "198.18.0.0", subnetMask: "255.254.0.0")]
        settings.ipv4Settings = ipv4

        // Point the device's DNS at our TUN address
        let dns = NEDNSSettings(servers: ["198.18.0.1"])
        dns.matchDomains = [""]  // match all domains
        settings.dnsSettings = dns

        settings.mtu = 1500 as NSNumber

        setTunnelNetworkSettings(settings) { error in
            if let error = error {
                self.logger.error("Tunnel settings failed: \(error.localizedDescription)")
                completionHandler(error)
                return
            }
            self.logger.info("Tunnel settings applied — reading packets")
            self.startBlockPageServer()
            self.readPackets()
            completionHandler(nil)

            // Initial refresh + schedule daily repeating refresh
            Task { await self.refreshData() }
            self.startRefreshTimer()
            self.startDailyBlacklistTimer()
            self.telemetry.startUploadTimer()
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Stopping tunnel (reason: \(String(describing: reason)))")
        refreshTimer?.cancel()
        refreshTimer = nil
        dailyBlacklistTimer?.cancel()
        dailyBlacklistTimer = nil
        telemetry.stopAndFlush()
        completionHandler()
    }

    // MARK: - Periodic data refresh

    private func startRefreshTimer() {
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + 86400, repeating: 86400) // every 24 hours
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.logger.info("Daily refresh triggered")
            Task { await self.refreshData() }
        }
        timer.resume()
        refreshTimer = timer
    }

    private func startDailyBlacklistTimer() {
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + 1800, repeating: 1800) // every 30 minutes
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.logger.info("Daily blacklist refresh triggered")
            Task {
                await DailyBlacklist.shared.refresh()
                self.logger.info("Daily blacklist refreshed")
            }
        }
        timer.resume()
        dailyBlacklistTimer = timer
    }

    private func refreshData() async {
        if BloomFilterStore.shared.needsRefresh {
            logger.info("Refreshing bloom filters...")
            await BloomFilterStore.shared.refresh()
            logger.info("Bloom filters refreshed")
        }

        logger.info("Refreshing classifier weights...")
        await PhishingClassifier.refreshWeights()
        logger.info("Classifier weights refreshed")

        // Refresh daily blacklist on startup too
        if DailyBlacklist.shared.needsRefresh {
            logger.info("Refreshing daily blacklist...")
            await DailyBlacklist.shared.refresh()
            logger.info("Daily blacklist refreshed")
        }

        // Clear verdict cache so new bloom/classifier data takes effect
        dnsCache.clear()
        logger.info("DNS verdict cache cleared")
    }

    // MARK: - Packet loop

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            for (i, packet) in packets.enumerated() {
                self.handlePacket(packet, proto: protocols[i])
            }
            self.readPackets()
        }
    }

    private func handlePacket(_ packet: Data, proto: NSNumber) {
        guard let parsed = IPPacket.parse(packet) else { return }
        guard parsed.destPort == 53 else { return }
        guard let query = DNSPacket.parseQuery(from: parsed.dnsPayload) else { return }

        let domain = query.domainName
        telemetry.incrementTotalQueries()

        // 0. Local verdict cache — skip all layers for recently seen domains
        if let cached = dnsCache.get(domain) {
            telemetry.incrementCacheHits()
            switch cached {
            case .allow:
                forwardToUpstream(query: query, original: parsed, proto: proto)
            case .block:
                let dnsResp = DNSPacket.buildBlockResponse(for: query)
                let ipResp = IPPacket.buildResponse(original: parsed, dnsResponse: dnsResp)
                packetFlow.writePackets([ipResp], withProtocols: [proto])
            }
            return
        }

        let store = BloomFilterStore.shared

        // 1. Runtime blacklist (domains confirmed bad by backend this session)
        if runtimeBlacklist.contains(domain.lowercased()) {
            dnsCache.set(domain, verdict: .block)
            logger.warning("BLOCKED (runtime) \(domain)")
            telemetry.recordBlock(domain: domain, layer: "runtime_blacklist")
            BlockLog.append(BlockEvent(domain: domain, reason: "Confirmed by 24Defend cloud", severity: .red))
            sendNotification(domain: domain, reason: "Confirmed phishing site", severity: .red)
            let dnsResp = DNSPacket.buildBlockResponse(for: query)
            let ipResp  = IPPacket.buildResponse(original: parsed, dnsResponse: dnsResp)
            packetFlow.writePackets([ipResp], withProtocols: [proto])
            return
        }

        // 2. Infrastructure domains → always allow (CDNs, Apple, Google, etc.)
        if DomainChecker.isInfrastructureDomain(domain.lowercased()) {
            telemetry.incrementInfrastructureAllowed()
            dnsCache.set(domain, verdict: .allow)
            forwardToUpstream(query: query, original: parsed, proto: proto)
            return
        }

        // 3. Bloom filter: whitelist → silent allow (no further checks)
        if store.isWhitelisted(domain) {
            telemetry.incrementBloomWhitelistHits()
            dnsCache.set(domain, verdict: .allow)
            lastWhitelistHitTime = Date()
            lastWhitelistDomain = domain
            forwardToUpstream(query: query, original: parsed, proto: proto)
            return
        }

        // 4. Bloom filter: blacklist hit → confirm with API before blocking
        //    Eliminates bloom filter false positives (e.g., googletagmanager.com)
        if store.isBlacklisted(domain) {
            telemetry.incrementBloomBlacklistHits()

            // Check known FP list first (avoids API call for previously cleared domains)
            if DailyBlacklist.shared.isFalsePositive(domain) {
                dnsCache.set(domain, verdict: .allow)
                forwardToUpstream(query: query, original: parsed, proto: proto)
                return
            }

            // Confirm with backend (fast DynamoDB lookup, ~50ms)
            Task {
                let apiVerdict = await APIClient.checkDomain(domain)

                if apiVerdict?.verdict == "block" {
                    // Confirmed — block it
                    self.dnsCache.set(domain, verdict: .block)
                    self.runtimeBlacklist.insert(domain.lowercased())
                    self.telemetry.recordBlock(domain: domain, layer: "bloom_blacklist")
                    self.logger.warning("BLOCKED (bloom+confirmed) \(domain)")
                    BlockLog.append(BlockEvent(domain: domain, reason: apiVerdict?.reason ?? "Known phishing domain", severity: .red))
                    self.sendNotification(domain: domain, reason: "\(domain) is a known phishing site", severity: .red)

                    let dnsResp = DNSPacket.buildBlockResponse(for: query)
                    let ipResp = IPPacket.buildResponse(original: parsed, dnsResponse: dnsResp)
                    self.packetFlow.writePackets([ipResp], withProtocols: [proto])
                } else {
                    // False positive — allow and record
                    self.dnsCache.set(domain, verdict: .allow)
                    self.logger.info("BLOOM FP: \(domain) — API says allow")
                    self.forwardToUpstream(query: query, original: parsed, proto: proto)
                }
            }
            return
        }

        // 4b. Daily blacklist: domains confirmed bad by backend investigation (polled every 30 min)
        if DailyBlacklist.shared.contains(domain) {
            telemetry.recordBlock(domain: domain, layer: "daily_blacklist")
            dnsCache.set(domain, verdict: .block)
            logger.warning("BLOCKED (daily blacklist) \(domain)")
            BlockLog.append(BlockEvent(domain: domain, reason: "Confirmed phishing by 24Defend analysis", severity: .red))
            sendNotification(domain: domain, reason: "\(domain) is a confirmed phishing site", severity: .red)
            let dnsResp = DNSPacket.buildBlockResponse(for: query)
            let ipResp  = IPPacket.buildResponse(original: parsed, dnsResponse: dnsResp)
            packetFlow.writePackets([ipResp], withProtocols: [proto])
            return
        }

        // 5-7. On-device heuristic check (Levenshtein, brand rules, ML classifier)
        let result = DomainChecker.check(domain: domain)

        switch result {
        case .blocked(let reason):
            // Determine which layer caused the block for telemetry
            let layer: String
            if reason.contains("Known phishing") || reason.contains("Subdomain of known") {
                layer = "brand_rules"
            } else {
                layer = "brand_rules"
            }
            telemetry.recordBlock(domain: domain, layer: layer)
            dnsCache.set(domain, verdict: .block)
            logger.warning("BLOCKED \(domain) — \(reason)")
            BlockLog.append(BlockEvent(domain: domain, reason: reason, severity: .red))
            sendNotification(domain: domain, reason: reason, severity: .red)

            let dnsResp = DNSPacket.buildBlockResponse(for: query)
            let ipResp  = IPPacket.buildResponse(original: parsed, dnsResponse: dnsResp)
            packetFlow.writePackets([ipResp], withProtocols: [proto])

        case .warned(let reason):
            if reason.contains("ML model") {
                // ML classifier flag: silent screener mode.
                // Forward DNS normally (user sees nothing), submit domain to backend
                // in the background (fire-and-forget). If the backend confirms it's bad,
                // it goes into the daily blacklist and gets caught on next visit.
                telemetry.incrementMLWarns()
                telemetry.incrementAPICalls()
                logger.info("ML silent submit: \(domain) — \(reason)")
                dnsCache.set(domain, verdict: .allow)
                forwardToUpstream(query: query, original: parsed, proto: proto)

                // Fire-and-forget: silently submit to backend for investigation
                Task.detached(priority: .utility) {
                    _ = await APIClient.checkDomain(domain)
                }
            } else {
                // Brand rule engine warnings: these are more reliable, keep existing behavior.
                // Hold DNS, check backend, then decide.
                let layer: String
                if reason.contains("Suspicious:") {
                    layer = "brand_rules"
                    telemetry.incrementBrandRuleWarns()
                } else {
                    layer = "brand_rules"
                    telemetry.incrementBrandRuleWarns()
                }

                logger.info("WARNED \(domain) — \(reason)")
                telemetry.incrementAPICalls()
                Task {
                    let backendVerdict = await APIClient.checkDomain(domain)

                    if backendVerdict?.verdict == "block" {
                        self.dnsCache.set(domain, verdict: .block)
                        self.logger.warning("ESCALATED to BLOCK: \(domain)")
                        self.runtimeBlacklist.insert(domain.lowercased())
                        self.telemetry.recordBlock(domain: domain, layer: "agent")
                        BlockLog.append(BlockEvent(domain: domain, reason: backendVerdict?.reason ?? reason, severity: .red))
                        self.sendNotification(domain: domain, reason: backendVerdict?.reason ?? reason, severity: .red)

                        let dnsResp = DNSPacket.buildBlockResponse(for: query)
                        let ipResp = IPPacket.buildResponse(original: parsed, dnsResponse: dnsResp)
                        self.packetFlow.writePackets([ipResp], withProtocols: [proto])
                    } else {
                        // Don't cache warned domains — re-check next time in case backend updates
                        self.telemetry.recordWarn(domain: domain, layer: layer)
                        BlockLog.append(BlockEvent(domain: domain, reason: reason, severity: .yellow))
                        self.sendNotification(domain: domain, reason: reason, severity: .yellow)
                        self.forwardToUpstream(query: query, original: parsed, proto: proto)
                    }
                }
            }

        case .allowed:
            dnsCache.set(domain, verdict: .allow)
            forwardToUpstream(query: query, original: parsed, proto: proto)
        }
    }

    // MARK: - Upstream forwarding

    private func forwardToUpstream(query: DNSPacket.Query, original: IPPacket.Parsed, proto: NSNumber) {
        let conn = NWConnection(
            host: NWEndpoint.Host(upstreamDNS),
            port: 53,
            using: .udp
        )

        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                conn.send(content: query.fullDNSData, completion: .contentProcessed { error in
                    if let error {
                        self.logger.error("DNS send error: \(error.localizedDescription)")
                        conn.cancel()
                        return
                    }
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 65535) { data, _, _, _ in
                        defer { conn.cancel() }
                        guard let data else { return }
                        let ipResp = IPPacket.buildResponse(original: original, dnsResponse: data)
                        self.packetFlow.writePackets([ipResp], withProtocols: [proto])
                    }
                })
            case .failed(let error):
                self.logger.error("DNS upstream connection failed: \(error.localizedDescription)")
                conn.cancel()
            default:
                break
            }
        }

        conn.start(queue: .global(qos: .userInteractive))
    }

    // MARK: - Block page HTTP server

    private func startBlockPageServer() {
        do {
            let params = NWParameters.tcp
            params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: 80)

            httpListener = try NWListener(using: params)
            httpListener?.newConnectionHandler = { [weak self] conn in
                self?.handleBlockPageConnection(conn)
            }
            httpListener?.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    self?.logger.info("Block page server ready on 127.0.0.1:80")
                case .failed(let error):
                    self?.logger.error("Block page server failed: \(error.localizedDescription)")
                default:
                    break
                }
            }
            httpListener?.start(queue: .global(qos: .userInteractive))

            // Also listen on 443 and immediately reject — forces Safari to fall back to HTTP faster
            let tlsParams = NWParameters.tcp
            tlsParams.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: 443)
            httpsRejectListener = try NWListener(using: tlsParams)
            httpsRejectListener?.newConnectionHandler = { [weak self] conn in
                self?.logger.info("HTTPS connection received — rejecting to force HTTP fallback")
                conn.start(queue: .global())
                conn.cancel()
            }
            httpsRejectListener?.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    self?.logger.info("HTTPS reject listener ready on 127.0.0.1:443")
                case .failed(let error):
                    self?.logger.error("HTTPS reject listener failed: \(error.localizedDescription)")
                default:
                    break
                }
            }
            httpsRejectListener?.start(queue: .global(qos: .userInteractive))
        } catch {
            logger.error("Failed to start block page server: \(error.localizedDescription)")
        }
    }

    private func handleBlockPageConnection(_ connection: NWConnection) {
        connection.start(queue: .global(qos: .userInteractive))

        // Read the HTTP request (we don't really need it, but must consume it)
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] _, _, _, _ in
            guard self != nil else { return }

            let html = """
            <!DOCTYPE html>
            <html lang="es">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Sitio bloqueado — 24Defend</title>
            <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, sans-serif;
                background: #0F172A;
                color: #E2E8F0;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 24px;
            }
            .card {
                text-align: center;
                max-width: 400px;
            }
            .shield {
                width: 80px; height: 80px;
                margin: 0 auto 24px;
                background: #1E293B;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                border: 3px solid #EF4444;
            }
            .shield svg {
                width: 40px; height: 40px;
                fill: #EF4444;
            }
            h1 {
                color: #EF4444;
                font-size: 22px;
                font-weight: 700;
                margin-bottom: 12px;
            }
            .desc {
                color: #94A3B8;
                font-size: 15px;
                line-height: 1.5;
                margin-bottom: 24px;
            }
            .domain {
                background: #1E293B;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 12px 16px;
                font-family: ui-monospace, monospace;
                font-size: 14px;
                color: #F87171;
                margin-bottom: 24px;
                word-break: break-all;
            }
            .footer {
                color: #475569;
                font-size: 12px;
            }
            </style>
            </head>
            <body>
            <div class="card">
                <div class="shield">
                    <svg viewBox="0 0 24 24"><path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7L12 2zm-1 15l-4-4 1.41-1.41L11 14.17l5.59-5.59L18 10l-7 7z"/></svg>
                </div>
                <h1>Sitio bloqueado</h1>
                <p class="desc">
                    24Defend ha bloqueado el acceso a este sitio porque ha sido identificado como fraudulento o de phishing.
                </p>
                <div class="domain" id="blocked-domain"></div>
                <p class="footer">Protegido por 24Defend</p>
            </div>
            <script>document.getElementById('blocked-domain').textContent=location.hostname;</script>
            </body>
            </html>
            """

            let headerAndBody = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: \(html.utf8.count)\r\nConnection: close\r\n\r\n\(html)"

            connection.send(
                content: headerAndBody.data(using: .utf8),
                contentContext: .finalMessage,
                isComplete: true,
                completion: .contentProcessed { _ in
                    connection.cancel()
                }
            )
        }
    }

    // MARK: - Notifications

    private func sendNotification(domain: String, reason: String, severity: EventSeverity, force: Bool = false) {
        // Suppress if we're in a "page resource" window (user just visited a whitelisted domain)
        if !force, let lastWL = lastWhitelistHitTime, Date().timeIntervalSince(lastWL) < 3.0 {
            logger.info("Suppressed notification for \(domain) — likely page resource of \(lastWhitelistDomain ?? "unknown")")
            return
        }

        // Rate limit: max 1 notification per 5 seconds
        if !force, let lastNotif = lastNotificationTime, Date().timeIntervalSince(lastNotif) < 5.0 {
            logger.info("Suppressed notification for \(domain) — rate limited")
            return
        }

        // Debounce: only one notification per domain per session (unless forced by escalation)
        if !force {
            guard !recentNotifications.contains(domain) else { return }
        }
        recentNotifications.insert(domain)

        let content = UNMutableNotificationContent()

        switch severity {
        case .red:
            content.title = "Phishing link blocked"
            content.body = "\(domain) is a known malicious site. Access was prevented."
        case .yellow:
            content.title = "Suspicious link detected"
            content.body = "\(domain) — \(reason). Proceed with caution."
        }

        content.sound = .default

        let request = UNNotificationRequest(
            identifier: "24defend-\(domain)",
            content: content,
            trigger: nil  // deliver immediately
        )

        lastNotificationTime = Date()

        UNUserNotificationCenter.current().add(request) { error in
            if let error {
                self.logger.error("Notification error: \(error.localizedDescription)")
            }
        }
    }
}
