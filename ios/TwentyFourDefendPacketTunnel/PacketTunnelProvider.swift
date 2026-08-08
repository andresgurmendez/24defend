import NetworkExtension
import Network
import UserNotifications
import os

class PacketTunnelProvider: NEPacketTunnelProvider {

    private let logger = Logger(subsystem: "com.24defend.app.packet-tunnel", category: "dns")

    // Upstream DNS servers. All three are fired in PARALLEL for every
    // query (see forwardToUpstream); the first response wins and the
    // others are cancelled. This replaces the previous sequential
    // cascade (build 10), which was too slow: during a network drop
    // where ALL upstreams timeout, sequential cost was 3 × 2 s = 6 s
    // per query. Real-user diagnostic log on 2026-08-01 showed bursts
    // of 15-30 s during network transitions where every query paid
    // that full 6 s cost — making it look like "no internet" to the
    // user, since browsers give up at 5 s.
    private let upstreamDNSList = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    // Hard timeout per query (applies to the whole parallel race,
    // not per-upstream). Cloudflare/Google/Quad9 all respond in
    // < 50 ms typically; 800 ms is 15× the p95 for a healthy path,
    // enough tolerance for jitter but 7.5× faster than the old 2 s
    // when the network is genuinely dead.
    private let upstreamTimeoutSeconds: TimeInterval = 0.8

    // Monitor iOS's own view of network reachability. When it reports
    // .unsatisfied (no interface available — WiFi off + no cellular,
    // airplane mode, or between-network handoffs), we drop DNS queries
    // instantly instead of paying the 800 ms timeout on each. This is
    // the near-zero-cost fast-path for "the network is genuinely down."
    private let pathMonitor = NWPathMonitor()
    private var currentPathStatus: Network.NWPath.Status = .satisfied
    // Notification dedup by BASE DOMAIN (not exact hostname), so that
    // sorteo.brou.hk and www.sorteo.brou.hk are treated as one "site".
    // Notification dedup + follow-up gating is BlockLog-backed because iOS
    // routinely restarts packet-tunnel extensions (sleep/wake, network
    // transitions, jetsam, etc.) and in-memory sets are wiped. Previously
    // that meant no green/blue/red would ever fire for a yellow that got
    // resolved on the backend after a restart. BlockLog is persisted to the
    // app group's UserDefaults so it survives. See `hasEvent(for:severity:)`.
    // yellowNotificationDomain is a session-only optimization for the green
    // "replace-in-tray" identifier; falls back to `domain` if not present.
    private var yellowNotificationDomain: [String: String] = [:]
    private var runtimeBlacklist: Set<String> = []    // domains confirmed bad by backend
    private var httpListener: NWListener?
    private var httpsRejectListener: NWListener?
    private var refreshTimer: DispatchSourceTimer?
    private var dailyBlacklistTimer: DispatchSourceTimer?
    private var investigationTimer: DispatchSourceTimer?
    private var memoryTimer: DispatchSourceTimer?
    // 500 entries × ~120 bytes ≈ 60KB — well inside the packet-tunnel
    // ~15MB extension budget. Was 2000 previously, but the extension has
    // been getting killed by iOS jetsam under memory pressure. Smaller
    // cache trades a bit of latency (more re-classifications on cache
    // eviction) for headroom that keeps us alive.
    private let dnsCache = DNSCache(maxSize: 500, ttl: 3600)
    private let telemetry = TelemetryClient.shared
    private var lastWhitelistHitTime: Date?
    private var lastWhitelistDomain: String?
    private var lastNotificationTime: Date?

    // MARK: - Tunnel lifecycle

    override func startTunnel(options: [String: NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        logger.info("Starting 24Defend DNS filter tunnel")
        DiagnosticLog.record(.tunnel, "startTunnel — extension launched")

        // Watch the underlying network path so we can short-circuit DNS
        // queries when there's genuinely no interface available.
        pathMonitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let previous = self.currentPathStatus
            self.currentPathStatus = path.status
            if previous != path.status {
                DiagnosticLog.record(.tunnel, "Network path changed: \(previous) → \(path.status)")
            }
        }
        pathMonitor.start(queue: .global(qos: .utility))

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

            // Defer the heavy refresh (bloom filter download + classifier
            // weights) 5 seconds off the critical path. Doing it inline was
            // a memory spike right at start, when iOS is already deciding
            // whether we're a "well-behaved" extension worth keeping around.
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) {
                Task { await self.refreshData() }
            }
            self.startRefreshTimer()
            self.startDailyBlacklistTimer()
            self.startInvestigationPolling()
            self.startMemoryWatchdog()
            self.telemetry.startUploadTimer()
        }
    }

    /// Log the extension's remaining memory budget every minute.
    /// iOS silently kills packet-tunnel extensions when they blow past ~15MB
    /// (device- and version-dependent) — jetsam. We can't recover from a kill
    /// once it happens, but the log lets us verify from Console.app whether
    /// we're actually operating close to the ceiling in the field.
    private func startMemoryWatchdog() {
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + 60, repeating: 60)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            let availableBytes = Int(os_proc_available_memory())
            let availableMB = Double(availableBytes) / 1_048_576.0
            if availableMB < 3.0 {
                self.logger.warning("MEMORY LOW: \(availableMB, format: .fixed(precision: 2))MB available")
                DiagnosticLog.record(.memory, String(format: "LOW %.2f MB available", availableMB))
            } else {
                self.logger.info("MEMORY: \(availableMB, format: .fixed(precision: 2))MB available")
                // Skip diagnostic log for the common non-low case — it fires every 60s
                // and would fill the 500-entry buffer with noise.
            }
        }
        timer.resume()
        memoryTimer = timer
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // Log both the rawValue (for grep-able telemetry) and a symbolic name
        // for the reasons we care about. See NEProviderStopReason enum:
        //   1  userInitiated       — user tapped disconnect
        //   2  providerFailed      — extension threw / crashed
        //   3  noNetworkAvailable  — device fully offline
        //   4  unrecoverableNetworkChange
        //   5  providerDisabled    — profile disabled
        //   6  authenticationCanceled
        //   7  configurationFailed
        //   8  idleTimeout
        //   9  configurationDisabled
        //  10  configurationRemoved
        //  11  superceded          — replaced by a new tunnel
        //  12  userLogout / userSwitch
        //  13  connectionFailed
        //  14  sleep               — iOS put device to sleep
        //  15  appUpdate           — extension being updated
        // Any of {2, 8, 11, 14} showing up regularly = we're getting killed.
        // Combined with the on-demand rule (see VPNManager) iOS will now
        // relaunch us, but the reason still tells us WHY we went down.
        let name: String = {
            switch reason {
            case .userInitiated: return "userInitiated"
            case .providerFailed: return "providerFailed"
            case .noNetworkAvailable: return "noNetworkAvailable"
            case .unrecoverableNetworkChange: return "unrecoverableNetworkChange"
            case .providerDisabled: return "providerDisabled"
            case .authenticationCanceled: return "authenticationCanceled"
            case .configurationFailed: return "configurationFailed"
            case .idleTimeout: return "idleTimeout"
            case .configurationDisabled: return "configurationDisabled"
            case .configurationRemoved: return "configurationRemoved"
            case .superceded: return "superceded"
            case .userLogout: return "userLogout"
            case .userSwitch: return "userSwitch"
            case .connectionFailed: return "connectionFailed"
            case .sleep: return "sleep"
            case .appUpdate: return "appUpdate"
            @unknown default: return "unknown"
            }
        }()
        logger.info("Stopping tunnel (reason=\(reason.rawValue) \(name))")
        DiagnosticLog.record(.tunnel, "stopTunnel — reason=\(reason.rawValue) (\(name))")

        refreshTimer?.cancel()
        refreshTimer = nil
        dailyBlacklistTimer?.cancel()
        dailyBlacklistTimer = nil
        investigationTimer?.cancel()
        investigationTimer = nil
        memoryTimer?.cancel()
        memoryTimer = nil
        pathMonitor.cancel()
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

    private func startInvestigationPolling() {
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + 30, repeating: 30) // every 30 seconds
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            Task {
                let result = await PendingInvestigation.shared.pollAll()

                // Confirmed threats → retroactive RED escalation
                for domain in result.confirmedThreats {
                    self.runtimeBlacklist.insert(domain)
                    self.dnsCache.set(domain, verdict: .block)
                    self.telemetry.recordBlock(domain: domain, layer: "investigation")
                    BlockLog.append(BlockEvent(
                        domain: domain,
                        reason: "Confirmed fraudulent after investigation",
                        severity: .red
                    ))
                    // Critical safety notification — bypass all suppression.
                    // Body copy is set in sendNotification (severity=.red + force=true
                    // → retroactive template), the `reason` here is only for BlockLog.
                    self.sendNotification(
                        domain: domain,
                        reason: "Confirmado como fraudulento tras investigación.",
                        severity: .red,
                        force: true
                    )
                    self.logger.warning("RETROACTIVE BLOCK: \(domain) confirmed malicious after investigation")
                }

                // Cleared domains → GREEN closure notification, but ONLY if
                // we already fired a yellow for that base domain. We check
                // BlockLog (persisted) instead of the in-memory yellowNotified
                // set so this works across tunnel restarts.
                for domain in result.cleared {
                    let baseKey = BloomFilterStore.extractBaseDomain(domain.lowercased())
                    guard self.hasEvent(baseKey: baseKey, severity: .yellow),
                          !self.hasEvent(baseKey: baseKey, severity: .red),
                          !self.hasEvent(baseKey: baseKey, severity: .green) else { continue }

                    BlockLog.append(BlockEvent(
                        domain: domain,
                        reason: "Verificado como sitio real tras investigación",
                        severity: .green
                    ))
                    self.sendNotification(
                        domain: domain,
                        reason: "Verificado como sitio real.",
                        severity: .green,
                        force: true
                    )
                    self.logger.info("CLEARED: \(domain) — agent confirmed legit; green sent")
                }

                // Inconclusive → CHECKED closure notification. Same guards as
                // green: only fire if we yellow-notified this base (per
                // BlockLog) and haven't already escalated to red or resolved
                // to green or checked.
                for domain in result.inconclusive {
                    let baseKey = BloomFilterStore.extractBaseDomain(domain.lowercased())
                    guard self.hasEvent(baseKey: baseKey, severity: .yellow),
                          !self.hasEvent(baseKey: baseKey, severity: .red),
                          !self.hasEvent(baseKey: baseKey, severity: .green),
                          !self.hasEvent(baseKey: baseKey, severity: .checked) else { continue }

                    BlockLog.append(BlockEvent(
                        domain: domain,
                        reason: "Revisión terminada — no encontramos señales claras de fraude, pero tampoco pudimos confirmar del todo que sea legítimo",
                        severity: .checked
                    ))
                    self.sendNotification(
                        domain: domain,
                        reason: "Revisión terminada, no concluyente.",
                        severity: .checked,
                        force: true
                    )
                    self.logger.info("INCONCLUSIVE: \(domain) — agent returned warn; checked sent")
                }
            }
        }
        timer.resume()
        investigationTimer = timer
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

        // Always refresh daily blacklist at tunnel start so the local copy
        // matches the latest backend state. If we ONLY refreshed when
        // needsRefresh returns true (age-based), a domain we allowlist
        // server-side can still trigger red blocks on the client for up to
        // 30 min (per-user cache TTL). Cheap network call, small payload.
        logger.info("Refreshing daily blacklist (forced at tunnel start)...")
        await DailyBlacklist.shared.refresh()
        logger.info("Daily blacklist refreshed")

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
        let domainLower = domain.lowercased()  // compute once, reuse everywhere
        telemetry.incrementTotalQueries()

        // 0. Local verdict cache — skip all layers for recently seen domains
        if let cached = dnsCache.get(domainLower) {
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
        if runtimeBlacklist.contains(domainLower) {
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
        if DomainChecker.isInfrastructureDomain(domainLower) {
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

        // 4b. Daily blacklist: domains confirmed bad by backend investigation
        //     (refreshed every 30 min). We CONFIRM with the backend before
        //     blocking — same pattern as the bloom-filter path (step 4) —
        //     because a domain we allowlisted server-side can still be in
        //     the client's local daily-blacklist copy for up to 30 min after
        //     the allowlist decision. Without confirmation, users see red
        //     block notifications for domains we've already deemed safe
        //     (observed on pedidosya.dhmedia.io after we shipped the
        //     dhmedia.io VENDOR_ALLOWLIST entry). Confirmation is a fast
        //     DDB lookup (~50ms).
        if DailyBlacklist.shared.contains(domain) {
            telemetry.incrementBloomBlacklistHits()

            if DailyBlacklist.shared.isFalsePositive(domain) {
                dnsCache.set(domain, verdict: .allow)
                forwardToUpstream(query: query, original: parsed, proto: proto)
                return
            }

            Task {
                let apiVerdict = await APIClient.checkDomain(domain)
                if apiVerdict?.verdict == "block" {
                    self.telemetry.recordBlock(domain: domain, layer: "daily_blacklist")
                    self.dnsCache.set(domain, verdict: .block)
                    self.runtimeBlacklist.insert(domain.lowercased())
                    self.logger.warning("BLOCKED (daily blacklist + confirmed) \(domain)")
                    BlockLog.append(BlockEvent(
                        domain: domain,
                        reason: apiVerdict?.reason ?? "Confirmed phishing by 24Defend analysis",
                        severity: .red
                    ))
                    self.sendNotification(domain: domain, reason: "\(domain) is a confirmed phishing site", severity: .red)

                    let dnsResp = DNSPacket.buildBlockResponse(for: query)
                    let ipResp = IPPacket.buildResponse(original: parsed, dnsResponse: dnsResp)
                    self.packetFlow.writePackets([ipResp], withProtocols: [proto])
                } else {
                    // Backend has since allowlisted this domain (or the
                    // agent reversed the verdict). Don't block. Cache the
                    // allow so subsequent queries this session are fast.
                    self.dnsCache.set(domain, verdict: .allow)
                    self.logger.info("DAILY BLACKLIST STALE: \(domain) — API says allow")
                    self.forwardToUpstream(query: query, original: parsed, proto: proto)
                }
            }
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

                // Submit to backend for investigation + track for retroactive notification
                PendingInvestigation.shared.add(domain: domain)
                Task.detached(priority: .utility) {
                    _ = await APIClient.checkDomain(domain)
                }
            } else {
                // Brand rule engine warned. Same pattern as the ML silent-submit
                // path: notify the user immediately (yellow — "we're checking"),
                // cache as allow so browser DNS retries within the session don't
                // re-fire the pipeline, submit for background investigation, and
                // forward DNS so the user is not stalled. If the agent later
                // confirms block, the poll loop (see startInvestigationPolling)
                // escalates to a RED notification and inserts into runtime blacklist.
                let layer = "brand_rules"
                telemetry.incrementBrandRuleWarns()
                logger.info("WARNED \(domain) — \(reason)")
                telemetry.recordWarn(domain: domain, layer: layer)
                BlockLog.append(BlockEvent(domain: domain, reason: reason, severity: .yellow))

                sendNotification(domain: domain, reason: reason, severity: .yellow)

                dnsCache.set(domain, verdict: .allow)
                forwardToUpstream(query: query, original: parsed, proto: proto)

                telemetry.incrementAPICalls()
                PendingInvestigation.shared.add(domain: domain)
                Task.detached(priority: .utility) {
                    _ = await APIClient.checkDomain(domain)
                }
            }

        case .allowed:
            dnsCache.set(domain, verdict: .allow)
            forwardToUpstream(query: query, original: parsed, proto: proto)
        }
    }

    // MARK: - Upstream forwarding

    /// Race the query against all upstream DNS servers in parallel. First
    /// response wins; the others get cancelled. If ALL time out within
    /// `upstreamTimeoutSeconds`, we drop the query.
    ///
    /// Why parallel instead of the previous sequential cascade: real-user
    /// diagnostic logs (2026-08-01) showed 15-30 s bursts where the network
    /// path was genuinely dead (all three upstreams timing out for every
    /// domain, across Apple / Microsoft / Meta / Anthropic / etc). Sequential
    /// cascade cost 3 × 2 s = 6 s per query in that state. Parallel race
    /// costs one 800 ms window regardless of upstream count, so the user's
    /// browser gets its "no answer" and can retry ~7.5× faster — critical
    /// because most browsers give up at 5 s.
    ///
    /// Path monitor short-circuit: if iOS reports the network is
    /// unsatisfied (no interface up), drop the query immediately without
    /// wasting the 800 ms — during airplane mode / handoffs this saves
    /// piling up hundreds of pending queries.
    private func forwardToUpstream(query: DNSPacket.Query, original: IPPacket.Parsed, proto: NSNumber) {
        if currentPathStatus == .unsatisfied {
            telemetry.incrementUpstreamAllFailed()
            DiagnosticLog.record(.dnsUpstream, "PATH UNSATISFIED — dropping '\(query.domainName)' immediately (no network interface available)")
            return
        }

        // Race guard: whoever writes the response first wins; others are
        // no-ops. Also cancels all sibling connections so we don't leak
        // sockets waiting on a race we already lost.
        let doneLock = NSLock()
        var done = false
        var connections: [NWConnection] = []
        func claimCompletion() -> Bool {
            doneLock.lock(); defer { doneLock.unlock() }
            if done { return false }
            done = true
            return true
        }
        func cancelAll() {
            for c in connections { c.cancel() }
        }

        // Whole-race timeout. If nothing responds within this window,
        // drop the query and log the failure across all upstreams.
        let timeoutItem = DispatchWorkItem { [weak self] in
            guard let self, claimCompletion() else { return }
            cancelAll()
            self.telemetry.incrementUpstreamAllFailed()
            let servers = self.upstreamDNSList.joined(separator: ", ")
            self.logger.error("All upstreams (\(servers)) timed out on '\(query.domainName)' — network path likely degraded")
            DiagnosticLog.record(.dnsUpstream, "ALL UPSTREAMS TIMEOUT (\(self.upstreamTimeoutSeconds)s) for '\(query.domainName)' — likely network path issue, dropped")
        }
        DispatchQueue.global(qos: .userInteractive).asyncAfter(
            deadline: .now() + upstreamTimeoutSeconds,
            execute: timeoutItem
        )

        for upstream in upstreamDNSList {
            let conn = NWConnection(
                host: NWEndpoint.Host(upstream),
                port: 53,
                using: .udp
            )
            connections.append(conn)

            conn.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    conn.send(content: query.fullDNSData, completion: .contentProcessed { error in
                        if error != nil {
                            // Don't touch the race here — one upstream
                            // erroring on send doesn't mean the others
                            // will. Let this connection drop silently.
                            conn.cancel()
                            return
                        }
                        conn.receive(minimumIncompleteLength: 1, maximumLength: 65535) { data, _, _, _ in
                            guard let data, !data.isEmpty else {
                                conn.cancel()
                                return
                            }
                            if claimCompletion() {
                                timeoutItem.cancel()
                                let ipResp = IPPacket.buildResponse(original: original, dnsResponse: data)
                                self.packetFlow.writePackets([ipResp], withProtocols: [proto])
                                cancelAll()
                            } else {
                                conn.cancel()
                            }
                        }
                    })
                case .failed:
                    // Individual upstream connect failure — cancel it
                    // and let the others race. Only the whole-race
                    // timeout escalates to a "dropped" log.
                    conn.cancel()
                default:
                    break
                }
            }

            conn.start(queue: .global(qos: .userInteractive))
        }
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
            .share-btn {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                background: transparent;
                border: 1px solid #334155;
                color: #E2E8F0;
                font-size: 14px;
                font-weight: 600;
                padding: 12px 22px;
                border-radius: 24px;
                cursor: pointer;
                margin-bottom: 22px;
                font-family: inherit;
            }
            .share-btn svg {
                width: 18px; height: 18px;
                fill: #E2E8F0;
            }
            .sheet-overlay {
                display: none;
                position: fixed;
                inset: 0;
                background: rgba(0,0,0,0.6);
                align-items: flex-end;
                justify-content: center;
                z-index: 10;
            }
            .sheet {
                background: #1E293B;
                width: 100%;
                max-width: 400px;
                border-radius: 16px 16px 0 0;
                padding: 8px 16px 24px;
            }
            .sheet-handle {
                width: 36px;
                height: 4px;
                background: #475569;
                border-radius: 2px;
                margin: 8px auto 16px;
            }
            .sheet-title {
                color: #94A3B8;
                font-size: 13px;
                text-align: center;
                margin-bottom: 12px;
            }
            .sheet-option {
                display: flex;
                align-items: center;
                gap: 14px;
                width: 100%;
                background: none;
                border: none;
                color: #E2E8F0;
                font-size: 16px;
                font-family: inherit;
                padding: 12px 4px;
                cursor: pointer;
                text-align: left;
            }
            .sheet-icon {
                width: 36px; height: 36px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                flex-shrink: 0;
            }
            .sheet-icon svg { width: 18px; height: 18px; fill: #fff; }
            .sheet-cancel {
                width: 100%;
                margin-top: 8px;
                background: #334155;
                border: none;
                color: #E2E8F0;
                font-size: 15px;
                font-weight: 600;
                font-family: inherit;
                padding: 14px;
                border-radius: 12px;
                cursor: pointer;
            }
            .toast {
                position: fixed;
                bottom: 24px;
                left: 50%;
                transform: translateX(-50%) translateY(20px);
                background: #334155;
                color: #E2E8F0;
                padding: 10px 18px;
                border-radius: 20px;
                font-size: 13px;
                opacity: 0;
                pointer-events: none;
                transition: opacity 0.2s, transform 0.2s;
                z-index: 20;
            }
            .toast.show {
                opacity: 1;
                transform: translateX(-50%) translateY(0);
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
                <button class="share-btn" onclick="triggerShare()">
                    <svg viewBox="0 0 24 24"><path d="M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92 1.61 0 2.92-1.31 2.92-2.92s-1.31-2.92-2.92-2.92z"/></svg>
                    Alertar a otros
                </button>
                <p class="footer">Protegido por 24Defend</p>
            </div>

            <div class="sheet-overlay" id="sheet-overlay" onclick="if(event.target===this)closeShareSheet()">
                <div class="sheet">
                    <div class="sheet-handle"></div>
                    <div class="sheet-title">Compartir alerta</div>
                    <button class="sheet-option" onclick="shareViaWhatsapp()">
                        <span class="sheet-icon" style="background:#25D366">
                            <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12c0 1.85.5 3.58 1.36 5.07L2 22l5.07-1.33A9.94 9.94 0 0 0 12 22c5.52 0 10-4.48 10-10S17.52 2 12 2zm.02 18.2c-1.6 0-3.15-.43-4.5-1.24l-.32-.19-3.35.88.9-3.26-.21-.34A8.17 8.17 0 0 1 3.8 12c0-4.53 3.68-8.2 8.2-8.2 4.53 0 8.2 3.68 8.2 8.2s-3.67 8.2-8.18 8.2zm4.5-6.13c-.25-.12-1.47-.72-1.7-.81-.23-.08-.39-.12-.56.13-.17.25-.64.81-.78.97-.14.17-.29.19-.53.06-.25-.12-1.05-.39-2-1.23-.74-.66-1.24-1.47-1.38-1.72-.14-.25-.02-.38.11-.51.11-.11.25-.29.37-.43.12-.14.16-.25.25-.41.08-.17.04-.31-.02-.43-.06-.12-.56-1.36-.77-1.86-.2-.48-.41-.42-.56-.43-.14-.01-.31-.01-.48-.01s-.43.06-.66.31c-.23.25-.86.85-.86 2.06 0 1.22.89 2.4 1.01 2.56.12.17 1.75 2.68 4.25 3.75.59.26 1.06.41 1.42.53.6.19 1.14.16 1.57.1.48-.07 1.47-.6 1.68-1.18.21-.58.21-1.07.14-1.18-.06-.11-.23-.17-.48-.29z"/></svg>
                        </span>
                        WhatsApp
                    </button>
                    <button class="sheet-option" onclick="shareViaSms()">
                        <span class="sheet-icon" style="background:#0A84FF">
                            <svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"/></svg>
                        </span>
                        Mensajes
                    </button>
                    <button class="sheet-option" onclick="shareViaMail()">
                        <span class="sheet-icon" style="background:#64748B">
                            <svg viewBox="0 0 24 24"><path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/></svg>
                        </span>
                        Correo
                    </button>
                    <button class="sheet-option" onclick="copyShareText()">
                        <span class="sheet-icon" style="background:#64748B">
                            <svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
                        </span>
                        Copiar texto
                    </button>
                    <button class="sheet-cancel" onclick="closeShareSheet()">Cancelar</button>
                </div>
            </div>
            <div class="toast" id="toast"></div>

            <script>
            document.getElementById('blocked-domain').textContent = location.hostname;

            function defangedDomain() {
                return location.hostname.split('.').join('[.]');
            }

            function detectedBrand() {
                var brandNames = [
                    ['brou', 'BROU'], ['itau', 'Itau'], ['santander', 'Santander'],
                    ['scotiabank', 'Scotiabank'], ['bbva', 'BBVA'], ['hsbc', 'HSBC'],
                    ['mercadopago', 'MercadoPago'], ['mercadolibre', 'MercadoLibre'],
                    ['oca', 'OCA'], ['prex', 'Prex'], ['antel', 'Antel'],
                    ['movistar', 'Movistar'], ['claro', 'Claro'],
                    ['abitab', 'Abitab'], ['redpagos', 'RedPagos'],
                    ['pedidosya', 'PedidosYa'], ['bps', 'BPS'], ['dgi', 'DGI']
                ];
                var d = location.hostname.toLowerCase();
                for (var i = 0; i < brandNames.length; i++) {
                    if (d.indexOf(brandNames[i][0]) !== -1) return brandNames[i][1];
                }
                return null;
            }

            function buildShareMessage() {
                var brand = detectedBrand();
                var ref = 'https://www.24defend.com/?ref=share' + (brand ? '&brand=' + brand.toLowerCase() : '');
                return '⚠️ Alerta de phishing: ' + defangedDomain() + ' es un sitio fraudulento.\\n\\n24Defend me protegió automáticamente de caer en la estafa.\\n\\nProtegete gratis, descargá la app: ' + ref;
            }

            function triggerShare() {
                // navigator.share requires a secure context (HTTPS/localhost); this
                // block page is served over plain HTTP from the sinkhole intercept,
                // so it's always undefined here. Go straight to the custom sheet.
                openShareSheet();
            }

            function openShareSheet() {
                document.getElementById('sheet-overlay').style.display = 'flex';
            }

            function closeShareSheet() {
                document.getElementById('sheet-overlay').style.display = 'none';
            }

            function shareViaWhatsapp() {
                window.open('https://wa.me/?text=' + encodeURIComponent(buildShareMessage()), '_blank');
                closeShareSheet();
            }

            function shareViaSms() {
                window.location.href = 'sms:?body=' + encodeURIComponent(buildShareMessage());
                closeShareSheet();
            }

            function shareViaMail() {
                window.location.href = 'mailto:?subject=' + encodeURIComponent('Alerta de phishing detectada') + '&body=' + encodeURIComponent(buildShareMessage());
                closeShareSheet();
            }

            function copyShareText() {
                var textarea = document.createElement('textarea');
                textarea.value = buildShareMessage();
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);
                textarea.focus();
                textarea.select();
                try {
                    if (document.execCommand('copy')) {
                        showToast('Texto copiado');
                    } else {
                        showToast('No se pudo copiar');
                    }
                } catch (e) {
                    showToast('No se pudo copiar');
                }
                document.body.removeChild(textarea);
                closeShareSheet();
            }

            function showToast(msg) {
                var toast = document.getElementById('toast');
                toast.textContent = msg;
                toast.classList.add('show');
                setTimeout(function() { toast.classList.remove('show'); }, 2200);
            }
            </script>
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
        // Only notify for domains that impersonate a known brand.
        // Generic blacklist blocks (ad trackers, CDN malware) are silenced.
        // The user only cares about phishing that targets THEIR bank/institution.
        if !force {
            let domainLower = domain.lowercased()
            let hasBrand = BrandRuleEngine.brands.contains { domainLower.contains($0) }
            if !hasBrand {
                logger.info("Suppressed notification for \(domain) — no brand impersonation")
                return
            }
        }

        // Suppress if we're in a "page resource" window (user just visited a whitelisted domain)
        if !force, let lastWL = lastWhitelistHitTime, Date().timeIntervalSince(lastWL) < 3.0 {
            let wlDomain = self.lastWhitelistDomain ?? "unknown"
            logger.info("Suppressed notification for \(domain) — likely page resource of \(wlDomain)")
            return
        }

        // Rate limit: max 1 notification per 5 seconds (skipped for forced red/green escalations)
        if !force, let lastNotif = lastNotificationTime, Date().timeIntervalSince(lastNotif) < 5.0 {
            logger.info("Suppressed notification for \(domain) — rate limited")
            return
        }

        // Cross-session dedup by BASE DOMAIN via BlockLog (persisted). One
        // yellow, one red, one green, one checked per "site" persists across
        // tunnel restarts. `sorteo.brou.hk` and `www.sorteo.brou.hk` share
        // the base `brou.hk` so the user gets ONE of each, not four. Red
        // always allowed once even if yellow already fired (escalation);
        // green/checked only fire if yellow already fired and no red has
        // escalated it.
        let baseKey = BloomFilterStore.extractBaseDomain(domain.lowercased())
        switch severity {
        case .yellow:
            if hasEvent(baseKey: baseKey, severity: .yellow)
                || hasEvent(baseKey: baseKey, severity: .red) {
                logger.info("Suppressed yellow for \(domain) — already notified about \(baseKey)")
                return
            }
            yellowNotificationDomain[baseKey] = domain
        case .red:
            if hasEvent(baseKey: baseKey, severity: .red) {
                logger.info("Suppressed red for \(domain) — already escalated \(baseKey)")
                return
            }
        case .green:
            if hasEvent(baseKey: baseKey, severity: .green)
                || hasEvent(baseKey: baseKey, severity: .red) {
                logger.info("Suppressed green for \(domain) — already resolved \(baseKey)")
                return
            }
        case .checked:
            if hasEvent(baseKey: baseKey, severity: .checked)
                || hasEvent(baseKey: baseKey, severity: .red)
                || hasEvent(baseKey: baseKey, severity: .green) {
                logger.info("Suppressed checked for \(domain) — already resolved \(baseKey)")
                return
            }
        }

        let content = UNMutableNotificationContent()

        switch severity {
        case .red:
            if force {
                // Retroactive escalation — page loaded, then agent confirmed phishing.
                // Deliberately non-prescriptive: we don't know what the user
                // entered (password? DNI? card number? nothing at all?) so
                // "cambiá tu contraseña" is often wrong AND confusing. The
                // institution that was being impersonated has proper channels
                // (block the card, reset the account, monitor activity) —
                // route the user there instead of us guessing.
                content.title = "Sitio fraudulento confirmado"
                content.body = "\(domain) — Si ingresaste datos personales, consultá con la institución pertinente."
            } else {
                // Immediate block — known bad from blacklist / bloom+backend confirm
                content.title = "Sitio de phishing bloqueado"
                content.body = "\(domain) es un sitio malicioso conocido. Acceso bloqueado."
            }
        case .yellow:
            // Immediate suspicion (brand rule / heuristic). Agent runs in background;
            // if it confirms phishing you'll get a follow-up RED notification;
            // if it clears the domain you'll get a follow-up GREEN.
            content.title = "Sitio sospechoso"
            content.body = "\(domain) podría estar imitando una marca. No ingreses datos mientras verificamos."
        case .green:
            // Retroactive all-clear — page was yellow-flagged, agent verified it as a
            // real, legitimate site. Give the user closure so they aren't stuck on the
            // yellow warning forever.
            content.title = "Sitio verificado"
            content.body = "Verificamos \(domain) — es un sitio real. Podés seguir usándolo con normalidad."
        case .checked:
            // Agent investigated but couldn't conclude either way. Close the
            // loop honestly — this is neither "safe" nor "dangerous", just
            // "we looked and couldn't tell."
            content.title = "Revisión terminada"
            content.body = "Terminamos de revisar \(domain). No encontramos señales claras de fraude, pero tampoco pudimos confirmar del todo que sea legítimo. Andá con cuidado si vas a ingresar datos."
        }

        content.sound = .default
        content.categoryIdentifier = "BLOCK_ALERT"
        // Structured payload so the app-side handler doesn't have to parse
        // the localized body string (which broke for the green case — the
        // "Verificamos X — es un sitio real..." body didn't split on the
        // parser's separators and the whole body ended up in the domain box).
        content.userInfo = [
            "domain": domain,
            "severity": severity.rawValue,
            "reason": reason,
        ]

        // For a green or checked notification, reuse the yellow's identifier
        // so iOS REPLACES the yellow in Notification Center instead of
        // stacking a second entry. For red/yellow, use the current domain
        // string.
        let identifierDomain: String = {
            if (severity == .green || severity == .checked),
               let yellowDomain = yellowNotificationDomain[baseKey] {
                return yellowDomain
            }
            return domain
        }()

        let request = UNNotificationRequest(
            identifier: "24defend-\(identifierDomain)",
            content: content,
            trigger: nil  // deliver immediately
        )

        lastNotificationTime = Date()

        UNUserNotificationCenter.current().add(request) { error in
            if let error {
                self.logger.error("Notification error: \(error.localizedDescription)")
                DiagnosticLog.record(.notification, "ERROR firing \(severity.rawValue) for \(domain): \(error.localizedDescription)")
            } else {
                DiagnosticLog.record(.notification, "FIRED \(severity.rawValue) for \(domain) — reason: \(reason)")
            }
        }
    }

    /// Persistent replacement for the old in-memory {yellow,red,green,checked}
    /// Notified sets. Answers "did we fire severity X for base domain Y at
    /// any point in the recent past?" — sourced from BlockLog which is
    /// stored in the app group's UserDefaults and survives tunnel restarts.
    ///
    /// Windows:
    ///   - Upper (48h): we don't want a 2-week-old yellow to prevent a fresh
    ///     yellow that would legitimately re-warn the user.
    ///   - Lower (5s grace): the tunnel's convention is BlockLog.append THEN
    ///     sendNotification; without a grace window the just-appended entry
    ///     dedups its own notification (bug introduced 2026-07-28, all
    ///     notifications silently suppressed since then). 5s is well past
    ///     the sub-millisecond gap between append and this lookup, and much
    ///     shorter than any user-perceivable dedup window.
    private func hasEvent(baseKey: String, severity: EventSeverity) -> Bool {
        let now = Date()
        let cutoff = now.addingTimeInterval(-48 * 3600)
        let graceCutoff = now.addingTimeInterval(-5.0)
        for event in BlockLog.load() {
            if event.timestamp < cutoff { break } // BlockLog is stored newest-first
            if event.timestamp > graceCutoff { continue } // Skip self-write from a just-appended entry
            if event.severity != severity { continue }
            let eventBase = BloomFilterStore.extractBaseDomain(event.domain.lowercased())
            if eventBase == baseKey { return true }
        }
        return false
    }
}
