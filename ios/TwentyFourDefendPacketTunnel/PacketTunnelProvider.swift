import NetworkExtension
import Network
import UserNotifications
import os

class PacketTunnelProvider: NEPacketTunnelProvider {

    private let logger = Logger(subsystem: "com.24defend.app.packet-tunnel", category: "dns")

    // Upstream DNS servers, tried in order with failover. If 1.1.1.1 is
    // blocked / unreachable / silently drops packets (observed on some
    // corporate WiFi, hotel networks, and certain LATAM carriers at peak),
    // we cascade to 8.8.8.8 and then 9.9.9.9. Without this failover the
    // user loses internet completely on any network that blocks 1.1.1.1 —
    // reported by the founding team as a P0 business blocker on 2026-07-31.
    private let upstreamDNSList = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    // Hard timeout per upstream. UDP is connectionless, so a silently
    // dropped packet leaves the receive callback pending forever without
    // this timer. 2s is generous for a working upstream (< 30ms typical)
    // and cascades to the next server before the user's browser gives up
    // (~5s default resolver timeout in most stacks).
    private let upstreamTimeoutSeconds: TimeInterval = 2.0
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
            } else {
                self.logger.info("MEMORY: \(availableMB, format: .fixed(precision: 2))MB available")
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

        refreshTimer?.cancel()
        refreshTimer = nil
        dailyBlacklistTimer?.cancel()
        dailyBlacklistTimer = nil
        investigationTimer?.cancel()
        investigationTimer = nil
        memoryTimer?.cancel()
        memoryTimer = nil
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

    private func forwardToUpstream(query: DNSPacket.Query, original: IPPacket.Parsed, proto: NSNumber) {
        forwardToUpstream(query: query, original: original, proto: proto, upstreamIndex: 0)
    }

    /// Send `query` to `upstreamDNSList[upstreamIndex]` with a hard timeout;
    /// on any failure (connection failed, send error, timeout, empty
    /// response) cascade to the next upstream. If all upstreams fail,
    /// increment telemetry and drop — the client will retry on its own.
    ///
    /// Race guard: exactly ONE of {receive, send-error, .failed state,
    /// timeout} must trigger the cascade. We use an atomic flag flipped
    /// under NSLock to ensure that.
    private func forwardToUpstream(
        query: DNSPacket.Query,
        original: IPPacket.Parsed,
        proto: NSNumber,
        upstreamIndex: Int
    ) {
        guard upstreamIndex < upstreamDNSList.count else {
            telemetry.incrementUpstreamAllFailed()
            logger.error("All upstream DNS servers failed — dropping query. This is the user-facing 'no internet' symptom.")
            return
        }
        let upstream = upstreamDNSList[upstreamIndex]
        let conn = NWConnection(
            host: NWEndpoint.Host(upstream),
            port: 53,
            using: .udp
        )

        // Race guard: whichever callback fires first "wins" and gets to
        // either write the response OR cascade to the next upstream.
        let doneLock = NSLock()
        var done = false
        func claimCompletion() -> Bool {
            doneLock.lock(); defer { doneLock.unlock() }
            if done { return false }
            done = true
            return true
        }

        // Timeout — cascades to next upstream on expiry.
        let timeoutItem = DispatchWorkItem { [weak self] in
            guard let self, claimCompletion() else { return }
            conn.cancel()
            self.logger.warning("DNS upstream \(upstream) timed out after \(self.upstreamTimeoutSeconds)s — trying next")
            self.forwardToUpstream(
                query: query, original: original, proto: proto,
                upstreamIndex: upstreamIndex + 1
            )
        }
        DispatchQueue.global(qos: .userInteractive).asyncAfter(
            deadline: .now() + upstreamTimeoutSeconds,
            execute: timeoutItem
        )

        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                conn.send(content: query.fullDNSData, completion: .contentProcessed { error in
                    if let error {
                        if claimCompletion() {
                            timeoutItem.cancel()
                            conn.cancel()
                            self.logger.warning("DNS send to \(upstream) errored (\(error.localizedDescription)) — trying next")
                            self.forwardToUpstream(
                                query: query, original: original, proto: proto,
                                upstreamIndex: upstreamIndex + 1
                            )
                        }
                        return
                    }
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 65535) { data, _, _, _ in
                        // Two failure modes here: (a) `data` is nil or empty
                        // — server hung up without replying → cascade;
                        // (b) got a valid DNS response → write back.
                        if let data, !data.isEmpty {
                            if claimCompletion() {
                                timeoutItem.cancel()
                                let ipResp = IPPacket.buildResponse(original: original, dnsResponse: data)
                                self.packetFlow.writePackets([ipResp], withProtocols: [proto])
                                conn.cancel()
                            }
                        } else {
                            if claimCompletion() {
                                timeoutItem.cancel()
                                conn.cancel()
                                self.logger.warning("DNS upstream \(upstream) returned empty response — trying next")
                                self.forwardToUpstream(
                                    query: query, original: original, proto: proto,
                                    upstreamIndex: upstreamIndex + 1
                                )
                            }
                        }
                    }
                })
            case .failed(let error):
                if claimCompletion() {
                    timeoutItem.cancel()
                    self.logger.warning("DNS upstream \(upstream) connection failed (\(error.localizedDescription)) — trying next")
                    self.forwardToUpstream(
                        query: query, original: original, proto: proto,
                        upstreamIndex: upstreamIndex + 1
                    )
                }
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
            }
        }
    }

    /// Persistent replacement for the old in-memory {yellow,red,green,checked}
    /// Notified sets. Answers "did we fire severity X for base domain Y at
    /// any point in the recent past?" — sourced from BlockLog which is
    /// stored in the app group's UserDefaults and survives tunnel restarts.
    ///
    /// Time window (48h) is intentional: we don't want a 2-week-old yellow to
    /// prevent a fresh yellow that would legitimately re-warn the user.
    private func hasEvent(baseKey: String, severity: EventSeverity) -> Bool {
        let cutoff = Date().addingTimeInterval(-48 * 3600)
        for event in BlockLog.load() {
            if event.timestamp < cutoff { break } // BlockLog is stored newest-first
            if event.severity != severity { continue }
            let eventBase = BloomFilterStore.extractBaseDomain(event.domain.lowercased())
            if eventBase == baseKey { return true }
        }
        return false
    }
}
