import NetworkExtension
import SwiftUI

@MainActor
final class VPNManager: ObservableObject {
    @Published var isConnected = false
    @Published var status: String = "Loading…"

    private var manager: NETunnelProviderManager?
    private var statusObserver: Any?

    init() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in self?.refreshStatus() }
        }
        Task { await load() }
    }

    // MARK: - Public

    func toggle() async {
        guard let manager else {
            status = "Manager not loaded"
            return
        }

        if isConnected {
            manager.connection.stopVPNTunnel()
        } else {
            do {
                manager.isEnabled = true
                try await manager.saveToPreferences()
                // Reload after save so the system picks up the latest config
                try await manager.loadFromPreferences()
                try manager.connection.startVPNTunnel()
            } catch {
                status = "Error: \(error.localizedDescription)"
            }
        }
    }

    // MARK: - Private

    private func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            if let existing = managers.first {
                manager = existing
            } else {
                let m = NETunnelProviderManager()
                m.localizedDescription = "24Defend Link Protection"
                let proto = NETunnelProviderProtocol()
                proto.providerBundleIdentifier = "com.24defend.app.packet-tunnel"
                proto.serverAddress = "24Defend DNS Filter"
                m.protocolConfiguration = proto
                manager = m
            }
            refreshStatus()
        } catch {
            status = "Load error: \(error.localizedDescription)"
        }
    }

    private func refreshStatus() {
        guard let manager else { return }
        let s = manager.connection.status
        isConnected = (s == .connected)

        switch s {
        case .invalid:        status = "Not configured"
        case .disconnected:   status = "Disconnected"
        case .connecting:     status = "Connecting…"
        case .connected:      status = "Protected"
        case .reasserting:    status = "Reconnecting…"
        case .disconnecting:  status = "Disconnecting…"
        @unknown default:     status = "Unknown"
        }
    }
}
