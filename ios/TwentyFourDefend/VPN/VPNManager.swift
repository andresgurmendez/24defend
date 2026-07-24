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
            status = "Protección no disponible"
            return
        }

        do {
            if isConnected {
                // User-initiated disconnect. We must also disable on-demand,
                // otherwise iOS would immediately re-establish the tunnel on
                // the next network activity and the user could never actually
                // turn the protection off.
                manager.isOnDemandEnabled = false
                try await manager.saveToPreferences()
                manager.connection.stopVPNTunnel()
            } else {
                // User-initiated connect. Ensure profile is enabled, on-demand
                // rules are installed, and on-demand is on before starting.
                manager.isEnabled = true
                configureOnDemand(on: manager)
                manager.isOnDemandEnabled = true
                try await manager.saveToPreferences()
                // Reload after save so the system picks up the latest config
                try await manager.loadFromPreferences()
                try manager.connection.startVPNTunnel()
            }
        } catch {
            status = "No se pudo activar. Intenta de nuevo."
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
                m.localizedDescription = "24Defend – Protección de enlaces"
                let proto = NETunnelProviderProtocol()
                proto.providerBundleIdentifier = "com.24defend.app.packet-tunnel"
                proto.serverAddress = "24Defend DNS Filter"
                // disconnectOnSleep defaults to false, but pin it explicitly —
                // any future iOS version that changed the default would silently
                // start killing our tunnel during device sleep.
                proto.disconnectOnSleep = false
                m.protocolConfiguration = proto
                manager = m
            }
            refreshStatus()
        } catch {
            status = "No se pudo cargar la protección"
        }
    }

    /// Install / refresh the on-demand rules on the tunnel manager.
    ///
    /// Without an on-demand rule, if iOS kills the extension (memory pressure /
    /// jetsam, sleep, network change, or an extension crash) the tunnel stays
    /// down until the user manually taps "Activar" again — which is exactly
    /// the "VPN suddenly disconnected" bug users have been reporting.
    ///
    /// `NEOnDemandRuleConnect` with `interfaceTypeMatch = .any` tells iOS to
    /// re-establish the tunnel on any network activity, regardless of what
    /// took it down. This is the standard pattern used by every serious DNS
    /// filter app (AdGuard, NextDNS, 1.1.1.1).
    ///
    /// Note the user's explicit off toggle is honored via `isOnDemandEnabled
    /// = false` — see `toggle()`.
    private func configureOnDemand(on manager: NETunnelProviderManager) {
        let connect = NEOnDemandRuleConnect()
        connect.interfaceTypeMatch = .any
        manager.onDemandRules = [connect]
    }

    private func refreshStatus() {
        guard let manager else { return }
        let s = manager.connection.status
        isConnected = (s == .connected)

        switch s {
        case .invalid:        status = "Configuración pendiente"
        case .disconnected:   status = "Sin protección"
        case .connecting:     status = "Activando protección…"
        case .connected:      status = "Protegido"
        case .reasserting:    status = "Restableciendo protección…"
        case .disconnecting:  status = "Desactivando protección…"
        @unknown default:     status = "Estado desconocido"
        }
    }
}
