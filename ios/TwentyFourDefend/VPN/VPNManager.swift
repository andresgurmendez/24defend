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
                status = "No se pudo activar. Intenta de nuevo."
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
                m.localizedDescription = "24Defend – Protección de enlaces"
                let proto = NETunnelProviderProtocol()
                proto.providerBundleIdentifier = "com.24defend.app.packet-tunnel"
                proto.serverAddress = "24Defend DNS Filter"
                m.protocolConfiguration = proto
                manager = m
            }
            refreshStatus()
        } catch {
            status = "No se pudo cargar la protección"
        }
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
