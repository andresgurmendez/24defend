import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var blockLog: [BlockEvent] = []
    @State private var showLog = false
    @State private var showDisclosure = false

    // Persists across app launches. Once the user has explicitly accepted the
    // VPN data-collection disclosure once, we don't show the sheet again.
    // Required by Apple Guideline 5.4 — the user must see a plain-language
    // description of what data the VPN handles BEFORE the OS VPN prompt fires.
    @AppStorage("vpn_disclosure_accepted_v1") private var disclosureAccepted = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 32) {
                Spacer()

                // Shield
                Image(systemName: vpn.isConnected ? "checkmark.shield.fill" : "shield.slash")
                    .font(.system(size: 80))
                    .foregroundStyle(vpn.isConnected ? .green : .secondary)
                    .animation(.easeInOut, value: vpn.isConnected)

                Text(vpn.status)
                    .font(.title2.weight(.semibold))

                // Toggle button. First-time activation gates on the 5.4 disclosure sheet.
                Button {
                    if !vpn.isConnected && !disclosureAccepted {
                        showDisclosure = true
                    } else {
                        Task { await vpn.toggle() }
                    }
                } label: {
                    Text(vpn.isConnected ? "Desactivar protección" : "Activar protección")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(vpn.isConnected ? Color.red.opacity(0.85) : Color.green)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                }
                .padding(.horizontal, 40)

                Spacer()

                // Recent blocks summary
                if !blockLog.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Alertas recientes")
                            .font(.headline)

                        ForEach(blockLog.prefix(3)) { event in
                            HStack {
                                Image(systemName: iconFor(event.severity))
                                    .foregroundStyle(colorFor(event.severity))
                                VStack(alignment: .leading) {
                                    Text(event.domain)
                                        .font(.subheadline.monospaced())
                                        .lineLimit(1)
                                    Text(event.reason)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                            }
                            .padding(10)
                            .background(.ultraThinMaterial)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                        }
                    }
                    .padding(.horizontal)
                }

                Spacer()
            }
            .navigationTitle("24Defend")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showLog = true } label: {
                        Image(systemName: "list.bullet.rectangle")
                    }
                }
            }
            .sheet(isPresented: $showLog) {
                BlockLogView()
            }
            .sheet(isPresented: $showDisclosure) {
                VPNDisclosureView {
                    disclosureAccepted = true
                    Task { await vpn.toggle() }
                }
            }
            .onAppear { blockLog = BlockLog.load() }
            .refreshable { blockLog = BlockLog.load() }
        }
    }

    private func iconFor(_ severity: EventSeverity) -> String {
        switch severity {
        case .red: return "xmark.shield.fill"
        case .yellow: return "exclamationmark.triangle.fill"
        case .green: return "checkmark.shield.fill"
        }
    }

    private func colorFor(_ severity: EventSeverity) -> Color {
        switch severity {
        case .red: return .red
        case .yellow: return .yellow
        case .green: return .green
        }
    }
}
