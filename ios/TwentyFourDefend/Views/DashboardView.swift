import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var blockLog: [BlockEvent] = []
    @State private var showLog = false

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

                // Toggle button
                Button {
                    Task { await vpn.toggle() }
                } label: {
                    Text(vpn.isConnected ? "Disable Protection" : "Enable Protection")
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
                        Text("Recent alerts")
                            .font(.headline)

                        ForEach(blockLog.prefix(3)) { event in
                            HStack {
                                Image(systemName: event.severity == .red ? "xmark.shield.fill" : "exclamationmark.triangle.fill")
                                    .foregroundStyle(event.severity == .red ? .red : .yellow)
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
            .onAppear { blockLog = BlockLog.load() }
            .refreshable { blockLog = BlockLog.load() }
        }
    }
}
