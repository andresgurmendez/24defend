import SwiftUI
import UIKit

/// Hidden diagnostic panel. Activated via 7 rapid taps on the "24Defend"
/// title in the Dashboard (see DashboardView). Not linked from any visible
/// UI element — this is for testers and internal debugging of the
/// "no internet" / "notification never arrived" class of report.
struct DiagnosticView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var entries: [DiagnosticLog.Entry] = []
    @State private var selectedCategory: DiagnosticLog.Category? = nil
    @State private var copiedFlash = false

    // Poll every 2s so the view stays fresh while the tester reproduces
    // the bug. Cheap because load() is a single UserDefaults read.
    private let refreshTimer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    private var filtered: [DiagnosticLog.Entry] {
        guard let cat = selectedCategory else { return entries }
        return entries.filter { $0.category == cat }
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Category filter chips
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        chip(label: "Todos", selected: selectedCategory == nil) { selectedCategory = nil }
                        chip(label: "DNS", selected: selectedCategory == .dnsUpstream) { selectedCategory = .dnsUpstream }
                        chip(label: "Túnel", selected: selectedCategory == .tunnel) { selectedCategory = .tunnel }
                        chip(label: "Notif", selected: selectedCategory == .notification) { selectedCategory = .notification }
                        chip(label: "API", selected: selectedCategory == .api) { selectedCategory = .api }
                        chip(label: "Mem", selected: selectedCategory == .memory) { selectedCategory = .memory }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                }
                .background(Color.gray.opacity(0.08))

                if filtered.isEmpty {
                    Spacer()
                    VStack(spacing: 10) {
                        Image(systemName: "text.magnifyingglass")
                            .font(.system(size: 40))
                            .foregroundStyle(.secondary)
                        Text("Sin entradas")
                            .font(.headline)
                        Text("Reproducí el problema con la protección activa y volvé a esta vista.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 40)
                    }
                    Spacer()
                } else {
                    List(filtered) { entry in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 6) {
                                Text(entry.category.rawValue.uppercased())
                                    .font(.caption2.weight(.semibold))
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(color(for: entry.category).opacity(0.2))
                                    .foregroundStyle(color(for: entry.category))
                                    .clipShape(RoundedRectangle(cornerRadius: 4))
                                Text(entry.timestamp, style: .time)
                                    .font(.caption2.monospaced())
                                    .foregroundStyle(.tertiary)
                                Text(entry.timestamp, style: .date)
                                    .font(.caption2.monospaced())
                                    .foregroundStyle(.tertiary)
                            }
                            Text(entry.message)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                        }
                        .padding(.vertical, 2)
                        .swipeActions(edge: .trailing) {
                            Button {
                                UIPasteboard.general.string = formatOne(entry)
                            } label: {
                                Label("Copiar", systemImage: "doc.on.doc")
                            }
                            .tint(.blue)
                        }
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("Diagnóstico")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cerrar") { dismiss() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button {
                            UIPasteboard.general.string = formatAll(filtered)
                            copiedFlash = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                                copiedFlash = false
                            }
                        } label: {
                            Label("Copiar todo", systemImage: "doc.on.doc.fill")
                        }
                        Button(role: .destructive) {
                            DiagnosticLog.clear()
                            entries = []
                        } label: {
                            Label("Limpiar", systemImage: "trash")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
            .overlay(alignment: .top) {
                if copiedFlash {
                    Text("Copiado")
                        .font(.subheadline.weight(.semibold))
                        .padding(.horizontal, 14)
                        .padding(.vertical, 8)
                        .background(.thinMaterial, in: Capsule())
                        .padding(.top, 8)
                        .transition(.opacity)
                }
            }
            .animation(.easeInOut(duration: 0.2), value: copiedFlash)
        }
        .onAppear { entries = DiagnosticLog.load() }
        .onReceive(refreshTimer) { _ in entries = DiagnosticLog.load() }
    }

    private func color(for category: DiagnosticLog.Category) -> Color {
        switch category {
        case .dnsUpstream: return .red
        case .tunnel: return .purple
        case .notification: return .orange
        case .api: return .blue
        case .memory: return .green
        case .other: return .gray
        }
    }

    private func chip(label: String, selected: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(label)
                .font(.caption.weight(.medium))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(selected ? Color.blue : Color.gray.opacity(0.15))
                .foregroundStyle(selected ? .white : .primary)
                .clipShape(Capsule())
        }
    }

    private func formatOne(_ e: DiagnosticLog.Entry) -> String {
        let iso = ISO8601DateFormatter().string(from: e.timestamp)
        return "\(iso) [\(e.category.rawValue)] \(e.message)"
    }

    private func formatAll(_ es: [DiagnosticLog.Entry]) -> String {
        let header = """
        24Defend diagnostic log — \(ISO8601DateFormatter().string(from: Date()))
        entries: \(es.count)
        =============================================

        """
        return header + es.map(formatOne).joined(separator: "\n")
    }
}
