import SwiftUI

struct BlockLogView: View {
    @State private var events: [BlockEvent] = []
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                if events.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "shield")
                            .font(.system(size: 48))
                            .foregroundStyle(.secondary)
                        Text("Sin alertas todavía")
                            .font(.headline)
                        Text("Aquí aparecerán los sitios bloqueados o sospechosos")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(events) { event in
                        HStack(spacing: 10) {
                            Circle()
                                .fill(event.severity == .red ? Color.red : Color.yellow)
                                .frame(width: 10, height: 10)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(event.domain)
                                    .font(.subheadline.monospaced())
                                Text(event.reason)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Text(event.timestamp, style: .relative)
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                }
            }
            .navigationTitle("Alertas")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Listo") { dismiss() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Limpiar") {
                        BlockLog.clear()
                        events = []
                    }
                }
            }
            .onAppear { events = BlockLog.load() }
        }
    }
}
