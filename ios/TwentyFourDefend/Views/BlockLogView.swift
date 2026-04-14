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
                        Text("No alerts yet")
                            .font(.headline)
                        Text("Blocked and suspicious domains will appear here")
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
            .navigationTitle("Alert Log")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Clear") {
                        BlockLog.clear()
                        events = []
                    }
                }
            }
            .onAppear { events = BlockLog.load() }
        }
    }
}
