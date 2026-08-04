import SwiftUI
import Charts

struct WeeklyReportsView: View {
    private enum QuickFilter: String, CaseIterable, Identifiable {
        case today = "Hoy"
        case week = "7 días"
        case month = "Este mes"
        case custom = "Personalizado"
        var id: String { rawValue }
    }

    @State private var filter: QuickFilter = .week
    @State private var customStart = Calendar.current.date(byAdding: .day, value: -7, to: Date()) ?? Date()
    @State private var customEnd = Date()
    @State private var showingCustomRange = false
    @State private var hasAnyHistory = true

    var body: some View {
        Group {
            if !hasAnyHistory {
                emptyState
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 24) {
                        filterChips

                        Text(headerText)
                            .font(.title3.weight(.semibold))
                            .fixedSize(horizontal: false, vertical: true)

                        statCards

                        if dailyCounts.count > 1 {
                            chart
                        }
                    }
                    .padding()
                }
            }
        }
        .navigationTitle("Reportes semanales")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { hasAnyHistory = !BlockLog.load().isEmpty }
        .sheet(isPresented: $showingCustomRange) {
            customRangeSheet
        }
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "chart.line.uptrend.xyaxis")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("Sin actividad todavía")
                .font(.headline)
            Text("Cuando detectemos sitios sospechosos o bloqueados, acá vas a ver un resumen.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Filter chips

    private var filterChips: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(QuickFilter.allCases) { option in
                    Button {
                        if option == .custom {
                            showingCustomRange = true
                        } else {
                            filter = option
                        }
                    } label: {
                        Text(option.rawValue)
                            .font(.subheadline.weight(.medium))
                            .padding(.horizontal, 14)
                            .padding(.vertical, 8)
                            .background(filter == option ? Color.accentColor : Color(.secondarySystemBackground))
                            .foregroundStyle(filter == option ? .white : .primary)
                            .clipShape(Capsule())
                    }
                }
            }
        }
    }

    private var customRangeSheet: some View {
        NavigationStack {
            Form {
                DatePicker("Desde", selection: $customStart, in: ...customEnd, displayedComponents: .date)
                DatePicker("Hasta", selection: $customEnd, in: customStart...Date(), displayedComponents: .date)
            }
            .navigationTitle("Rango personalizado")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Aplicar") {
                        filter = .custom
                        showingCustomRange = false
                    }
                }
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancelar") { showingCustomRange = false }
                }
            }
        }
    }

    // MARK: - Stats

    private var range: (from: Date, to: Date) {
        let calendar = Calendar.current
        let now = Date()
        switch filter {
        case .today:
            return (calendar.startOfDay(for: now), now)
        case .week:
            return (calendar.date(byAdding: .day, value: -7, to: now) ?? now, now)
        case .month:
            let start = calendar.date(from: calendar.dateComponents([.year, .month], from: now)) ?? now
            return (start, now)
        case .custom:
            let end = calendar.date(byAdding: .day, value: 1, to: calendar.startOfDay(for: customEnd)) ?? customEnd
            return (calendar.startOfDay(for: customStart), end)
        }
    }

    private var filteredEvents: [BlockEvent] {
        BlockLog.events(from: range.from, to: range.to)
    }

    private var blockedCount: Int { filteredEvents.filter { $0.severity == .red }.count }
    private var suspiciousCount: Int { filteredEvents.filter { $0.severity == .yellow || $0.severity == .checked }.count }
    private var clearedCount: Int { filteredEvents.filter { $0.severity == .green }.count }

    private var periodPhrase: String {
        switch filter {
        case .today: return "hoy"
        case .week: return "en los últimos 7 días"
        case .month: return "este mes"
        case .custom: return "en el período seleccionado"
        }
    }

    private var headerText: String {
        let total = filteredEvents.count
        guard total > 0 else {
            return "Sin actividad sospechosa \(periodPhrase)."
        }
        let noun = total == 1 ? "intento" : "intentos"
        return "Te protegimos de \(total) \(noun) de sitios falsos \(periodPhrase)."
    }

    private var statCards: some View {
        HStack(spacing: 12) {
            statCard(count: blockedCount, label: "Bloqueados", icon: "xmark.shield.fill", color: .red)
            statCard(count: suspiciousCount, label: "Sospechosos", icon: "exclamationmark.triangle.fill", color: .yellow)
            statCard(count: clearedCount, label: "Verificados", icon: "checkmark.shield.fill", color: .green)
        }
    }

    private func statCard(count: Int, label: String, icon: String, color: Color) -> some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .font(.title3)
            Text("\(count)")
                .font(.title2.weight(.bold))
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 14)
        .background(.ultraThinMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - Chart

    private var dailyCounts: [(day: Date, count: Int)] {
        let calendar = Calendar.current
        let grouped = Dictionary(grouping: filteredEvents) { calendar.startOfDay(for: $0.timestamp) }
        return grouped.map { (day: $0.key, count: $0.value.count) }.sorted { $0.day < $1.day }
    }

    private var chart: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Actividad por día")
                .font(.headline)
            Chart(dailyCounts, id: \.day) { item in
                BarMark(
                    x: .value("Día", item.day, unit: .day),
                    y: .value("Eventos", item.count)
                )
                .foregroundStyle(Color.accentColor)
            }
            .frame(height: 160)
        }
    }
}
