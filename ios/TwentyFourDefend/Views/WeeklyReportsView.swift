import SwiftUI

/// Placeholder screen reached from the hamburger menu. Content pending.
struct WeeklyReportsView: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "chart.line.uptrend.xyaxis")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("Reportes semanales de phishing")
                .font(.headline)
            Text("Muy pronto vas a encontrar acá un resumen semanal de la actividad de phishing detectada.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Reportes semanales")
        .navigationBarTitleDisplayMode(.inline)
    }
}
