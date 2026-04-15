import SwiftUI

struct BlockDetailView: View {
    let domain: String
    let reason: String
    let severity: EventSeverity
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            // Shield icon
            ZStack {
                Circle()
                    .fill(severity == .red ? Color.red.opacity(0.15) : Color.yellow.opacity(0.15))
                    .frame(width: 100, height: 100)
                Circle()
                    .stroke(severity == .red ? Color.red : Color.yellow, lineWidth: 3)
                    .frame(width: 100, height: 100)
                Image(systemName: severity == .red ? "shield.fill" : "exclamationmark.triangle.fill")
                    .font(.system(size: 44))
                    .foregroundStyle(severity == .red ? .red : .yellow)
            }

            // Title
            Text(severity == .red ? "Sitio bloqueado" : "Sitio sospechoso")
                .font(.title.weight(.bold))
                .foregroundStyle(severity == .red ? .red : .yellow)

            // Description
            Text(severity == .red
                 ? "24Defend ha bloqueado el acceso a este sitio porque ha sido identificado como fraudulento o de phishing."
                 : "Este dominio es similar a un sitio oficial verificado. Proceda con precaución.")
                .font(.body)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 32)

            // Domain
            Text(domain)
                .font(.subheadline.monospaced())
                .padding(14)
                .frame(maxWidth: .infinity)
                .background(Color(.systemGray6))
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .padding(.horizontal, 40)

            // Reason
            if !reason.isEmpty {
                Text(reason)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 40)
            }

            Spacer()

            Text("Protegido por 24Defend")
                .font(.caption2)
                .foregroundStyle(.tertiary)

            Button("Cerrar") { dismiss() }
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color(.systemGray5))
                .clipShape(RoundedRectangle(cornerRadius: 14))
                .padding(.horizontal, 40)
                .padding(.bottom, 20)
        }
    }
}
