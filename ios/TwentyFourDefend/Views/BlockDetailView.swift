import SwiftUI

struct BlockDetailView: View {
    let domain: String
    let reason: String
    let severity: EventSeverity
    var autoShare: Bool = false
    @Environment(\.dismiss) private var dismiss
    @State private var showShareSheet = false

    /// Extract brand name from the domain for the share message
    private var detectedBrand: String? {
        let d = domain.lowercased()
        let brandNames: [(keyword: String, display: String)] = [
            ("brou", "BROU"), ("itau", "Itau"), ("santander", "Santander"),
            ("scotiabank", "Scotiabank"), ("bbva", "BBVA"), ("hsbc", "HSBC"),
            ("mercadopago", "MercadoPago"), ("mercadolibre", "MercadoLibre"),
            ("oca", "OCA"), ("prex", "Prex"), ("antel", "Antel"),
            ("movistar", "Movistar"), ("claro", "Claro"),
            ("abitab", "Abitab"), ("redpagos", "RedPagos"),
            ("pedidosya", "PedidosYa"), ("bps", "BPS"), ("dgi", "DGI"),
        ]
        return brandNames.first { d.contains($0.keyword) }?.display
    }

    /// Make domain non-clickable by inserting spaces around dots
    private var safeDomain: String {
        domain.replacingOccurrences(of: ".", with: " . ")
    }

    private var shareMessage: String {
        if let brand = detectedBrand {
            return """
            24Defend bloqueo un intento de fraude en mi celular. El enlace \(safeDomain) se hacia pasar por \(brand) para robar datos de acceso.

            Si recibis un mensaje con este tipo de enlaces, no lo abras. Podes proteger tu celular con 24Defend:
            https://www.24defend.com/?ref=share&brand=\(brand.lowercased())
            """
        } else {
            return """
            24Defend detecto y bloqueo un enlace fraudulento en mi celular: \(safeDomain)

            Si recibis un mensaje con enlaces sospechosos, no los abras. Podes proteger tu celular con 24Defend:
            https://www.24defend.com/?ref=share
            """
        }
    }

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
                 : "Este dominio es similar a un sitio oficial verificado. Proceda con precaucion.")
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

            // Brand impersonation callout
            if let brand = detectedBrand {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text("Este sitio se hace pasar por \(brand)")
                        .font(.subheadline.weight(.medium))
                }
                .padding(12)
                .frame(maxWidth: .infinity)
                .background(Color.orange.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .padding(.horizontal, 40)
            }

            Spacer()

            Text("Protegido por 24Defend")
                .font(.caption2)
                .foregroundStyle(.tertiary)

            // Share button — primary CTA
            Button {
                showShareSheet = true
            } label: {
                HStack {
                    Image(systemName: "square.and.arrow.up")
                    Text("Compartir con amigos y familia")
                }
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.blue)
                .foregroundStyle(.white)
                .clipShape(RoundedRectangle(cornerRadius: 14))
            }
            .padding(.horizontal, 40)

            Button("Cerrar") { dismiss() }
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .padding(.bottom, 20)
        }
        .sheet(isPresented: $showShareSheet) {
            ShareSheet(items: [shareMessage])
        }
        .onAppear {
            if autoShare {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                    showShareSheet = true
                }
            }
        }
    }
}

/// UIKit share sheet wrapper for SwiftUI
struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
