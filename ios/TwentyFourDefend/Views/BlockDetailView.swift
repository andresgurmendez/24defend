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
            24Defend bloqueó un intento de fraude en mi celular. El enlace \(safeDomain) se hacía pasar por \(brand) para robar datos.

            Si recibís un mensaje con este tipo de enlaces, no lo abras. Podés proteger tu celular con 24Defend:
            https://www.24defend.com/?ref=share&brand=\(brand.lowercased())
            """
        } else {
            return """
            24Defend detectó y bloqueó un enlace fraudulento en mi celular: \(safeDomain)

            Si recibís un mensaje con enlaces sospechosos, no los abras. Podés proteger tu celular con 24Defend:
            https://www.24defend.com/?ref=share
            """
        }
    }

    private var themeColor: Color {
        switch severity {
        case .red: return .red
        case .yellow: return .yellow
        case .green: return .green
        }
    }

    private var iconName: String {
        switch severity {
        case .red: return "shield.fill"
        case .yellow: return "exclamationmark.triangle.fill"
        case .green: return "checkmark.shield.fill"
        }
    }

    private var titleText: String {
        switch severity {
        case .red: return "Sitio bloqueado"
        case .yellow: return "Sitio sospechoso"
        case .green: return "Sitio verificado"
        }
    }

    private var descriptionText: String {
        switch severity {
        case .red: return "24Defend bloqueó el acceso a este sitio porque fue identificado como fraudulento."
        case .yellow: return "Este dominio se parece a un sitio oficial. Andá con cuidado y no ingreses datos."
        case .green: return "Verificamos que este sitio es real. Podés seguir usándolo con normalidad."
        }
    }

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            // Shield icon
            ZStack {
                Circle()
                    .fill(themeColor.opacity(0.15))
                    .frame(width: 100, height: 100)
                Circle()
                    .stroke(themeColor, lineWidth: 3)
                    .frame(width: 100, height: 100)
                Image(systemName: iconName)
                    .font(.system(size: 44))
                    .foregroundStyle(themeColor)
            }

            // Title
            Text(titleText)
                .font(.title.weight(.bold))
                .foregroundStyle(themeColor)

            // Description
            Text(descriptionText)
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

            // Brand impersonation callout — only for red/yellow warnings.
            // On a GREEN verified sheet this would contradict the "sitio real"
            // message we just showed the user.
            if severity != .green, let brand = detectedBrand {
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

            // Share button — only for confirmed blocks, not suspicious/warn
            if severity == .red {
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
            }

            Button("Cerrar") { dismiss() }
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .padding(.bottom, 20)
        }
        .sheet(isPresented: $showShareSheet) {
            ShareSheet(items: [shareMessage])
        }
        .onAppear {
            if autoShare && severity == .red {
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
