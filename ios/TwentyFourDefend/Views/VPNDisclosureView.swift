import SwiftUI

/// One-time disclosure sheet shown before the user grants the VPN configuration
/// on their first tap of "Activar protección". Explicitly required by Apple's
/// Guideline 5.4 (VPN apps) — the user must see a plain-language description
/// of what data the app handles BEFORE they accept the VPN connection.
struct VPNDisclosureView: View {
    /// Called when the user taps "Aceptar y activar". Parent triggers the VPN
    /// connection AFTER the sheet dismisses.
    var onAccept: () -> Void

    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text("Antes de activar la protección")
                        .font(.title2.weight(.bold))
                        .padding(.top, 8)

                    Text("24Defend usa una configuración de VPN local en tu dispositivo para revisar consultas DNS y bloquear sitios de fraude. Antes de activarla queremos que sepas exactamente qué pasa con tus datos.")
                        .font(.body)
                        .foregroundStyle(.primary)

                    section(
                        icon: "checkmark.seal.fill",
                        color: .green,
                        title: "Lo que se queda en tu dispositivo",
                        bullets: [
                            "Tu navegación normal nunca sale de tu iPhone.",
                            "Los bloqueos y la lista de alertas se guardan solo localmente.",
                            "No hay cuenta, no hay login, no usamos tu Apple ID."
                        ]
                    )

                    section(
                        icon: "info.circle.fill",
                        color: .blue,
                        title: "Lo que sí enviamos a nuestro servidor",
                        bullets: [
                            "Cuando un sitio parece sospechoso, mandamos solo el nombre del dominio para clasificarlo con IA (~0,2% de las consultas).",
                            "Un identificador anónimo del dispositivo (UUID), sin vincular a vos ni a tu Apple ID.",
                            "Contadores agregados (cuántas consultas, cuántos bloqueos) para mejorar el producto."
                        ]
                    )

                    section(
                        icon: "hand.raised.fill",
                        color: .red,
                        title: "Lo que no hacemos",
                        bullets: [
                            "No compartimos datos con anunciantes ni redes sociales.",
                            "No usamos IDFA ni herramientas de rastreo.",
                            "No vendemos tu información a nadie.",
                            "No accedemos a tus contactos, fotos, ubicación ni micrófono."
                        ]
                    )

                    // Privacy policy link — prominent, per Apple's 5.4 requirement.
                    Button {
                        if let url = URL(string: "https://www.24defend.com/privacy-es.html") {
                            openURL(url)
                        }
                    } label: {
                        HStack {
                            Image(systemName: "doc.text.fill")
                            Text("Ver política de privacidad completa")
                            Spacer()
                            Image(systemName: "arrow.up.right.square")
                        }
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(.blue)
                        .padding()
                        .background(Color.blue.opacity(0.08))
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                    .padding(.top, 4)

                    // Accept button — clear affirmative action per 5.4.
                    Button {
                        onAccept()
                        dismiss()
                    } label: {
                        Text("Aceptar y activar protección")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(Color.green)
                            .foregroundStyle(.white)
                            .clipShape(RoundedRectangle(cornerRadius: 14))
                    }

                    Button("Cancelar") { dismiss() }
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity)
                        .padding(.bottom, 8)
                }
                .padding(.horizontal, 24)
                .padding(.top, 8)
            }
        }
        .interactiveDismissDisabled()
    }

    @ViewBuilder
    private func section(icon: String, color: Color, title: String, bullets: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .foregroundStyle(color)
                Text(title)
                    .font(.headline)
            }
            ForEach(bullets, id: \.self) { bullet in
                HStack(alignment: .top, spacing: 8) {
                    Text("•").foregroundStyle(color)
                    Text(bullet)
                        .font(.subheadline)
                        .foregroundStyle(.primary)
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.gray.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}
