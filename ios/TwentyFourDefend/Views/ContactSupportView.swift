import SwiftUI
import UIKit

struct ContactSupportView: View {
    private let websiteURL = URL(string: "https://www.24defend.com/")!
    private let supportEmail = "dev@24defend.com"
    private var mailURL: URL {
        URL(string: "mailto:\(supportEmail)?subject=24Defend%20-%20consulta%20soporte")!
    }

    @State private var showCopiedAlert = false

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                VStack(spacing: 12) {
                    Image(systemName: "envelope")
                        .font(.system(size: 48))
                        .foregroundStyle(.secondary)
                    Text("Contacto y soporte")
                        .font(.headline)
                    Text("¿Tenés dudas o encontraste un problema? Escribinos.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
                .padding(.top, 24)

                VStack(spacing: 0) {
                    Link(destination: websiteURL) {
                        contactRow(
                            icon: "globe",
                            title: "Sitio web",
                            value: "www.24defend.com"
                        )
                    }
                    .accessibilityHint("Abre 24defend.com en Safari")

                    Divider().padding(.leading, 56)

                    Button {
                        openMail()
                    } label: {
                        contactRow(
                            icon: "envelope.fill",
                            title: "Correo de soporte",
                            value: supportEmail
                        )
                    }
                    .accessibilityHint("Abre el correo para escribir a \(supportEmail)")
                }
                .background(.ultraThinMaterial)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .padding(.horizontal)
            }
        }
        .navigationTitle("Contacto y soporte")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Correo copiado al portapapeles", isPresented: $showCopiedAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("No encontramos una app de correo instalada. Copiamos \(supportEmail) para que lo pegues donde prefieras.")
        }
    }

    /// No mail client registered for `mailto:` (removed Mail app, MDM'd
    /// device, webmail-only setup) silently no-ops `UIApplication.open` —
    /// fall back to clipboard so the user isn't left with a dead tap.
    private func openMail() {
        if UIApplication.shared.canOpenURL(mailURL) {
            UIApplication.shared.open(mailURL)
        } else {
            UIPasteboard.general.string = supportEmail
            showCopiedAlert = true
        }
    }

    private func contactRow(icon: String, title: String, value: String) -> some View {
        HStack(spacing: 16) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(Color.accentColor)
                .frame(width: 24)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline)
                    .foregroundStyle(.primary)
                Text(value)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Image(systemName: "chevron.right")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.tertiary)
                .accessibilityHidden(true)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}
