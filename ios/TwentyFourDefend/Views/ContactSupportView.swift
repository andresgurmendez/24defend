import SwiftUI

struct ContactSupportView: View {
    private let websiteURL = URL(string: "https://www.24defend.com/")!
    private let supportEmail = "dev@24defend.com"

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

                    Divider().padding(.leading, 56)

                    Link(destination: URL(string: "mailto:\(supportEmail)")!) {
                        contactRow(
                            icon: "envelope.fill",
                            title: "Correo de soporte",
                            value: supportEmail
                        )
                    }
                }
                .background(.ultraThinMaterial)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .padding(.horizontal)
            }
        }
        .navigationTitle("Contacto y soporte")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func contactRow(icon: String, title: String, value: String) -> some View {
        HStack(spacing: 16) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(Color.accentColor)
                .frame(width: 24)

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
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .contentShape(Rectangle())
    }
}
