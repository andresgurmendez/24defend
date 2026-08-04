import SwiftUI

/// Placeholder screen reached from the hamburger menu. Content pending.
struct TermsView: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "doc.text")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("Términos y condiciones")
                .font(.headline)
            Text("Muy pronto vas a encontrar acá los términos y condiciones de uso de 24Defend.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Términos y condiciones")
        .navigationBarTitleDisplayMode(.inline)
    }
}
