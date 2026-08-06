import SwiftUI

/// Placeholder screen reached from the hamburger menu. Content pending.
struct ContactSupportView: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "envelope")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("Contacto y soporte")
                .font(.headline)
            Text("Muy pronto vas a poder contactarnos desde acá.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Contacto y soporte")
        .navigationBarTitleDisplayMode(.inline)
    }
}
