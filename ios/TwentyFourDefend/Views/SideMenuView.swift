import SwiftUI

/// Destinations reachable from the hamburger menu.
enum MenuDestination: String, Identifiable, Hashable {
    case weeklyReports
    case terms
    case contact

    var id: String { rawValue }
}

/// Slide-in hamburger menu shown over the dashboard. Purely presentational —
/// navigation is driven by the `onSelect` callback so the parent NavigationStack
/// owns pushing the destination.
struct SideMenuView: View {
    var onSelect: (MenuDestination) -> Void

    @State private var showShareSheet = false

    private let shareMessage = """
    Estoy usando 24Defend para protegerme de sitios de fraude y phishing en el celular. Te lo recomiendo:
    https://www.24defend.com/?ref=share_menu
    """

    private struct Row: Identifiable {
        let id = UUID()
        let destination: MenuDestination
        let icon: String
        let iconColor: Color
        let iconBackground: Color
        let title: String
    }

    private let rows: [Row] = [
        Row(destination: .weeklyReports,
            icon: "chart.line.uptrend.xyaxis",
            iconColor: .green,
            iconBackground: Color.green.opacity(0.15),
            title: "Reportes semanales de phishing"),
        Row(destination: .terms,
            icon: "doc.text",
            iconColor: .purple,
            iconBackground: Color.purple.opacity(0.15),
            title: "Términos y condiciones"),
        Row(destination: .contact,
            icon: "envelope.fill",
            iconColor: .blue,
            iconBackground: Color.blue.opacity(0.15),
            title: "Contacto y soporte"),
    ]

    var body: some View {
        VStack(spacing: 0) {
            header
                .padding(.horizontal, 20)
                .padding(.top, 16)
                .padding(.bottom, 20)

            Divider()

            VStack(spacing: 4) {
                ForEach(rows) { row in
                    Button {
                        onSelect(row.destination)
                    } label: {
                        HStack(spacing: 14) {
                            Image(systemName: row.icon)
                                .font(.system(size: 16, weight: .semibold))
                                .foregroundStyle(row.iconColor)
                                .frame(width: 40, height: 40)
                                .background(row.iconBackground)
                                .clipShape(RoundedRectangle(cornerRadius: 10))

                            Text(row.title)
                                .font(.body.weight(.medium))
                                .foregroundStyle(.primary)
                                .multilineTextAlignment(.leading)

                            Spacer()

                            Image(systemName: "chevron.right")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.tertiary)
                        }
                        .padding(.horizontal, 20)
                        .padding(.vertical, 12)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.top, 8)

            Spacer()

            Divider()

            Button {
                showShareSheet = true
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: "square.and.arrow.up")
                    Text("Compartir la app")
                }
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.blue)
                .foregroundStyle(.white)
                .clipShape(RoundedRectangle(cornerRadius: 14))
            }
            .padding(.horizontal, 20)
            .padding(.top, 16)
            .padding(.bottom, 12)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        // ignoresSafeArea is applied only to the background, not to this
        // VStack itself, so the white fill bleeds edge-to-edge behind the
        // status bar / home indicator while the header and button still sit
        // safely inside the readable area instead of overlapping system UI.
        .background(Color(.systemBackground).ignoresSafeArea())
        .sheet(isPresented: $showShareSheet) {
            ShareSheet(items: [shareMessage])
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Text("24")
                .font(.headline.weight(.bold))
                .foregroundStyle(.white)
                .frame(width: 44, height: 44)
                .background(Color.black)
                .clipShape(RoundedRectangle(cornerRadius: 12))

            VStack(alignment: .leading, spacing: 2) {
                Text("24Defend")
                    .font(.title3.weight(.bold))
                Text("Protección anti-phishing")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
    }
}
