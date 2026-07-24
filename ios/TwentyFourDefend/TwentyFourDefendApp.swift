import SwiftUI
import UserNotifications

@main
struct TwentyFourDefendApp: App {
    @StateObject private var vpnManager = VPNManager()
    @StateObject private var blockAlert = BlockAlertState()
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        WindowGroup {
            DashboardView()
                .environmentObject(vpnManager)
                .environmentObject(blockAlert)
                .sheet(isPresented: $blockAlert.isPresented) {
                    BlockDetailView(
                        domain: blockAlert.domain,
                        reason: blockAlert.reason,
                        severity: blockAlert.severity,
                        autoShare: blockAlert.shouldShare
                    )
                    .onDisappear { blockAlert.shouldShare = false }
                }
                .onAppear {
                    requestNotificationPermission()
                    appDelegate.blockAlert = blockAlert
                }
        }
    }

    private func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }
}

class BlockAlertState: ObservableObject {
    @Published var isPresented = false
    @Published var shouldShare = false
    @Published var domain = ""
    @Published var reason = ""
    @Published var severity: EventSeverity = .red
}

class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    var blockAlert = BlockAlertState()

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        registerNotificationActions()
        return true
    }

    private func registerNotificationActions() {
        let shareAction = UNNotificationAction(
            identifier: "SHARE_ACTION",
            title: "Compartir",
            options: [.foreground]
        )
        let detailAction = UNNotificationAction(
            identifier: "DETAIL_ACTION",
            title: "Ver detalles",
            options: [.foreground]
        )
        let category = UNNotificationCategory(
            identifier: "BLOCK_ALERT",
            actions: [shareAction, detailAction],
            intentIdentifiers: [],
            options: []
        )
        UNUserNotificationCenter.current().setNotificationCategories([category])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        let content = response.notification.request.content

        // Prefer structured userInfo (set by PacketTunnelProvider.sendNotification).
        // Fall back to body-parsing for any pre-existing notifications that
        // predated the userInfo migration (rare — session-scoped state).
        let domain: String = {
            if let d = content.userInfo["domain"] as? String, !d.isEmpty { return d }
            return content.body.components(separatedBy: " is ").first
                ?? content.body.components(separatedBy: " — ").first
                ?? content.body
        }()
        let severity: EventSeverity = {
            if let raw = content.userInfo["severity"] as? String,
               let sev = EventSeverity(rawValue: raw) { return sev }
            if content.title.contains("verificado") { return .green }
            if content.title.contains("Phishing") || content.title.contains("fraudulento") { return .red }
            return .yellow
        }()

        DispatchQueue.main.async {
            self.blockAlert.domain = domain
            self.blockAlert.reason = content.body
            self.blockAlert.severity = severity

            if response.actionIdentifier == "SHARE_ACTION" {
                // Open app with share sheet directly
                self.blockAlert.shouldShare = true
            }
            self.blockAlert.isPresented = true
        }

        completionHandler()
    }
}
