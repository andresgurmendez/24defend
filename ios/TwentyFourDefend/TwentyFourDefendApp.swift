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
                        severity: blockAlert.severity
                    )
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
    @Published var domain = ""
    @Published var reason = ""
    @Published var severity: EventSeverity = .red
}

class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    var blockAlert = BlockAlertState()

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
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

        DispatchQueue.main.async {
            self.blockAlert.domain = content.body.components(separatedBy: " is ").first
                ?? content.body.components(separatedBy: " — ").first
                ?? content.body
            self.blockAlert.reason = content.body
            self.blockAlert.severity = content.title.contains("Phishing") ? .red : .yellow
            self.blockAlert.isPresented = true
        }

        completionHandler()
    }
}
