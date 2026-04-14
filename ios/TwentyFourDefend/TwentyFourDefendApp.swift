import SwiftUI
import UserNotifications

@main
struct TwentyFourDefendApp: App {
    @StateObject private var vpnManager = VPNManager()

    var body: some Scene {
        WindowGroup {
            DashboardView()
                .environmentObject(vpnManager)
                .onAppear { requestNotificationPermission() }
        }
    }

    private func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }
}
