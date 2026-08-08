import SwiftUI
import WebKit
import UIKit

/// Renders the actual Privacy Policy by loading `www/privacy-es.html`
/// (bundled as an app resource via `project.yml`) in a WKWebView, instead
/// of maintaining a second hand-copied Swift version. A prior version of
/// this screen inlined the policy text directly in Swift and it drifted
/// out of sync with the website within the same PR that added it — two
/// documents both claiming to be "the privacy policy" is an App Store
/// 5.1.1 compliance risk. Loading the same HTML file here and on
/// www.24defend.com makes that drift structurally impossible.
struct PrivacyPolicyView: View {
    private var resourceURL: URL? {
        Bundle.main.url(forResource: "privacy-es", withExtension: "html")
    }

    var body: some View {
        Group {
            if let url = resourceURL {
                PrivacyWebView(url: url)
            } else {
                unavailable
            }
        }
        .navigationTitle("Política de privacidad")
        .navigationBarTitleDisplayMode(.inline)
    }

    // If the bundled HTML is ever missing (renamed, dropped from Copy
    // Bundle Resources, project.yml misconfiguration), fail loud in DEBUG
    // and show a real fallback instead of a blank white screen — this
    // screen exists for App Store 5.1.1 compliance, so silently showing
    // nothing is worse than an obvious error.
    private var unavailable: some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("No pudimos cargar la política de privacidad.")
                .font(.headline)
                .multilineTextAlignment(.center)
            Text("Visitá www.24defend.com/privacy-es.html")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .padding(32)
        .onAppear {
            assertionFailure("privacy-es.html missing from app bundle")
        }
    }
}

private struct PrivacyWebView: UIViewRepresentable {
    let url: URL

    func makeUIView(context: Context) -> WKWebView {
        let webView = WKWebView()
        webView.navigationDelegate = context.coordinator
        // allowingReadAccessTo the containing directory (not just the file)
        // so the page's own "English" language-switcher link, which points
        // to the sibling privacy-en.html bundled alongside it, resolves
        // locally instead of 404ing inside the WebView.
        webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        // Intentionally empty. SwiftUI calls this for reasons unrelated to
        // this view (trait/environment changes propagating down the
        // NavigationStack, Dynamic Type, dark-mode toggle) — reloading the
        // file here on every call wiped the user's scroll position and
        // re-hit disk I/O for no reason. The page is loaded exactly once,
        // in makeUIView.
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    /// Intercepts in-page navigation so links inside the policy don't
    /// navigate the modal itself. `mailto:`/`https:` links hand off to
    /// UIApplication (Mail / Safari); the initial `file:` load of the
    /// bundled HTML is allowed to proceed normally.
    final class Coordinator: NSObject, WKNavigationDelegate {
        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            guard let url = navigationAction.request.url, url.scheme != "file" else {
                decisionHandler(.allow)
                return
            }
            decisionHandler(.cancel)
            UIApplication.shared.open(url)
        }
    }
}
