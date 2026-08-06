import SwiftUI
import WebKit

/// Renders the actual Privacy Policy by loading `www/privacy-es.html`
/// (bundled as an app resource via `project.yml`) in a WKWebView, instead
/// of maintaining a second hand-copied Swift version. A prior version of
/// this screen inlined the policy text directly in Swift and it drifted
/// out of sync with the website within the same PR that added it — two
/// documents both claiming to be "the privacy policy" is an App Store
/// 5.1.1 compliance risk. Loading the same HTML file here and on
/// www.24defend.com makes that drift structurally impossible.
struct PrivacyPolicyView: View {
    var body: some View {
        PrivacyWebView()
            .navigationTitle("Política de privacidad")
            .navigationBarTitleDisplayMode(.inline)
    }
}

private struct PrivacyWebView: UIViewRepresentable {
    func makeUIView(context: Context) -> WKWebView {
        WKWebView()
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        guard let url = Bundle.main.url(forResource: "privacy-es", withExtension: "html") else {
            return
        }
        // allowingReadAccessTo the containing directory (not just the file)
        // so the page's own "English" language-switcher link, which points
        // to the sibling privacy-en.html bundled alongside it, resolves
        // locally instead of 404ing inside the WebView.
        webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
    }
}
