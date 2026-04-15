import Foundation

public struct CheckResponse: Codable {
    public let domain: String
    public let verdict: String   // "block", "warn", "allow"
    public let reason: String
    public let confidence: Double
    public let source: String    // "blacklist", "whitelist", "cache", "agent"
}

public final class APIClient {

    // Change this to your ngrok URL or production API
    static let baseURL = "https://skyward-bulbiferous-delois.ngrok-free.dev"

    // Use a session that connects directly, bypassing our VPN tunnel
    private static let session: URLSession = {
        let config = URLSessionConfiguration.default
        config.connectionProxyDictionary = [:]  // bypass proxy/VPN
        config.timeoutIntervalForRequest = 5
        config.timeoutIntervalForResource = 8
        return URLSession(configuration: config)
    }()

    public static func checkDomain(_ domain: String) async -> CheckResponse? {
        guard let url = URL(string: "\(baseURL)/check") else { return nil }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("true", forHTTPHeaderField: "ngrok-skip-browser-warning")

        let body = ["domain": domain]
        request.httpBody = try? JSONEncoder().encode(body)

        do {
            let (data, response) = try await session.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200 else { return nil }
            return try JSONDecoder().decode(CheckResponse.self, from: data)
        } catch {
            return nil
        }
    }
}
