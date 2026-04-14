import Foundation

// MARK: - DNS wire-format parsing and response construction

enum DNSPacket {

    struct Query {
        let transactionID: UInt16
        let domainName: String
        let questionType: UInt16   // 1=A, 28=AAAA
        let questionClass: UInt16  // 1=IN
        let rawQuestion: Data      // QNAME + QTYPE + QCLASS bytes
        let fullDNSData: Data      // original DNS payload to forward upstream
    }

    static func parseQuery(from data: Data) -> Query? {
        guard data.count >= 12 else { return nil }
        let txID = UInt16(data[0]) << 8 | UInt16(data[1])

        guard let (domain, endOfName) = parseName(from: data, offset: 12) else { return nil }
        guard endOfName + 4 <= data.count else { return nil }

        let qtype  = UInt16(data[endOfName]) << 8 | UInt16(data[endOfName + 1])
        let qclass = UInt16(data[endOfName + 2]) << 8 | UInt16(data[endOfName + 3])
        let questionEnd = endOfName + 4

        return Query(
            transactionID: txID,
            domainName: domain,
            questionType: qtype,
            questionClass: qclass,
            rawQuestion: data[12..<questionEnd],
            fullDNSData: data
        )
    }

    /// Build a DNS response that resolves to 0.0.0.0 / :: (sinkhole)
    static func buildBlockResponse(for query: Query) -> Data {
        var r = Data()

        // Header
        r.append(UInt8(query.transactionID >> 8))
        r.append(UInt8(query.transactionID & 0xFF))
        r.append(contentsOf: [0x81, 0x80] as [UInt8]) // QR=1, AA=0, RCODE=0

        r.append(contentsOf: [0x00, 0x01] as [UInt8]) // QDCOUNT=1

        let isA    = query.questionType == 1
        let isAAAA = query.questionType == 28
        r.append(contentsOf: (isA || isAAAA) ? [0x00, 0x01] as [UInt8] : [0x00, 0x00] as [UInt8]) // ANCOUNT
        r.append(contentsOf: [0x00, 0x00, 0x00, 0x00] as [UInt8]) // NSCOUNT, ARCOUNT

        // Question (echo back)
        r.append(query.rawQuestion)

        // Answer
        if isA {
            r.append(contentsOf: [0xC0, 0x0C] as [UInt8])             // name pointer → offset 12
            r.append(contentsOf: [0x00, 0x01] as [UInt8])             // TYPE A
            r.append(contentsOf: [0x00, 0x01] as [UInt8])             // CLASS IN
            r.append(contentsOf: [0x00, 0x00, 0x00, 0x3C] as [UInt8]) // TTL 60s
            r.append(contentsOf: [0x00, 0x04] as [UInt8])             // RDLENGTH 4
            r.append(contentsOf: [0x7F, 0x00, 0x00, 0x01] as [UInt8]) // 127.0.0.1
        } else if isAAAA {
            r.append(contentsOf: [0xC0, 0x0C] as [UInt8])
            r.append(contentsOf: [0x00, 0x1C] as [UInt8])             // TYPE AAAA
            r.append(contentsOf: [0x00, 0x01] as [UInt8])
            r.append(contentsOf: [0x00, 0x00, 0x00, 0x3C] as [UInt8])
            r.append(contentsOf: [0x00, 0x10] as [UInt8])             // RDLENGTH 16
            r.append(contentsOf: [UInt8](repeating: 0, count: 16))    // ::0
        }

        return r
    }

    // MARK: - Name parsing

    private static func parseName(from data: Data, offset: Int) -> (String, Int)? {
        var labels: [String] = []
        var pos = offset

        while pos < data.count {
            let len = Int(data[pos])
            if len == 0 { pos += 1; break }
            if len & 0xC0 == 0xC0 { pos += 2; break } // compression pointer — rare in queries
            pos += 1
            guard pos + len <= data.count else { return nil }
            guard let label = String(data: data[pos..<(pos + len)], encoding: .utf8) else { return nil }
            labels.append(label)
            pos += len
        }

        return (labels.joined(separator: "."), pos)
    }
}

// MARK: - IPv4 + UDP packet helpers

enum IPPacket {

    struct Parsed {
        let sourceIP: Data    // 4 bytes
        let destIP: Data      // 4 bytes
        let sourcePort: UInt16
        let destPort: UInt16
        let dnsPayload: Data
    }

    /// Parse an IPv4/UDP packet and extract the DNS payload.
    static func parse(_ packet: Data) -> Parsed? {
        guard packet.count >= 28 else { return nil }              // IP(20) + UDP(8) minimum
        guard packet[0] >> 4 == 4 else { return nil }             // IPv4
        let ihl = Int(packet[0] & 0x0F) * 4
        guard ihl >= 20, packet.count >= ihl + 8 else { return nil }
        guard packet[9] == 17 else { return nil }                 // UDP

        let srcPort = UInt16(packet[ihl]) << 8 | UInt16(packet[ihl + 1])
        let dstPort = UInt16(packet[ihl + 2]) << 8 | UInt16(packet[ihl + 3])

        let dnsStart = ihl + 8
        guard dnsStart < packet.count else { return nil }

        return Parsed(
            sourceIP: Data(packet[12..<16]),
            destIP: Data(packet[16..<20]),
            sourcePort: srcPort,
            destPort: dstPort,
            dnsPayload: Data(packet[dnsStart...])
        )
    }

    /// Wrap a DNS response in a UDP/IPv4 packet (swapping src/dst from the original).
    static func buildResponse(original: Parsed, dnsResponse: Data) -> Data {
        let udpLen = 8 + dnsResponse.count
        let totalLen = 20 + udpLen
        var p = Data(count: totalLen)

        // — IP header (20 bytes) —
        p[0] = 0x45                                             // v4, IHL=5
        p[2] = UInt8(totalLen >> 8); p[3] = UInt8(totalLen & 0xFF)
        p[6] = 0x40                                             // DF
        p[8] = 64                                               // TTL
        p[9] = 17                                               // UDP
        p.replaceSubrange(12..<16, with: original.destIP)       // src ← original dst
        p.replaceSubrange(16..<20, with: original.sourceIP)     // dst ← original src
        let cksum = ipChecksum(Data(p[0..<20]))
        p[10] = UInt8(cksum >> 8); p[11] = UInt8(cksum & 0xFF)

        // — UDP header (8 bytes) —
        let u = 20
        p[u]     = UInt8(original.destPort >> 8)
        p[u + 1] = UInt8(original.destPort & 0xFF)
        p[u + 2] = UInt8(original.sourcePort >> 8)
        p[u + 3] = UInt8(original.sourcePort & 0xFF)
        p[u + 4] = UInt8(udpLen >> 8)
        p[u + 5] = UInt8(udpLen & 0xFF)
        // UDP checksum = 0 (optional over IPv4)

        // — DNS payload —
        p.replaceSubrange((u + 8)..<totalLen, with: dnsResponse)
        return p
    }

    private static func ipChecksum(_ header: Data) -> UInt16 {
        var sum: UInt32 = 0
        for i in stride(from: 0, to: header.count - 1, by: 2) {
            sum += UInt32(header[i]) << 8 | UInt32(header[i + 1])
        }
        if header.count % 2 != 0 {
            sum += UInt32(header[header.count - 1]) << 8
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return ~UInt16(sum & 0xFFFF)
    }
}
