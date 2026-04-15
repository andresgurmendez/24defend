import Foundation

/// BK-tree for efficient fuzzy string matching using Levenshtein distance.
/// Query time: O(log n) average vs O(n) linear scan.
/// Uses the triangle inequality: |d(x,z) - d(y,z)| <= d(x,y) <= d(x,z) + d(y,z)
public final class BKTree {

    private final class Node {
        let value: String
        var children: [Int: Node] = [:]  // key = edit distance to parent

        init(_ value: String) {
            self.value = value
        }
    }

    private var root: Node?
    private(set) var count = 0

    public init() {}

    /// Build a BK-tree from an array of strings.
    public convenience init(values: [String]) {
        self.init()
        for v in values {
            insert(v)
        }
    }

    /// Insert a string into the tree.
    public func insert(_ value: String) {
        let v = value.lowercased()
        guard let root else {
            self.root = Node(v)
            count = 1
            return
        }

        var current = root
        while true {
            let dist = Self.levenshtein(v, current.value)
            if dist == 0 { return } // duplicate
            if let child = current.children[dist] {
                current = child
            } else {
                current.children[dist] = Node(v)
                count += 1
                return
            }
        }
    }

    /// Find all strings within `maxDistance` of the query.
    /// Returns array of (value, distance) pairs, sorted by distance.
    public func search(_ query: String, maxDistance: Int) -> [(value: String, distance: Int)] {
        guard let root else { return [] }

        var results: [(String, Int)] = []
        var stack: [Node] = [root]

        let q = query.lowercased()

        while let node = stack.popLast() {
            let dist = Self.levenshtein(q, node.value)

            if dist <= maxDistance {
                results.append((node.value, dist))
            }

            // Triangle inequality pruning: only visit children with key in
            // range [dist - maxDistance, dist + maxDistance]
            let lower = dist - maxDistance
            let upper = dist + maxDistance

            for (childDist, child) in node.children {
                if childDist >= lower && childDist <= upper {
                    stack.append(child)
                }
            }
        }

        return results.sorted { $0.1 < $1.1 }
    }

    /// Check if any string in the tree is within `maxDistance` of the query.
    /// More efficient than search() when you only need a boolean answer.
    public func hasMatch(_ query: String, maxDistance: Int) -> Bool {
        guard let root else { return false }

        var stack: [Node] = [root]
        let q = query.lowercased()

        while let node = stack.popLast() {
            let dist = Self.levenshtein(q, node.value)
            if dist <= maxDistance && dist > 0 {
                return true
            }

            let lower = dist - maxDistance
            let upper = dist + maxDistance
            for (childDist, child) in node.children {
                if childDist >= lower && childDist <= upper {
                    stack.append(child)
                }
            }
        }

        return false
    }

    // MARK: - Levenshtein (optimized single-row)

    static func levenshtein(_ s1: String, _ s2: String) -> Int {
        let a = Array(s1)
        let b = Array(s2)
        let m = a.count, n = b.count
        if m == 0 { return n }
        if n == 0 { return m }

        var prev = Array(0...n)
        var curr = Array(repeating: 0, count: n + 1)

        for i in 1...m {
            curr[0] = i
            for j in 1...n {
                let cost = a[i - 1] == b[j - 1] ? 0 : 1
                curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
            }
            swap(&prev, &curr)
        }
        return prev[n]
    }
}
