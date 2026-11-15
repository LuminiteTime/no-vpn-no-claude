import Foundation

/// Pure decision logic: no I/O, fully unit-tested.
enum Policy {
    /// Anthropic's own address space (claude.ai, api.anthropic.com, claude.com, ... all live here).
    /// Anthropic, PBC allocations per ARIN whois.
    static let anthropicNetworks = ["160.79.104.0/21", "2607:6bc0::/32"]

    /// Resolved periodically and added to the block table, in case anything moves outside the ranges above.
    /// ponytail: status.claude.com skipped — it sits on shared Atlassian/CloudFront IPs, blocking it hits other sites.
    static let claudeHosts = [
        "claude.ai", "www.claude.ai", "assets.claude.ai", "downloads.claude.ai",
        "claude.com", "www.claude.com", "platform.claude.com", "code.claude.com",
        "anthropic.com", "www.anthropic.com", "api.anthropic.com", "console.anthropic.com",
        "statsig.anthropic.com", "mcp-proxy.anthropic.com",
        "claudeusercontent.com", "claude.site", "clau.de",
    ]

    /// An address inside Anthropic's range; the route to it tells which interface Claude traffic takes.
    static let probeAddress = "160.79.104.10"

    static let geoRecheckInterval: TimeInterval = 120   // ipinfo.io free tier is ~1000 req/day
    static let geoRetryInterval: TimeInterval = 10
    /// Geo services flaky but the network is provably the same one we verified → keep allowing this long.
    static let unchangedNetworkGrace: TimeInterval = 600

    static func decide(geo: GeoResult, network: NetworkSnapshot, lastVerified: Verification?,
                       allowed: Set<String>, now: Date) -> Verdict {
        switch geo {
        case .country(let code, _) where allowed.contains(code):
            return .allow(interface: network.interface, country: code)
        case .country(let code, _):
            return .block(reason: "exit country is \(code)")
        case .unavailable:
            guard let verified = lastVerified, verified.isStillValid(for: network, now: now) else {
                return .block(reason: "country check failed")
            }
            return .allow(interface: verified.network.interface, country: verified.country)
        }
    }

    /// An allow verdict is bound to the network it was verified on; any change revokes it at once.
    static func mustRevoke(_ verdict: Verdict, current: NetworkSnapshot, lastVerified: Verification?) -> Bool {
        guard verdict.isAllowed else { return false }
        return lastVerified?.network != current
    }

    static func pfRules(for verdict: Verdict, addresses: [String]) -> String {
        var rules = ["table <claude> const { \(addresses.joined(separator: ", ")) }"]
        if case .allow(let interface, _) = verdict, isValidInterfaceName(interface) {
            rules.append("pass out quick on \(interface) to <claude>")
        }
        rules.append("block return out quick to <claude>")
        return rules.joined(separator: "\n") + "\n"
    }

    /// "lv, de" → ["LV", "DE"]; anything that is not an ISO 3166 code lands in `unknown`.
    static func parseCountries(_ text: String, known: Set<String> = isoCountryCodes) -> CountryList {
        var codes: [String] = []
        var unknown: [String] = []
        for token in text.uppercased().split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init) {
            if !known.contains(token) { unknown.append(token) } else if !codes.contains(token) { codes.append(token) }
        }
        return CountryList(codes: codes, unknown: unknown)
    }

    static let isoCountryCodes = Set(Locale.Region.isoRegions.map(\.identifier).filter { $0.count == 2 })

    // MARK: - Parsing command output

    /// Geo answer → country (+ timezone when the provider reports one).
    /// Accepts `LV\n`, ipinfo.io `{"country":"LV","timezone":...}` and ifconfig.co `{"country_iso":"LV","time_zone":...}`.
    static func parseGeo(_ body: String) -> GeoResult {
        guard let object = jsonObject(body) else { return countryCode(body).map { .country($0) } ?? .unavailable }
        let country = (object["country_iso"] as? String) ?? (object["country"] as? String)
        guard let code = country.flatMap(countryCode) else { return .unavailable }
        return .country(code, timezone: (object["timezone"] as? String) ?? (object["time_zone"] as? String))
    }

    /// The zone to present for an exit country. The provider's zone wins only if it really belongs
    /// to that country; otherwise the country's main zone (first in zone.tab). nil = unknown country.
    static func timezone(country: String, reported: String?, zones: [String: [String]]) -> String? {
        guard let candidates = zones[country] else { return nil }
        if let reported, candidates.contains(reported) { return reported }
        return candidates.first
    }

    /// `/usr/share/zoneinfo/zone.tab` → country code to zones, main zone first.
    static func parseZoneTab(_ text: String) -> [String: [String]] {
        var zones: [String: [String]] = [:]
        for line in text.split(separator: "\n") where !line.hasPrefix("#") {
            let columns = line.split(separator: "\t")
            guard columns.count >= 3 else { continue }
            zones[String(columns[0]), default: []].append(String(columns[2]))
        }
        return zones
    }

    private static func countryCode(_ text: String) -> String? {
        let code = text.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard code.count == 2, code.allSatisfy({ $0.isASCII && $0.isLetter }) else { return nil }
        return code
    }

    /// `route -n get <ip>` → interface name.
    static func parseRouteInterface(_ output: String) -> String? {
        let line = output.split(separator: "\n").first { $0.trimmingCharacters(in: .whitespaces).hasPrefix("interface:") }
        guard let name = line?.split(separator: ":").last?.trimmingCharacters(in: .whitespaces),
              isValidInterfaceName(name) else { return nil }
        return name
    }

    /// `netstat -rn` → static routes as "dest gateway netif". The VPN endpoint's host route lives here,
    /// so a server switch inside the same `utun` still changes the network identity.
    static func parseStaticRoutes(_ netstatOutput: String) -> [String] {
        netstatOutput.split(separator: "\n").compactMap { line in
            let columns = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard columns.count >= 4, columns[2].contains("S"), columns[2].first == "U" else { return nil }
            return "\(columns[0]) \(columns[1]) \(columns[3])"
        }.sorted()
    }

    /// Paths that leave the Mac through someone else's exit, invisible to an IP-based block.
    static func bypassWarning(proxySettings: String, relayConnections: String) -> String? {
        let proxyKeys = ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable"]
        let proxyOn = proxySettings.split(separator: "\n").contains { line in
            let parts = line.split(separator: ":").map { $0.trimmingCharacters(in: .whitespaces) }
            return parts.count == 2 && proxyKeys.contains(parts[0]) && parts[1] == "1"
        }
        if proxyOn { return "system proxy enabled: apps using it bypass the guard" }
        if relayConnections.contains("->") { return "iCloud Private Relay active: Safari bypasses the guard" }
        return nil
    }

    /// `ifconfig <if>` → its address lines. Link-local addresses are random per tunnel instance,
    /// so a VPN reconnect / server switch changes them even when the interface name stays `utun4`.
    static func parseAddressLines(_ ifconfigOutput: String) -> [String] {
        ifconfigOutput.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.hasPrefix("inet ") || $0.hasPrefix("inet6 ") }
    }

    static func isValidInterfaceName(_ name: String) -> Bool {
        name.range(of: #"^[a-z]+[0-9]+$"#, options: .regularExpression) != nil
    }

    static func isNumericAddress(_ address: String) -> Bool {
        address.range(of: #"^[0-9a-fA-F:.]+(/[0-9]{1,3})?$"#, options: .regularExpression) != nil
    }

    private static func jsonObject(_ body: String) -> [String: Any]? {
        guard let data = body.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}

struct CountryList: Equatable {
    let codes: [String]
    let unknown: [String]
    var isValid: Bool { !codes.isEmpty && unknown.isEmpty }
}

enum GeoResult: Equatable {
    case country(String, timezone: String? = nil)
    case unavailable
}

enum Verdict: Equatable {
    case allow(interface: String, country: String)
    case block(reason: String)

    var isAllowed: Bool { interface != nil }

    var interface: String? {
        if case .allow(let interface, _) = self { return interface }
        return nil
    }
}

struct NetworkSnapshot: Equatable {
    let interface: String
    let addresses: [String]
    var routes: [String] = []
}

struct Verification {
    let network: NetworkSnapshot
    let country: String
    var timezone: String? = nil
    let at: Date

    func isStillValid(for current: NetworkSnapshot, now: Date) -> Bool {
        network == current && now.timeIntervalSince(at) < Policy.unchangedNetworkGrace
    }
}
