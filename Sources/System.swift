import Foundation

/// Thin adapters over macOS tools. Absolute paths only: this runs as root.
enum Shell {
    struct Result { let status: Int32; let output: String }

    @discardableResult
    static func run(_ path: String, _ arguments: [String], input: String? = nil) -> Result {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        let stdin = Pipe()
        process.standardInput = stdin
        do { try process.run() } catch { return Result(status: -1, output: "\(error)") }
        if let input { try? stdin.fileHandleForWriting.write(contentsOf: Data(input.utf8)) }
        try? stdin.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()   // read before wait: no pipe deadlock
        process.waitUntilExit()
        return Result(status: process.terminationStatus, output: String(decoding: data, as: UTF8.self))
    }
}

/// Our own pf anchor. The main ruleset (and the VPN client's rules) is never touched.
enum Firewall {
    static let anchor = "com.apple/050.NoVpnNoClaude"
    private static let pfctl = "/sbin/pfctl"

    /// Atomic replace of the anchor's rules. Returns an error text or nil.
    static func load(_ rules: String) -> String? {
        let result = Shell.run(pfctl, ["-q", "-a", anchor, "-f", "-"], input: rules)
        return result.status == 0 ? nil : "pfctl load failed: \(result.output.trimmingCharacters(in: .whitespacesAndNewlines))"
    }

    /// Takes our own pf enable reference, so another tool releasing its reference cannot switch pf off.
    static func holdReference() {
        Shell.run(pfctl, ["-E"])
    }

    /// Re-enables pf if something force-disabled it; reports whether our anchor is actually evaluated.
    static func healthProblem() -> String? {
        if !isEnabled() {
            holdReference()
            if !isEnabled() { return "pf is disabled" }
        }
        if !Shell.run(pfctl, ["-s", "rules"]).output.contains("anchor \"com.apple/*\"") {
            return "main pf ruleset lacks anchor \"com.apple/*\""
        }
        return nil
    }

    /// False when someone flushed our anchor.
    static func rulesLoaded() -> Bool {
        Shell.run(pfctl, ["-a", anchor, "-s", "rules"]).output.contains("block return out quick")
    }

    private static func isEnabled() -> Bool {
        Shell.run(pfctl, ["-s", "info"]).output.contains("Status: Enabled")
    }

    /// Drops already-established connections to Claude so a new block applies to them too.
    static func killStates(to networks: [String]) {
        for network in networks {
            let any = network.contains(":") ? "::/0" : "0.0.0.0/0"
            Shell.run(pfctl, ["-q", "-k", any, "-k", network])
        }
    }

    static func flush() {
        Shell.run(pfctl, ["-q", "-a", anchor, "-F", "all"])
    }
}

enum Network {
    /// Interface that traffic to Claude currently leaves through, plus its addresses as an identity.
    static func snapshot() -> NetworkSnapshot? {
        let route = Shell.run("/sbin/route", ["-n", "get", Policy.probeAddress])
        guard let interface = Policy.parseRouteInterface(route.output) else { return nil }
        let ifconfig = Shell.run("/sbin/ifconfig", [interface])
        let netstat = Shell.run("/usr/sbin/netstat", ["-rn"])
        return NetworkSnapshot(interface: interface, addresses: Policy.parseAddressLines(ifconfig.output),
                               routes: Policy.parseStaticRoutes(netstat.output))
    }

    static func bypassWarning() -> String? {
        Policy.bypassWarning(proxySettings: Shell.run("/usr/sbin/scutil", ["--proxy"]).output,
                             relayConnections: Shell.run("/usr/sbin/lsof", ["-nP", "-a", "-c", "networkserviceproxy", "-i"]).output)
    }

    static func resolve(_ host: String) -> [String] {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &list) == 0 else { return [] }
        defer { freeaddrinfo(list) }
        var addresses: [String] = []
        var node = list
        while let info = node?.pointee {
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(info.ai_addr, info.ai_addrlen, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                addresses.append(String(cString: buffer))
            }
            node = info.ai_next
        }
        return addresses.filter(Policy.isNumericAddress)
    }
}

enum Geo {
    private static let providers = [
        "https://ipinfo.io/country",
        "https://ifconfig.co/country-iso",
        "https://api.country.is",
    ]

    /// Exit country as seen through `interface` — the same path Claude traffic takes.
    static func country(via interface: String) -> GeoResult {
        for url in providers {
            let result = Shell.run("/usr/bin/curl", ["-4", "-sS", "--fail", "-m", "5", "--interface", interface, url])
            if result.status == 0, let code = Policy.parseCountry(result.output) { return .country(code) }
        }
        return .unavailable
    }
}
