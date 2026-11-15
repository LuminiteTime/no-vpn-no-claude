import Foundation

/// Root loop: fail closed at start, then allow Claude only through a verified interface.
final class Daemon {
    private static let tickInterval: TimeInterval = 2
    private static let warningInterval: TimeInterval = 30
    private static let resolveInterval: TimeInterval = 600

    private let allowed: [String]
    private var verdict: Verdict = .block(reason: "starting")
    private var lastVerified: Verification?
    private var lastSeenNetwork: NetworkSnapshot?
    private var lastCheck: Date?
    private var blockedAddresses = Set(Policy.anthropicNetworks)
    private var loadProblem: String?
    private var healthProblem: String?
    private var bypassWarning: String?
    private var nextGeoCheck = Date.distantPast
    private var nextWarningCheck = Date.distantPast
    private let resolver = BackgroundResolver()
    private let watchdog = Watchdog()

    /// An empty list never allows anything: a broken config fails closed instead of crash-looping unprotected.
    init(allowed: [String]) {
        self.allowed = allowed
    }

    func run() -> Never {
        signal(SIGPIPE, SIG_IGN)   // a child exiting early must not kill the guard
        log("starting, Claude blocked until VPN is verified, allowed countries \(allowed.isEmpty ? "NONE (bad config)" : allowed.joined(separator: ","))")
        enforce(verdict, force: true)
        Firewall.holdReference()
        watchdog.start()
        resolver.start(every: Daemon.resolveInterval)
        while true {
            tick()
            watchdog.beat()
            Thread.sleep(forTimeInterval: Daemon.tickInterval)
        }
    }

    private func tick() {
        let now = Date()
        checkFirewall()
        guardClaude(on: Network.snapshot(), now: now)
        if now >= nextWarningCheck { bypassWarning = Network.bypassWarning(); nextWarningCheck = now + Daemon.warningInterval }
        absorbResolvedAddresses()
        publish()
    }

    private func guardClaude(on network: NetworkSnapshot?, now: Date) {
        defer { lastSeenNetwork = network }
        guard let network else {
            enforce(.block(reason: "no route to Claude (offline?)"))
            return
        }
        if network != lastSeenNetwork { nextGeoCheck = now }   // VPN toggled / reconnected / server switched
        if Policy.mustRevoke(verdict, current: network, lastVerified: lastVerified) {
            enforce(.block(reason: "network changed, re-checking"))
        }
        if now >= nextGeoCheck { verify(network) }
    }

    private func verify(_ network: NetworkSnapshot) {
        publish(checking: true)
        let geo = Geo.country(via: network.interface)
        let now = Date()
        guard Network.snapshot() == network else { nextGeoCheck = now; return }   // changed mid-check: redo
        if case .country(let code, let reportedZone) = geo {
            lastCheck = now
            lastVerified = allowed.contains(code)
                ? Verification(network: network, country: code,
                               timezone: TimeZones.zone(for: code, reported: reportedZone), at: now)
                : nil
        }
        enforce(Policy.decide(geo: geo, network: network, lastVerified: lastVerified, allowed: Set(allowed), now: now))
        nextGeoCheck = now + (geo == .unavailable ? Policy.geoRetryInterval : Policy.geoRecheckInterval)
    }

    private func enforce(_ new: Verdict, force: Bool = false) {
        guard force || new != verdict else { return }
        let revoking = verdict.isAllowed && !new.isAllowed
        loadProblem = Firewall.load(Policy.pfRules(for: new, addresses: blockedAddresses.sorted()))
        if revoking { Firewall.killStates(to: blockedAddresses.sorted()) }
        if let loadProblem { log(loadProblem) }
        if new != verdict { log(Daemon.describe(new)) }
        verdict = new
    }

    /// Self-heal every tick: pf re-enabled, our rules re-applied if anything flushed them.
    private func checkFirewall() {
        let problem = Firewall.healthProblem()
        if problem != healthProblem { log("firewall health: \(problem ?? "ok")") }
        healthProblem = problem
        if loadProblem != nil { enforce(verdict, force: true); return }
        if !Firewall.rulesLoaded() {
            log("our pf rules were flushed, reloading")
            enforce(verdict, force: true)
        }
    }

    private func absorbResolvedAddresses() {
        let resolved = resolver.addresses
        guard !resolved.isSubset(of: blockedAddresses) else { return }
        blockedAddresses.formUnion(resolved)
        enforce(verdict, force: true)
    }

    private func publish(checking: Bool = false) {
        Status(allowed: verdict.isAllowed, interface: verdict.interface, allowedCountries: allowed,
               timezone: verdict.isAllowed ? lastVerified?.timezone : nil, detail: Daemon.describe(verdict), checking: checking,
               firewallProblem: healthProblem ?? loadProblem, warning: bypassWarning,
               lastCheck: lastCheck, updatedAt: Date()).write()
    }

    private static func describe(_ verdict: Verdict) -> String {
        switch verdict {
        case .allow(let interface, let country): return "Exit country \(country) via \(interface)"
        case .block(let reason): return "Blocked: \(reason)"
        }
    }
}

func log(_ message: String) {
    FileHandle.standardError.write(Data("\(ISO8601DateFormatter().string(from: Date())) \(message)\n".utf8))
}

/// DNS can hang for tens of seconds; keep it off the guard loop.
final class BackgroundResolver {
    private let lock = NSLock()
    private var resolved: Set<String> = []

    var addresses: Set<String> {
        lock.lock(); defer { lock.unlock() }
        return resolved
    }

    func start(every interval: TimeInterval) {
        Thread.detachNewThread { [self] in
            while true {
                let found = Set(Policy.claudeHosts.flatMap(Network.resolve))
                lock.lock(); resolved.formUnion(found); lock.unlock()
                Thread.sleep(forTimeInterval: interval)
            }
        }
    }
}

/// If the guard loop ever hangs, exit: launchd restarts us and we start fail-closed.
final class Watchdog {
    private static let limit: TimeInterval = 60
    private let lock = NSLock()
    private var lastBeat = Date()

    func beat() {
        lock.lock(); lastBeat = Date(); lock.unlock()
    }

    func start() {
        Thread.detachNewThread { [self] in
            while true {
                Thread.sleep(forTimeInterval: 10)
                lock.lock(); let silent = Date().timeIntervalSince(lastBeat); lock.unlock()
                if silent > Watchdog.limit { log("watchdog: loop stuck \(Int(silent))s, restarting"); exit(1) }
            }
        }
    }
}
