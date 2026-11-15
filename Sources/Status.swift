import Foundation

/// Written by the root daemon, read by the menu-bar tray.
struct Status: Codable {
    static let path = "/var/run/novpn-no-claude.json"

    var allowed: Bool
    var interface: String?
    var allowedCountries: [String]?
    var timezone: String?
    var detail: String
    var checking: Bool
    var firewallProblem: String?
    var warning: String?
    var lastCheck: Date?
    var updatedAt: Date

    static func read() -> Status? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return try? decoder.decode(Status.self, from: data)
    }

    func write() {
        guard let data = try? Status.encoder.encode(self) else { return }
        try? data.write(to: URL(fileURLWithPath: Status.path), options: .atomic)
    }

    private static let encoder: JSONEncoder = { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; return e }()
    private static let decoder: JSONDecoder = { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }()
}

/// Gate for launching Claude Code. Purely local: reads the daemon verdict and the current route, no network.
struct LaunchReport: Equatable {
    let ok: Bool
    let summary: String
    let hint: String?
    /// Exit country's zone, handed to Claude Code as TZ.
    var timezone: String? = nil

    init(_ status: Status?, currentInterface: String?, now: Date) {
        guard let status, now.timeIntervalSince(status.updatedAt) < StatusView.staleAfter else {
            self.init(fail: "guard daemon is not running", hint: "check /var/log/novpn-no-claude.log or reinstall")
            return
        }
        let allowed = (status.allowedCountries ?? []).joined(separator: ", ")
        if let problem = status.firewallProblem {
            self.init(fail: "firewall problem, \(problem)", hint: "check /var/log/novpn-no-claude.log")
        } else if !status.allowed {
            self.init(fail: status.detail, hint: "turn on the VPN (allowed \(allowed)) and retry")
        } else if status.interface == nil || status.allowedCountries == nil {
            self.init(fail: "guard daemon is outdated", hint: "reinstall with sudo ./install.sh")
        } else if status.timezone == nil {
            self.init(fail: "no time zone known for this exit country", hint: "check /var/log/novpn-no-claude.log")
        } else if currentInterface != status.interface {
            self.init(fail: "network changed, Claude now routes via \(currentInterface ?? "nothing")",
                      hint: "retry in a few seconds")
        } else {
            let age = status.lastCheck.map { " · verified \(LaunchReport.ago(now.timeIntervalSince($0)))" } ?? ""
            self.init(ok: true, summary: "\(status.detail) · TZ \(status.timezone!)\(age) · allowed \(allowed)", hint: nil)
            self.timezone = status.timezone
        }
    }

    private init(fail summary: String, hint: String) {
        self.init(ok: false, summary: summary, hint: "Claude Code not started, \(hint)")
    }

    private init(ok: Bool, summary: String, hint: String?) {
        self.ok = ok
        self.summary = summary
        self.hint = hint
    }

    static func ago(_ seconds: TimeInterval) -> String {
        let s = max(0, Int(seconds))
        return s < 60 ? "\(s)s ago" : "\(s / 60)m ago"
    }
}

/// What the tray shows. AppKit-free so it is testable. `badge` is the SF Symbol, `tone` its color.
struct StatusView: Equatable {
    static let staleAfter: TimeInterval = 15

    enum Tone { case allowed, blocked, checking, problem, unknown }

    let badge: String
    let tone: Tone
    let title: String
    let lines: [String]

    init(_ status: Status?, now: Date) {
        guard let status, now.timeIntervalSince(status.updatedAt) < StatusView.staleAfter else {
            self.init(badge: "questionmark.circle", tone: .unknown, title: "",
                      lines: ["Guard daemon not responding", "Last firewall state still applies"])
            return
        }
        let warning = status.warning.map { ["⚠︎ \($0)"] } ?? []
        let check = status.lastCheck.map { "Last check: \(StatusView.clock.string(from: $0))" } ?? "Last check: never"
        if let problem = status.firewallProblem {
            self.init(badge: "exclamationmark.triangle", tone: .problem, title: "",
                      lines: ["Firewall problem: \(problem)", status.detail, check])
        } else if status.checking {
            self.init(badge: "arrow.triangle.2.circlepath", tone: .checking, title: "",
                      lines: ["Checking VPN…", status.detail, check] + warning)
        } else if status.allowed {
            self.init(badge: "network", tone: .allowed, title: warning.isEmpty ? "" : "⚠︎",
                      lines: ["Claude allowed", status.detail, check] + warning)
        } else {
            self.init(badge: "network.slash", tone: .blocked, title: warning.isEmpty ? "" : "⚠︎",
                      lines: ["Claude BLOCKED", status.detail, check] + warning)
        }
    }

    private init(badge: String, tone: Tone, title: String, lines: [String]) {
        self.badge = badge
        self.tone = tone
        self.title = title
        self.lines = lines
    }

    private static let clock: DateFormatter = { let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; return f }()
}
