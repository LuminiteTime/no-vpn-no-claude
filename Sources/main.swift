import Foundation

let arguments = Array(CommandLine.arguments.dropFirst())

switch arguments.first {
case "daemon":
    guard getuid() == 0 else { fail("daemon must run as root") }
    let countries = Policy.parseCountries(arguments.dropFirst().joined(separator: ","))
    Daemon(allowed: countries.isValid ? countries.codes : []).run()
case "tray":
    Tray.run()
case "check":
    let report = LaunchReport(Status.read(), currentInterface: Network.snapshot()?.interface, now: Date())
    let mark = report.ok ? Term.green("✓") : Term.red("✗")
    let summary = report.ok ? Term.dim(report.summary) : Term.red(report.summary)
    printErr("\(mark) \(Term.bold("no-vpn-no-claude")) \(summary)")
    if let hint = report.hint { printErr("  \(Term.yellow(hint))") }
    if let timezone = report.timezone { print(timezone) }   // stdout: the wrapper passes it to Claude Code as TZ
    exit(report.ok ? 0 : 1)
case "status":
    print(StatusView(Status.read(), now: Date()).lines.joined(separator: "\n"))
case "countries":
    let list = Policy.parseCountries(arguments.dropFirst().joined(separator: ","))
    guard list.unknown.isEmpty else { fail("unknown country code \(list.unknown.joined(separator: ", ")), use ISO codes like LV or DE") }
    guard list.isValid else { fail("enter at least one country code") }
    let english = Locale(identifier: "en_US")
    print(list.codes.joined(separator: ","))
    print(list.codes.map { "\(english.localizedString(forRegionCode: $0) ?? $0) (\($0))" }.joined(separator: ", "))
case "hook":
    guard arguments.count == 3, ["add", "remove"].contains(arguments[1]) else { fail("usage: novpn hook add|remove <rc file>") }
    do { try ShellHook.update(rcPath: arguments[2], add: arguments[1] == "add") } catch { fail("cannot update \(arguments[2]), \(error.localizedDescription)") }
case "flush":
    guard getuid() == 0 else { fail("flush must run as root") }
    Firewall.flush()
default:
    printErr("usage: novpn daemon <countries> | tray | check | status | countries <list> | hook add|remove <rc> | flush")
    exit(2)
}

func fail(_ message: String) -> Never {
    printErr(Term.red("✗ \(message)"))
    exit(1)
}

func printErr(_ line: String) {
    FileHandle.standardError.write(Data((line + "\n").utf8))
}

/// ANSI colors on a terminal (or with CLICOLOR_FORCE=1), never when NO_COLOR is set.
enum Term {
    private static let enabled: Bool = {
        let env = ProcessInfo.processInfo.environment
        return (isatty(STDERR_FILENO) != 0 || env["CLICOLOR_FORCE"] == "1") && env["NO_COLOR"] == nil
    }()

    static func green(_ text: String) -> String { paint(text, "32") }
    static func red(_ text: String) -> String { paint(text, "31") }
    static func yellow(_ text: String) -> String { paint(text, "33") }
    static func dim(_ text: String) -> String { paint(text, "2") }
    static func bold(_ text: String) -> String { paint(text, "1") }

    private static func paint(_ text: String, _ code: String) -> String {
        enabled ? "\u{1B}[\(code)m\(text)\u{1B}[0m" : text
    }
}
