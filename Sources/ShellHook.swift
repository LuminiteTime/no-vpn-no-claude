import Foundation

/// The marked block the installer puts into the user's shell rc file. Edits are idempotent and never
/// touch anything outside the markers.
enum ShellHook {
    static let begin = "# >>> no-vpn-no-claude >>>"
    static let end = "# <<< no-vpn-no-claude <<<"
    static let wrapperPath = "/Library/Application Support/NoVpnNoClaude/claude-wrapper.sh"

    static func adding(to rc: String) -> String {
        var text = removing(from: rc)
        if !text.isEmpty && !text.hasSuffix("\n") { text += "\n" }
        if !text.isEmpty { text += "\n" }
        return text + "\(begin)\n[ -f \"\(wrapperPath)\" ] && . \"\(wrapperPath)\"\n\(end)\n"
    }

    /// Drops every complete marked block plus the blank line `adding` put before it.
    /// An unmatched begin marker is left alone rather than deleting the rest of the file.
    static func removing(from rc: String) -> String {
        var lines = rc.components(separatedBy: "\n")
        while let first = lines.firstIndex(of: begin),
              let last = lines[first...].firstIndex(of: end) {
            let start = first > 0 && lines[first - 1].isEmpty ? first - 1 : first
            lines.removeSubrange(start...last)
        }
        return lines.joined(separator: "\n")
    }

    /// Rewrites the file in place, so its owner, permissions and symlinks survive.
    static func update(rcPath: String, add: Bool) throws {
        let current = (try? String(contentsOfFile: rcPath, encoding: .utf8)) ?? ""
        let updated = add ? adding(to: current) : removing(from: current)
        guard updated != current else { return }
        try updated.write(toFile: rcPath, atomically: false, encoding: .utf8)
    }
}
