import AppKit

/// Menu-bar indicator. Read-only: it only displays what the root daemon publishes.
final class Tray: NSObject {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private var shown: StatusView?

    static func run() -> Never {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let tray = Tray()
        tray.refresh()
        Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in tray.refresh() }
        app.run()
        exit(0)
    }

    private func refresh() {
        let view = StatusView(Status.read(), now: Date())
        guard view != shown else { return }
        shown = view
        item.button?.image = TrayIcon.image(badge: view.badge)
        item.button?.title = view.title
        item.button?.toolTip = view.lines.joined(separator: "\n")
        item.menu = menu(for: view)
    }

    private func menu(for view: StatusView) -> NSMenu {
        let menu = NSMenu()
        menu.addItem(withTitle: "No VPN — No Claude", action: nil, keyEquivalent: "")
        menu.addItem(.separator())
        view.lines.forEach { menu.addItem(withTitle: $0, action: nil, keyEquivalent: "") }
        return menu
    }
}
