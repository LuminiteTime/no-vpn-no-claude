import AppKit

/// Menu-bar glyph: a large status symbol in the status color with a small radiating star (Claude-style
/// starburst, drawn here, not the logo) in the upper right corner. The star follows the menu bar text color.
enum TrayIcon {
    private static let size = NSSize(width: 24, height: 18)
    private static let statusRect = NSRect(x: 0, y: 0, width: 17, height: 17)
    private static let starCenter = CGPoint(x: 19.5, y: 13)
    private static let starRadius: CGFloat = 4.6

    static func image(symbol: String, color: NSColor) -> NSImage {
        let image = NSImage(size: size, flipped: false) { _ in
            drawStatus(symbol, color: color)
            punchStarHole()
            drawStar()
            return true
        }
        image.accessibilityDescription = "no-vpn-no-claude"
        return image
    }

    private static func drawStatus(_ symbol: String, color: NSColor) {
        let config = NSImage.SymbolConfiguration(pointSize: 15, weight: .semibold)
            .applying(.init(paletteColors: [color]))
        guard let glyph = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?
            .withSymbolConfiguration(config) else { return }
        let fitted = glyph.size.fitted(in: statusRect.size)
        glyph.draw(in: NSRect(x: statusRect.midX - fitted.width / 2, y: statusRect.midY - fitted.height / 2,
                              width: fitted.width, height: fitted.height))
    }

    private static func punchStarHole() {
        NSGraphicsContext.current?.compositingOperation = .clear
        let r = starRadius + 1.3
        NSBezierPath(ovalIn: NSRect(x: starCenter.x - r, y: starCenter.y - r, width: 2 * r, height: 2 * r)).fill()
        NSGraphicsContext.current?.compositingOperation = .sourceOver
    }

    /// Ten tapered rays of uneven length meeting in a small core, like a hand-cut asterisk.
    private static func drawStar() {
        let lengths: [CGFloat] = [1.0, 0.78, 0.94, 0.72, 0.97, 0.8, 0.92, 0.75, 1.0, 0.76].map { $0 * starRadius }
        NSColor.labelColor.setFill()
        for (index, length) in lengths.enumerated() {
            let angle = CGFloat(index) / CGFloat(lengths.count) * 2 * .pi + .pi / 2
            let tip: CGFloat = 0.45
            let ray = NSBezierPath()
            ray.move(to: point(at: angle - 0.3, radius: 1.1))
            ray.line(to: point(at: angle - 0.08, radius: length - tip))
            ray.appendArc(withCenter: point(at: angle, radius: length - tip), radius: tip,
                          startAngle: (angle - .pi / 2) * 180 / .pi, endAngle: (angle + .pi / 2) * 180 / .pi)
            ray.line(to: point(at: angle + 0.3, radius: 1.1))
            ray.close()
            ray.fill()
        }
        NSBezierPath(ovalIn: NSRect(x: starCenter.x - 1.4, y: starCenter.y - 1.4, width: 2.8, height: 2.8)).fill()
    }

    private static func point(at angle: CGFloat, radius: CGFloat) -> CGPoint {
        CGPoint(x: starCenter.x + cos(angle) * radius, y: starCenter.y + sin(angle) * radius)
    }
}

private extension NSSize {
    func fitted(in box: NSSize) -> NSSize {
        let scale = min(box.width / width, box.height / height)
        return NSSize(width: width * scale, height: height * scale)
    }
}
