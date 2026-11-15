import AppKit

/// Menu-bar glyph: a radiating star (Claude-style starburst, drawn here, not the logo) with a status badge
/// in the lower right corner. Template image, so macOS tints it for light and dark menu bars.
enum TrayIcon {
    private static let size = NSSize(width: 22, height: 18)
    private static let starCenter = CGPoint(x: 7.5, y: 10.5)
    private static let badgeRect = NSRect(x: 13, y: 0.5, width: 9, height: 9)

    static func image(badge symbol: String) -> NSImage {
        let image = NSImage(size: size, flipped: false) { _ in
            drawStar()
            punchBadgeHole()
            drawBadge(symbol)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "no-vpn-no-claude"
        return image
    }

    /// Ten tapered rays of uneven length meeting in a small core, like a hand-cut asterisk.
    private static func drawStar() {
        let lengths: [CGFloat] = [7.2, 5.6, 6.8, 5.2, 7.0, 5.8, 6.6, 5.4, 7.2, 5.5]
        NSColor.black.setFill()
        for (index, length) in lengths.enumerated() {
            let angle = CGFloat(index) / CGFloat(lengths.count) * 2 * .pi + .pi / 2
            let ray = NSBezierPath()
            ray.move(to: point(at: angle - 0.22, radius: 1.6))
            ray.line(to: point(at: angle - 0.07, radius: length - 0.5))
            ray.appendArc(withCenter: point(at: angle, radius: length - 0.5), radius: 0.5,
                          startAngle: (angle - .pi / 2) * 180 / .pi, endAngle: (angle + .pi / 2) * 180 / .pi)
            ray.line(to: point(at: angle + 0.22, radius: 1.6))
            ray.close()
            ray.fill()
        }
        NSBezierPath(ovalIn: NSRect(x: starCenter.x - 1.8, y: starCenter.y - 1.8, width: 3.6, height: 3.6)).fill()
    }

    private static func punchBadgeHole() {
        NSGraphicsContext.current?.compositingOperation = .clear
        NSBezierPath(ovalIn: badgeRect.insetBy(dx: -1.2, dy: -1.2)).fill()
        NSGraphicsContext.current?.compositingOperation = .sourceOver
    }

    private static func drawBadge(_ symbol: String) {
        let config = NSImage.SymbolConfiguration(pointSize: 8.5, weight: .bold)
        guard let glyph = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?
            .withSymbolConfiguration(config) else { return }
        let fitted = glyph.size.fitted(in: badgeRect.size)
        let origin = CGPoint(x: badgeRect.midX - fitted.width / 2, y: badgeRect.midY - fitted.height / 2)
        glyph.draw(in: NSRect(origin: origin, size: fitted))
    }

    private static func point(at angle: CGFloat, radius: CGFloat) -> CGPoint {
        CGPoint(x: starCenter.x + cos(angle) * radius, y: starCenter.y + sin(angle) * radius)
    }
}

private extension NSSize {
    func fitted(in box: NSSize) -> NSSize {
        let scale = min(box.width / width, box.height / height, 1)
        return NSSize(width: width * scale, height: height * scale)
    }
}
