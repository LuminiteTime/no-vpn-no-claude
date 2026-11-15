#!/bin/bash
# Usage: sudo ./uninstall.sh
# Stops the guard, removes the Claude block and the shell launch check. Other pf rules stay untouched.
set -uo pipefail
[[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]] || { echo "Run as sudo ./uninstall.sh"; exit 1; }

DIR="/Library/Application Support/NoVpnNoClaude"
USER_HOME=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory | sed 's/^[^:]*: //')

for rc in "$USER_HOME/.zshrc" "$USER_HOME/.bash_profile"; do
    [[ -f "$rc" && -x "$DIR/novpn" ]] && sudo -u "$SUDO_USER" "$DIR/novpn" hook remove "$rc"
done
launchctl bootout system/local.novpnnoclaude.daemon 2>/dev/null
launchctl bootout gui/$(id -u "$SUDO_USER")/local.novpnnoclaude.tray 2>/dev/null
pfctl -q -a com.apple/050.NoVpnNoClaude -F all 2>/dev/null
rm -f /Library/LaunchDaemons/local.novpnnoclaude.daemon.plist /Library/LaunchAgents/local.novpnnoclaude.tray.plist \
      /var/run/novpn-no-claude.json
rm -rf "$DIR"
echo "Uninstalled. Claude is no longer blocked. Log kept at /var/log/novpn-no-claude.log"
