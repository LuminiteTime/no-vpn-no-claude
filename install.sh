#!/bin/bash
# Usage: sudo ./install.sh [--countries LV,DE] [--hook | --no-hook]
# Builds, tests and installs the root daemon (starts at boot), the menu-bar tray (starts at login)
# and, optionally, the Claude Code launch check for the invoking user's shell.
set -euo pipefail
cd "$(dirname "$0")"

DIR="/Library/Application Support/NoVpnNoClaude"
BIN="$DIR/novpn"
WRAPPER="$DIR/claude-wrapper.sh"
DAEMON=local.novpnnoclaude.daemon
TRAY=local.novpnnoclaude.tray
DAEMON_PLIST=/Library/LaunchDaemons/$DAEMON.plist
TRAY_PLIST=/Library/LaunchAgents/$TRAY.plist
ANCHOR=com.apple/050.NoVpnNoClaude
STATUS=/var/run/novpn-no-claude.json

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    B=$'\e[1m' G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' D=$'\e[2m' N=$'\e[0m'
else
    B='' G='' R='' Y='' D='' N=''
fi
step() { echo; echo "${B}==> $*${N}"; }
ok()   { echo "  ${G}✓${N} $*"; }
warn() { echo "  ${Y}!${N} $*"; }
die()  { echo "  ${R}✗ $*${N}" >&2; exit 1; }
ask()  { local reply; read -r -p "  $1 " reply </dev/tty; echo "$reply"; }

# bootout returns before the old job is gone; bootstrapping too early fails with "5: Input/output error".
restart_job() {  # domain label plist
    launchctl bootout "$1/$2" 2>/dev/null || true
    for _ in $(seq 1 20); do launchctl print "$1/$2" >/dev/null 2>&1 || break; sleep 0.5; done
    for _ in 1 2 3 4; do launchctl bootstrap "$1" "$3" 2>/dev/null && return 0; sleep 1; done
    launchctl bootstrap "$1" "$3"
}

COUNTRIES_ARG="" HOOK_ARG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --countries) COUNTRIES_ARG="${2:-}"; shift 2 ;;
        --hook) HOOK_ARG=yes; shift ;;
        --no-hook) HOOK_ARG=no; shift ;;
        -h|--help) sed -n 2,4p "$0"; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done
INTERACTIVE=no; [[ -t 0 ]] && INTERACTIVE=yes

echo "${B}no-vpn-no-claude installer${N}"

step "Checking requirements"
[[ $EUID -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] || die "run as a regular admin user via sudo ./install.sh"
MACOS=$(sw_vers -productVersion)
(( ${MACOS%%.*} >= 13 )) || die "macOS 13 or newer required, found $MACOS"
ok "macOS $MACOS, installing for $SUDO_USER"
sudo -u "$SUDO_USER" xcrun --find swiftc >/dev/null 2>&1 || die "Swift compiler missing, run xcode-select --install and retry"
ok "Swift compiler found"
pfctl -s rules 2>/dev/null | grep -q 'anchor "com.apple/\*"' \
    || die "main pf ruleset does not evaluate anchor \"com.apple/*\" (a VPN kill switch may have replaced it), nothing installed"
ok "pf ruleset evaluates com.apple/* anchors (VPN and other pf rules stay untouched)"

step "Building and testing"
BUILD_LOG=$(mktemp -t novpn-build)
sudo -u "$SUDO_USER" ./build.sh >"$BUILD_LOG" 2>&1 || { tail -20 "$BUILD_LOG"; die "build or tests failed, full log in $BUILD_LOG"; }
ok "$(grep -c '^ok' "$BUILD_LOG") tests passed"
rm -f "$BUILD_LOG"

step "Allowed exit countries"
CURRENT=$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:2' "$DAEMON_PLIST" 2>/dev/null || true)
COUNTRIES="$COUNTRIES_ARG"
while [[ -z "$COUNTRIES" ]]; do
    [[ $INTERACTIVE == yes ]] || { [[ -n "$CURRENT" ]] && COUNTRIES="$CURRENT" && break; die "no terminal, pass --countries LV,DE"; }
    echo "  Claude is allowed only when the internet exit IP is in one of these countries."
    COUNTRIES=$(ask "ISO codes, comma separated${CURRENT:+ [$CURRENT]}:")
    COUNTRIES="${COUNTRIES:-$CURRENT}"
    if ! build/novpn countries "$COUNTRIES" >/dev/null 2>&1; then build/novpn countries "$COUNTRIES" || true; COUNTRIES=""; fi
done
PARSED=$(build/novpn countries "$COUNTRIES") || die "invalid --countries value"
COUNTRIES=$(sed -n 1p <<<"$PARSED")
ok "$(sed -n 2p <<<"$PARSED")"

step "Claude Code launch check"
USER_HOME=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory | sed 's/^[^:]*: //')
USER_SHELL=$(dscl . -read "/Users/$SUDO_USER" UserShell | sed 's/^[^:]*: //')
case "$(basename "$USER_SHELL")" in
    zsh) RC="$USER_HOME/.zshrc" ;;
    bash) RC="$USER_HOME/.bash_profile" ;;
    *) RC="" ;;
esac
RC_SHORT="~${RC#"$USER_HOME"}"
HOOK="$HOOK_ARG"
if [[ -z "$RC" ]]; then
    warn "shell $USER_SHELL is not supported, add this to its config manually"
    echo "    ${D}[ -f \"$WRAPPER\" ] && . \"$WRAPPER\"${N}"
    HOOK=no
elif [[ -z "$HOOK" ]]; then
    if [[ $INTERACTIVE == yes ]]; then
        echo "  Wraps the claude command so it starts only after the guard approves the network."
        echo "  All claude flags keep working. The check is local and sends nothing to the network."
        reply=$(ask "Add it to $RC_SHORT? [Y/n]")
        [[ "$reply" =~ ^[Nn] ]] && HOOK=no || HOOK=yes
    else
        HOOK=no
    fi
fi

step "Installing"
install -d -o root -g wheel -m 755 "$DIR"
install -o root -g wheel -m 755 build/novpn "$BIN"
cat > "$WRAPPER" <<EOF
# Installed by no-vpn-no-claude. Claude Code starts only after the VPN guard approves the current network.
function claude {
    "$BIN" check || return 1
    command claude "\$@"
}
EOF
chown root:wheel "$WRAPPER"; chmod 644 "$WRAPPER"
ok "binary and wrapper in $DIR (root-owned)"

cat > "$DAEMON_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>$DAEMON</string>
    <key>ProgramArguments</key><array><string>$BIN</string><string>daemon</string><string>$COUNTRIES</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ThrottleInterval</key><integer>2</integer>
    <key>StandardErrorPath</key><string>/var/log/novpn-no-claude.log</string>
</dict></plist>
EOF
cat > "$TRAY_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>$TRAY</string>
    <key>ProgramArguments</key><array><string>$BIN</string><string>tray</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>LimitLoadToSessionType</key><string>Aqua</string>
    <key>ProcessType</key><string>Interactive</string>
</dict></plist>
EOF
chown root:wheel "$DAEMON_PLIST" "$TRAY_PLIST"; chmod 644 "$DAEMON_PLIST" "$TRAY_PLIST"
plutil -lint -s "$DAEMON_PLIST" "$TRAY_PLIST" || die "generated plist is invalid"
ok "launchd jobs written"

step "Starting"
USER_ID=$(id -u "$SUDO_USER")
restart_job system $DAEMON "$DAEMON_PLIST" || die "launchd refused the daemon, see the error above"
ok "daemon running (starts at boot)"
if restart_job gui/$USER_ID $TRAY "$TRAY_PLIST" 2>/dev/null; then ok "tray running (starts at login)"
else warn "no GUI session for $SUDO_USER now, tray starts at next login"; fi

for _ in $(seq 1 30); do
    sleep 1
    grep -q '"lastCheck"' "$STATUS" 2>/dev/null && grep -q '"checking":false' "$STATUS" && break
done
COLOR_ENV=CLICOLOR_FORCE=0; [[ -n "$G" ]] && COLOR_ENV=CLICOLOR_FORCE=1
sudo -u "$SUDO_USER" env "$COLOR_ENV" "$BIN" check 2>&1 | sed 's/^/  /' || true

# Hook goes in last, so a failed install never leaves claude refusing to start against a missing daemon.
if [[ $HOOK == yes ]]; then
    sudo -u "$SUDO_USER" "$BIN" hook add "$RC" || die "could not update $RC"
    ok "launch check added to $RC_SHORT, open a new terminal to use it"
elif [[ -n "$RC" ]]; then
    sudo -u "$SUDO_USER" "$BIN" hook remove "$RC" 2>/dev/null || true
    ok "launch check not installed"
fi

step "Leak probe"
CLAUDE_IF=$(route -n get 160.79.104.10 2>/dev/null | awk '/interface:/{print $2}' || true)
DIRECT_IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' || true)
if ! pfctl -a "$ANCHOR" -s rules 2>/dev/null | grep -q 'block return out quick'; then
    die "block rule not loaded, see /var/log/novpn-no-claude.log"
elif [[ -z "$CLAUDE_IF" || "$CLAUDE_IF" == "$DIRECT_IF" ]]; then
    ok "skipped, no VPN tunnel active to compare against (Claude stays blocked until one is verified)"
elif nc -z -G 3 -b "$DIRECT_IF" 160.79.104.10 443 2>/dev/null; then
    die "Claude is reachable via $DIRECT_IF outside the VPN, another pf rule overrides ours"
else
    ok "Claude via $DIRECT_IF (outside VPN) is blocked, only verified $CLAUDE_IF is allowed"
fi

echo
echo "${G}${B}Installed.${N} ${D}Log /var/log/novpn-no-claude.log · status $BIN status · remove sudo ./uninstall.sh${N}"
