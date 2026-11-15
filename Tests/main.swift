import Foundation

var failures = 0
func check(_ condition: @autoclosure () -> Bool, _ name: String) {
    if condition() { print("ok   \(name)") } else { print("FAIL \(name)"); failures += 1 }
}

let now = Date()
let allowedSet: Set<String> = ["LV", "DE"]
let vpn = NetworkSnapshot(interface: "utun4", addresses: ["inet 10.8.1.8 --> 10.8.1.8", "inet6 fe80::a0fa%utun4"])
let reconnectedVpn = NetworkSnapshot(interface: "utun4", addresses: ["inet 10.8.1.8 --> 10.8.1.8", "inet6 fe80::beef%utun4"])
let direct = NetworkSnapshot(interface: "en0", addresses: ["inet 192.168.1.101"])
let verified = Verification(network: vpn, country: "LV", at: now.addingTimeInterval(-60))

// MARK: country parsing
check(Policy.parseGeo("LV\n") == .country("LV"), "plain country")
check(Policy.parseGeo("de") == .country("DE"), "lowercase country")
check(Policy.parseGeo(#"{"ip":"1.2.3.4","country":"LV","timezone":"Europe/Riga"}"#) == .country("LV", timezone: "Europe/Riga"), "ipinfo json with timezone")
check(Policy.parseGeo(#"{"country":"Latvia","country_iso":"LV","time_zone":"Europe/Riga"}"#) == .country("LV", timezone: "Europe/Riga"), "ifconfig.co json, country name ignored")
check(Policy.parseGeo(#"{"ip":"1.2.3.4","country":"LV"}"#) == .country("LV"), "country.is json without timezone")
check(Policy.parseGeo("<!DOCTYPE html><html>") == .unavailable, "html challenge page rejected")
check(Policy.parseGeo("") == .unavailable, "empty rejected")
check(Policy.parseGeo("LVA") == .unavailable && Policy.parseGeo("L1") == .unavailable, "bad codes rejected")
check(Policy.parseGeo(#"{"country":"Latvia"}"#) == .unavailable, "json with only a country name rejected")

// MARK: time zone of the exit country
let zones = Policy.parseZoneTab("""
# comment
DE\t+5230+01322\tEurope/Berlin\tmost of Germany
DE\t+4742+00841\tEurope/Busingen\tBusingen
LV\t+5657+02406\tEurope/Riga
US\t+404251-0740023\tAmerica/New_York\tEastern
US\t+340308-1181434\tAmerica/Los_Angeles\tPacific
""")
check(zones["DE"] == ["Europe/Berlin", "Europe/Busingen"] && zones["LV"] == ["Europe/Riga"], "zone.tab parsed, main zone first")
check(Policy.timezone(country: "LV", reported: "Europe/Riga", zones: zones) == "Europe/Riga", "reported zone of that country used")
check(Policy.timezone(country: "US", reported: "America/Los_Angeles", zones: zones) == "America/Los_Angeles", "regional zone kept for multi-zone country")
check(Policy.timezone(country: "DE", reported: nil, zones: zones) == "Europe/Berlin", "no reported zone → country's main zone")
check(Policy.timezone(country: "LV", reported: "Europe/Moscow", zones: zones) == "Europe/Riga", "zone of another country never used")
check(Policy.timezone(country: "LV", reported: "../../etc/passwd", zones: zones) == "Europe/Riga", "garbage zone never used")
check(Policy.timezone(country: "BV", reported: nil, zones: zones) == nil, "country without zone → unknown")
check(TimeZones.zone(for: "LV", reported: nil) == "Europe/Riga" && TimeZones.zone(for: "DE", reported: nil) == "Europe/Berlin", "system zone.tab readable")


// MARK: decisions
check(Policy.decide(geo: .country("LV"), network: vpn, lastVerified: nil, allowed: allowedSet, now: now) == .allow(interface: "utun4", country: "LV"), "LV allowed")
check(Policy.decide(geo: .country("DE"), network: vpn, lastVerified: nil, allowed: allowedSet, now: now).isAllowed, "DE allowed")
check(!Policy.decide(geo: .country("RU"), network: direct, lastVerified: verified, allowed: allowedSet, now: now).isAllowed, "RU blocked even with old verification")
check(!Policy.decide(geo: .country("US"), network: vpn, lastVerified: verified, allowed: allowedSet, now: now).isAllowed, "VPN server in US blocked")
check(!Policy.decide(geo: .unavailable, network: vpn, lastVerified: nil, allowed: allowedSet, now: now).isAllowed, "geo failure, never verified: blocked")
check(Policy.decide(geo: .unavailable, network: vpn, lastVerified: verified, allowed: allowedSet, now: now) == .allow(interface: "utun4", country: "LV"), "geo failure, same network recently verified: allowed")
check(!Policy.decide(geo: .unavailable, network: direct, lastVerified: verified, allowed: allowedSet, now: now).isAllowed, "geo failure, other interface: blocked")
check(!Policy.decide(geo: .unavailable, network: reconnectedVpn, lastVerified: verified, allowed: allowedSet, now: now).isAllowed, "geo failure, tunnel recreated: blocked")
check(!Policy.decide(geo: .unavailable, network: vpn, lastVerified: verified, allowed: allowedSet, now: now.addingTimeInterval(Policy.unchangedNetworkGrace)).isAllowed, "geo failure, verification expired: blocked")

// MARK: revocation on network change
let allowed = Verdict.allow(interface: "utun4", country: "LV")
check(!Policy.mustRevoke(allowed, current: vpn, lastVerified: verified), "same network keeps allow")
check(Policy.mustRevoke(allowed, current: direct, lastVerified: verified), "VPN dropped revokes")
check(Policy.mustRevoke(allowed, current: reconnectedVpn, lastVerified: verified), "tunnel recreated revokes")
check(!Policy.mustRevoke(.block(reason: "x"), current: direct, lastVerified: verified), "block stays block")

// MARK: pf rules
let addresses = ["160.79.104.0/21", "2607:6bc0::/32"]
let allowRules = Policy.pfRules(for: allowed, addresses: addresses)
let blockRules = Policy.pfRules(for: .block(reason: "x"), addresses: addresses)
let passLine = "pass out quick on utun4 to <claude>"
let blockLine = "block return out quick to <claude>"
check(allowRules.contains("table <claude> const { 160.79.104.0/21, 2607:6bc0::/32 }"), "table lists addresses")
check(allowRules.range(of: passLine)!.lowerBound < allowRules.range(of: blockLine)!.lowerBound, "allow: pass on interface precedes block")
check(blockRules.contains(blockLine) && !blockRules.contains("pass"), "block: no pass rule")
let injected = Policy.pfRules(for: .allow(interface: "en0 to any\npass out all", country: "LV"), addresses: addresses)
check(!injected.contains("pass"), "malicious interface name never reaches pf")

// MARK: command output parsing
let routeOutput = """
   route to: 160.79.104.10
destination: 160.79.104.10
  interface: utun4
      flags: <UP,HOST,DONE,WASCLONED,IFSCOPE,IFREF>
"""
check(Policy.parseRouteInterface(routeOutput) == "utun4", "route interface parsed")
check(Policy.parseRouteInterface("route: writing to routing socket: not in table") == nil, "no route → nil")
check(Policy.parseRouteInterface("  interface: utun4;rm") == nil, "weird interface rejected")
let ifconfigOutput = """
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1376
	inet 10.8.1.8 --> 10.8.1.8 netmask 0xffffffff
	inet6 fe80::a0fa:2445:7ae3:6a0b%utun4 prefixlen 64 scopeid 0x1b
	inet6 fd58:baa6:dead::1 prefixlen 128
"""
check(Policy.parseAddressLines(ifconfigOutput).count == 3, "address lines parsed")
check(Policy.isNumericAddress("160.79.104.10") && Policy.isNumericAddress("2607:6bc0::10"), "numeric addresses accepted")
check(!Policy.isNumericAddress("fe80::1%en0") && !Policy.isNumericAddress("x; pass"), "scoped/garbage addresses rejected")

// MARK: route identity (VPN server switch inside the same utun)
let netstatOutput = """
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
0/1                utun4              UScg                utun4
default            192.168.1.1        UGScg                 en0
85.159.228.60/32   192.168.1.1        UGSc                  en0
192.168.1.1        4:bf:6d:42:42:c4   UHLWIir               en0   1152
"""
let routes = Policy.parseStaticRoutes(netstatOutput)
check(routes == ["0/1 utun4 utun4", "85.159.228.60/32 192.168.1.1 en0", "default 192.168.1.1 en0"], "static routes parsed, header and ARP entries skipped")
let switchedServer = netstatOutput.replacingOccurrences(of: "85.159.228.60", with: "203.0.113.7")
check(Policy.parseStaticRoutes(switchedServer) != routes, "endpoint change alters route identity")
check(Policy.parseStaticRoutes(netstatOutput.replacingOccurrences(of: "1152", with: "900")) == routes, "ARP expiry ticking does not alter identity")
let vpnWithRoutes = NetworkSnapshot(interface: "utun4", addresses: vpn.addresses, routes: routes)
let vpnOtherServer = NetworkSnapshot(interface: "utun4", addresses: vpn.addresses, routes: Policy.parseStaticRoutes(switchedServer))
let verifiedWithRoutes = Verification(network: vpnWithRoutes, country: "LV", at: now)
check(Policy.mustRevoke(allowed, current: vpnOtherServer, lastVerified: verifiedWithRoutes), "server switch in same utun revokes")
check(!Policy.decide(geo: .unavailable, network: vpnOtherServer, lastVerified: verifiedWithRoutes, allowed: allowedSet, now: now).isAllowed, "server switch + geo failure: blocked")

// MARK: bypass warnings
let noProxy = "<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n  SOCKSEnable : 0\n}"
check(Policy.bypassWarning(proxySettings: noProxy, relayConnections: "") == nil, "no proxy, no relay: no warning")
check(Policy.bypassWarning(proxySettings: noProxy.replacingOccurrences(of: "SOCKSEnable : 0", with: "SOCKSEnable : 1"), relayConnections: "") != nil, "SOCKS proxy warns")
check(Policy.bypassWarning(proxySettings: "  ProxyAutoConfigEnable : 1", relayConnections: "") != nil, "PAC proxy warns")
check(Policy.bypassWarning(proxySettings: noProxy, relayConnections: "networkse 123 u 9u IPv4 UDP 10.8.1.8:5000->17.250.84.146:443") != nil, "Private Relay connection warns")

// MARK: tray view
let fresh = Status(allowed: true, interface: "utun4", allowedCountries: ["LV", "DE"], timezone: "Europe/Riga", detail: "Exit country LV via utun4", checking: false, firewallProblem: nil, lastCheck: now, updatedAt: now)
check(StatusView(fresh, now: now).tone == .allowed, "allowed badge green")
check(StatusView(nil, now: now).badge == "questionmark.circle", "no status → question badge")
check(StatusView(fresh, now: now.addingTimeInterval(StatusView.staleAfter)).badge == "questionmark.circle", "stale status → question badge")
var blocked = fresh; blocked.allowed = false
check(StatusView(blocked, now: now).lines.first == "Claude BLOCKED" && StatusView(blocked, now: now).tone == .blocked, "blocked text and red tone")
var warned = fresh; warned.warning = "system proxy enabled"
check(StatusView(warned, now: now).title == "⚠︎" && StatusView(warned, now: now).lines.last!.contains("proxy"), "bypass warning shown")
var broken = fresh; broken.firewallProblem = "pf is disabled"
check(StatusView(broken, now: now).badge == "exclamationmark.triangle", "firewall problem wins")

// MARK: launch gate (novpn check)
let go = LaunchReport(fresh, currentInterface: "utun4", now: now.addingTimeInterval(12))
check(go.ok && go.summary == "Exit country LV via utun4 · TZ Europe/Riga · verified 12s ago · allowed LV, DE", "launch: verified VPN → go with compact summary")
check(go.timezone == "Europe/Riga", "launch: hands the exit zone to the wrapper")
var noZone = fresh; noZone.timezone = nil
check(!LaunchReport(noZone, currentInterface: "utun4", now: now).ok, "launch: unknown exit zone → refuse")
check(LaunchReport(blocked, currentInterface: "en0", now: now).timezone == nil, "launch: no zone handed out when refused")
check(!LaunchReport(nil, currentInterface: "utun4", now: now).ok, "launch: no daemon → refuse")
check(!LaunchReport(fresh, currentInterface: "utun4", now: now.addingTimeInterval(StatusView.staleAfter)).ok, "launch: stale status → refuse")
check(LaunchReport(blocked, currentInterface: "en0", now: now).hint!.contains("allowed LV, DE"), "launch: blocked → refuse naming allowed countries")
check(!LaunchReport(fresh, currentInterface: "en0", now: now).ok, "launch: route moved off verified interface → refuse")
check(!LaunchReport(fresh, currentInterface: nil, now: now).ok, "launch: offline → refuse")
check(!LaunchReport(broken, currentInterface: "utun4", now: now).ok, "launch: firewall problem → refuse")
var outdated = fresh; outdated.allowedCountries = nil
check(LaunchReport(outdated, currentInterface: "utun4", now: now).summary.contains("outdated"), "launch: old daemon → refuse, ask to reinstall")
check(LaunchReport.ago(5) == "5s ago" && LaunchReport.ago(185) == "3m ago", "age formatting")

// MARK: country config
check(Policy.parseCountries("lv, de") == CountryList(codes: ["LV", "DE"], unknown: []), "countries normalized")
check(Policy.parseCountries("LV,LV de").codes == ["LV", "DE"], "duplicates dropped, order kept")
check(Policy.parseCountries("LV,XX,latvia").unknown == ["XX", "LATVIA"], "non-ISO codes reported")
check(!Policy.parseCountries("").isValid && !Policy.parseCountries("LV,ZZ").isValid, "empty or partly bad list invalid")
check(Policy.isoCountryCodes.contains("US") && Policy.isoCountryCodes.count > 200, "ISO list available")
check(!Policy.decide(geo: .country("LV"), network: vpn, lastVerified: nil, allowed: [], now: now).isAllowed, "empty config never allows")

// MARK: shell hook
let rc = "export PATH=x\nalias ll='ls -l'\n"
let hooked = ShellHook.adding(to: rc)
check(hooked.hasPrefix(rc) && hooked.contains(ShellHook.begin) && hooked.contains(ShellHook.wrapperPath), "hook appended after user content")
check(ShellHook.adding(to: hooked) == hooked, "adding twice is idempotent")
check(ShellHook.removing(from: hooked) == rc, "remove restores original exactly")
check(ShellHook.adding(to: "") == ShellHook.adding(to: "").trimmingCharacters(in: .newlines) + "\n" && !ShellHook.adding(to: "").hasPrefix("\n"), "empty rc gets just the block")
check(ShellHook.removing(from: "a\n\(ShellHook.begin)\nb\n") == "a\n\(ShellHook.begin)\nb\n", "unmatched marker leaves file untouched")
let tmpRc = FileManager.default.temporaryDirectory.appendingPathComponent("novpn-rc-\(getpid())").path
try? rc.write(toFile: tmpRc, atomically: true, encoding: .utf8)
try? ShellHook.update(rcPath: tmpRc, add: true)
try? ShellHook.update(rcPath: tmpRc, add: false)
check((try? String(contentsOfFile: tmpRc, encoding: .utf8)) == rc, "file round trip add/remove")
try? FileManager.default.removeItem(atPath: tmpRc)

// MARK: pf accepts generated syntax (parse only, loads nothing)
func pfParses(_ rules: String) -> Bool {
    let file = FileManager.default.temporaryDirectory.appendingPathComponent("novpn-test-\(getpid()).pf")
    try? rules.write(to: file, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: file) }
    return Shell.run("/sbin/pfctl", ["-q", "-n", "-f", file.path]).status == 0
}
check(pfParses(allowRules), "pfctl -n accepts allow rules")
check(pfParses(blockRules), "pfctl -n accepts block rules")
check(!pfParses("this is not pf\n"), "pfctl -n rejects garbage (sanity)")

print(failures == 0 ? "\nALL PASSED" : "\n\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
