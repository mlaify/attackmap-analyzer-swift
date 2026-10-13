"""iOS/macOS app attack surface (AttackMap#188, swift#1).

`*.entitlements` and `*.xcconfig` inputs are written into `tmp_path` here
rather than committed: both are CODEOWNERS paths in this repo.
"""

from __future__ import annotations

import plistlib
import random
from pathlib import Path

from attackmap_analyzer_swift import SwiftAnalyzer
from attackmap_analyzer_swift.apple_surface import is_secret_name


def _write(root: Path, rel: str, content: str | bytes) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content, encoding="utf-8")


def _analyze(tmp_path: Path, files: dict[str, str | bytes]):
    files = {"App/AppDelegate.swift": "import UIKit\n", **files}
    for rel, content in files.items():
        _write(tmp_path, rel, content)
    return SwiftAnalyzer().analyze(tmp_path)


def _issues(result, kind: str):
    return [i for i in result.app_surface_issues if i.kind == kind]


INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.example.app</string>
	<key>CFBundleURLTypes</key>
	<array>
		<dict>
			<key>CFBundleURLSchemes</key>
			<array>
				<string>exampleapp</string>
			</array>
		</dict>
	</array>
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
		<key>NSExceptionDomains</key>
		<dict>
			<key>legacy.example.com</key>
			<dict>
				<key>NSExceptionAllowsInsecureHTTPLoads</key>
				<true/>
			</dict>
			<key>old-tls.example.com</key>
			<dict>
				<key>NSExceptionMinimumTLSVersion</key>
				<string>TLSv1.0</string>
			</dict>
			<key>fine.example.com</key>
			<dict>
				<key>NSIncludesSubdomains</key>
				<true/>
			</dict>
		</dict>
	</dict>
</dict>
</plist>
"""


def test_ats_exceptions_and_url_scheme_with_file_and_line(tmp_path: Path) -> None:
    result = _analyze(tmp_path, {
        "App/Info.plist": INFO_PLIST,
        "App/SceneDelegate.swift": (
            "import UIKit\nclass SceneDelegate: UIResponder, UIWindowSceneDelegate {\n"
            "    func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {\n"
            "        handle(URLContexts.first?.url)\n    }\n}\n"
        ),
    })
    ats = _issues(result, "apple_ats_insecure_loads")
    assert [(i.file, i.line, i.severity) for i in ats] == [
        ("App/Info.plist", 18, "medium"),
        ("App/Info.plist", 22, "low"),
        ("App/Info.plist", 27, "low"),
    ]
    assert ats[0].evidence_text == "NSAppTransportSecurity.NSAllowsArbitraryLoads = true"
    assert ats[1].evidence_text == "NSExceptionDomains.legacy.example.com: NSExceptionAllowsInsecureHTTPLoads"
    assert ats[2].evidence_text == "NSExceptionDomains.old-tls.example.com: NSExceptionMinimumTLSVersion = TLSv1.0"
    scheme = _issues(result, "apple_custom_url_scheme")
    assert [(i.file, i.line, i.severity) for i in scheme] == [("App/Info.plist", 12, "low")]
    assert scheme[0].evidence_text == "CFBundleURLSchemes: exampleapp://"
    hints = {(h.hint, h.file, h.line) for h in result.entrypoint_hints}
    assert ("url_scheme: exampleapp://", "App/Info.plist", 12) in hints
    assert ("url_scheme_handler (opens URLs from other apps)", "App/SceneDelegate.swift", 3) in hints


def test_binary_plist_and_scoped_ats_keys(tmp_path: Path) -> None:
    data = plistlib.dumps({
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True, "NSAllowsArbitraryLoadsInWebContent": True},
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["https", "fb12345"]}],
    }, fmt=plistlib.FMT_BINARY)
    result = _analyze(tmp_path, {"Ext/Info.plist": data})
    ats = _issues(result, "apple_ats_insecure_loads")
    # The global key is ignored on iOS 10+ when a scoped key is present: low.
    assert [(i.line, i.severity) for i in ats] == [(None, "low"), (None, "low")]
    assert "ignored on iOS 10+" in (ats[0].evidence_text or "")
    assert [i.evidence_text for i in _issues(result, "apple_custom_url_scheme")] == ["CFBundleURLSchemes: fb12345://"]


def test_two_schemes_in_one_binary_plist_stay_two(tmp_path: Path) -> None:
    data = plistlib.dumps({"CFBundleURLTypes": [{"CFBundleURLSchemes": ["one", "two"]}]}, fmt=plistlib.FMT_BINARY)
    result = _analyze(tmp_path, {"Ext/Info.plist": data})
    assert [(i.line, i.evidence_text) for i in _issues(result, "apple_custom_url_scheme")] == [
        (None, "CFBundleURLSchemes: one://"), (None, "CFBundleURLSchemes: two://"),
    ]


def test_secure_plist_has_no_issues(tmp_path: Path) -> None:
    result = _analyze(tmp_path, {"App/Info.plist": plistlib.dumps({
        "NSAppTransportSecurity": {"NSAllowsLocalNetworking": True, "NSAllowsArbitraryLoads": False},
        "CFBundleIdentifier": "x",
    }).decode()})
    assert result.app_surface_issues == []


ENTITLEMENTS = plistlib.dumps({
    "com.apple.security.cs.disable-library-validation": True,
    "com.apple.security.cs.allow-dyld-environment-variables": True,
    "com.apple.security.cs.allow-jit": True,
    "get-task-allow": True,
    "com.apple.developer.associated-domains": ["applinks:example.com", "webcredentials:example.com"],
}).decode()


def test_entitlements(tmp_path: Path) -> None:
    result = _analyze(tmp_path, {
        "App/App.entitlements": ENTITLEMENTS,
        "App/App-Debug.entitlements": ENTITLEMENTS,
    })
    runtime = _issues(result, "apple_hardened_runtime_exception")
    assert {(i.file, i.evidence_text) for i in runtime if i.file == "App/App.entitlements"} == {
        ("App/App.entitlements", "com.apple.security.cs.disable-library-validation = true"),
        ("App/App.entitlements", "com.apple.security.cs.allow-dyld-environment-variables = true"),
    }
    assert all(i.line for i in runtime)
    # get-task-allow is expected in a Debug entitlements file.
    debug = _issues(result, "apple_debuggable_entitlement")
    assert [(i.file, i.severity) for i in debug] == [("App/App.entitlements", "low")]
    links = [h for h in result.entrypoint_hints if h.hint.startswith("universal_link:")]
    assert {h.hint for h in links} == {"universal_link: applinks:example.com"}


def test_xcconfig_secrets(tmp_path: Path) -> None:
    result = _analyze(tmp_path, {"Config/Release.xcconfig": "\n".join([
        "// build settings",
        "API_KEY = sk_live_0123456789abcdef",
        "CLIENT_SECRET = $(CLIENT_SECRET_FROM_CI)",
        "STRIPE_API_KEY = YOUR_KEY_HERE",
        "CODE_SIGN_IDENTITY = Apple Distribution",
        "PROVISIONING_PROFILE_SPECIFIER = iOS App Store",
        "DEVELOPMENT_TEAM = QMQYCKL255",
        "AUTH_TOKEN[sdk=iphoneos*] = 3f9a8b7c6d5e4f3a2b1c",
        "",
    ])})
    secrets = [(s.name, s.line, s.kind) for s in result.secret_hints]
    assert secrets == [("API_KEY", 2, "xcconfig_secret"), ("AUTH_TOKEN", 8, "xcconfig_secret")]
    assert all("0123456789" not in (s.evidence_text or "") for s in result.secret_hints)


def test_cartfile_resolved_sbom(tmp_path: Path) -> None:
    result = _analyze(tmp_path, {
        "Cartfile": 'github "Alamofire/Alamofire" ~> 5.4\n',
        "Cartfile.resolved": (
            'github "Alamofire/Alamofire" "5.4.3"\n'
            'github "ReactiveX/RxSwift" "v6.2.0"\n'
            'git "https://gitlab.com/acme/Toolkit.git" "1.0.1"\n'
            'binary "https://example.com/Vendor.json" "2.0.0"\n'
        ),
    })
    deps = {d.name: d for d in result.dependencies}
    assert set(deps) == {"Alamofire/Alamofire", "ReactiveX/RxSwift", "acme/Toolkit", "Vendor"}
    assert all(d.ecosystem == "carthage" and d.resolved for d in deps.values())
    assert deps["Alamofire/Alamofire"].direct is True
    assert deps["ReactiveX/RxSwift"].direct is False
    assert deps["ReactiveX/RxSwift"].version == "6.2.0"
    assert deps["Alamofire/Alamofire"].evidence_text == "https://github.com/Alamofire/Alamofire"
    assert deps["acme/Toolkit"].evidence_text == "https://gitlab.com/acme/Toolkit.git"
    assert deps["Vendor"].evidence_text is None and deps["Vendor"].line == 4


SWIFT_SURFACE = '''import UIKit
import WebKit

final class Web {
    func search(_ term: String, key: String, safe: String) {
        webView.evaluateJavaScript("find('\\(term)')")
        webView.evaluateJavaScript("store.get('\\(key)')")
        webView.evaluateJavaScript("setZoom(\\(level))")
        webView.evaluateJavaScript("find(`\\(term.sanitizedForJavaScriptTemplateLiterals)`)")
        guard let cleaned = safe.jsEscaped else { return }
        webView.evaluateJavaScript("find('\\(cleaned)')")
        webView.evaluateJavaScript("noop()")
    }
    func store(token: Token) {
        UserDefaults.standard.set(token.accessToken, forKey: "session")
        UserDefaults(suiteName: "group.x")?.set(password, forKey: "pw")
        defaults.set(value, forKey: "refresh_token")
        UserDefaults.standard.set(deviceToken, forKey: "deviceToken")
        UserDefaults.standard.set(true, forKey: "hasPassword")
        cache.set(password, forKey: "password")
    }
    @AppStorage("authToken") var authToken: String = ""
    @AppStorage("lastTab") var lastTab: Int = 0
    func copy() {
        UIPasteboard.general.string = user.apiKey
        UIPasteboard.general.string = shareURL.absoluteString
    }
    func load(name: String) {
        let cls = NSClassFromString("Plugin\\(name)")
        let sel = NSSelectorFromString("initWithUpdateHandler:")
        let other = NSClassFromString(className)
        let handle = dlopen(path + "/lib.dylib", RTLD_NOW)
        // UserDefaults.standard.set(password, forKey: "password")
    }
}

class Listener: NSObject, NSXPCListenerDelegate {
    let listener = NSXPCListener(machServiceName: "com.example.helper")
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedObject = self
        newConnection.resume()
        return true
    }
}

class CheckedListener: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        guard isValidClient(newConnection.auditToken) else { return false }
        newConnection.resume()
        return true
    }
}
'''


def test_swift_code_surface(tmp_path: Path) -> None:
    result = _analyze(tmp_path, {"App/Web.swift": SWIFT_SURFACE})

    def lines(kind: str) -> list[tuple[int | None, str]]:
        return [(i.line, i.severity) for i in _issues(result, kind)]

    # Interpolated into a JS string: `term` (input-named) medium, `key` low. Not:
    # an unquoted number, an inline or bound sanitizer, a constant script.
    assert lines("apple_webview_js_injection") == [(6, "medium"), (7, "low")]
    assert lines("apple_insecure_secret_storage") == [(15, "medium"), (16, "medium"), (17, "medium"), (22, "medium")]
    assert lines("apple_pasteboard_secret") == [(25, "low")]
    assert lines("apple_dynamic_dispatch") == [(29, "medium"), (32, "medium")]
    assert lines("apple_xpc_unvalidated_peer") == [(39, "high")]
    assert any(h.hint == "xpc_service: mach service (NSXPCListener(machServiceName:))" and h.line == 38
               for h in result.entrypoint_hints)


def test_test_targets_are_skipped(tmp_path: Path) -> None:
    result = _analyze(tmp_path, {
        "AppTests/Fixtures/Info.plist": INFO_PLIST,
        "Tests/WebTests.swift": SWIFT_SURFACE,
    })
    assert result.app_surface_issues == []


def test_secret_names() -> None:
    assert all(is_secret_name(n) for n in ("accessToken", "API_KEY", "apiKey", "user_password", "clientSecret", "JWT"))
    assert not any(is_secret_name(n) for n in ("deviceToken", "passwordKey", "hasPassword", "tokenExpiry", "keyboard", ""))


def test_garbage_plists_and_sources_never_raise(tmp_path: Path) -> None:
    rng = random.Random(188)
    blobs: list[bytes] = [
        b"", b"bplist00", b"<plist><dict><key>NSAppTransportSecurity</key>",
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><plist><string>&a;</string></plist>',
        b"<plist>" + b"<array>" * 5000 + b"</plist>",
        plistlib.dumps({"NSAppTransportSecurity": "nope", "CFBundleURLTypes": [1, {"CFBundleURLSchemes": "x"}]}),
    ]
    blobs += [bytes(rng.randrange(256) for _ in range(rng.randint(1, 600))) for _ in range(40)]
    source = INFO_PLIST.encode()
    blobs += [source[: rng.randrange(len(source))] for _ in range(30)]
    for i, blob in enumerate(blobs):
        _write(tmp_path, f"p{i}/Info.plist", blob)
        _write(tmp_path, f"p{i}/App.entitlements", blob)
        _write(tmp_path, f"p{i}/X.xcconfig", blob.decode("latin-1"))
        _write(tmp_path, f"p{i}/Cartfile.resolved", blob.decode("latin-1"))
    for cut in range(0, len(SWIFT_SURFACE), 11):
        _write(tmp_path, f"s/Cut{cut}.swift", SWIFT_SURFACE[:cut])
    SwiftAnalyzer().analyze(tmp_path)  # must not raise


XPC_TEMPLATE = """import Foundation

class ServiceDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: MyServiceProtocol.self)
        newConnection.exportedObject = MyService()
        newConnection.resume()
        return true
    }
}

let delegate = ServiceDelegate()
let listener = NSXPCListener.service()
listener.delegate = delegate
listener.resume()
"""


def test_xpc_severity_depends_on_reachability(tmp_path: Path) -> None:
    # Apple's XPC Service template: only the parent app can connect.
    result = _analyze(tmp_path / "bundled", {"MyService/main.swift": XPC_TEMPLATE})
    (issue,) = _issues(result, "apple_xpc_unvalidated_peer")
    assert issue.severity == "low" and "bundled XPC service" in (issue.evidence_text or "")
    # A mach service in the same target: any local process can look it up.
    mach = XPC_TEMPLATE.replace("NSXPCListener.service()", 'NSXPCListener(machServiceName: "com.example.helper")')
    result = _analyze(tmp_path / "mach", {"Helper/main.swift": mach})
    assert [i.severity for i in _issues(result, "apple_xpc_unvalidated_peer")] == ["high"]
    # The listener in another file of the same target still counts.
    result = _analyze(tmp_path / "split", {
        "Helper/Delegate.swift": XPC_TEMPLATE.split("let delegate")[0],
        "Helper/main.swift": 'let listener = NSXPCListener(machServiceName: "com.example.helper")\n',
    })
    assert [i.severity for i in _issues(result, "apple_xpc_unvalidated_peer")] == ["high"]


def test_xpc_peer_validated_through_a_helper_is_not_flagged(tmp_path: Path) -> None:
    for name, check in {
        "helper-arg": "        guard isTrusted(newConnection) else { return false }\n",
        "labeled": "        guard verifier.check(connection: newConnection) else { return false }\n",
        "pid": "        let pid = newConnection.processIdentifier\n",
    }.items():
        source = XPC_TEMPLATE.replace("        newConnection.resume()\n", check + "        newConnection.resume()\n")
        source = source.replace("NSXPCListener.service()", 'NSXPCListener(machServiceName: "x")')
        result = _analyze(tmp_path / name, {"Helper/main.swift": source})
        assert _issues(result, "apple_xpc_unvalidated_peer") == [], name


def test_xpc_targets_are_finer_than_the_top_directory(tmp_path: Path) -> None:
    delegate = XPC_TEMPLATE.split("let delegate")[0]
    mach = 'let listener = NSXPCListener(machServiceName: "com.example.helper")\n'
    # Two SwiftPM targets under one Sources/: the mach service is elsewhere.
    result = _analyze(tmp_path / "spm", {"Sources/XPCSvc/Delegate.swift": delegate, "Sources/Helper/main.swift": mach})
    assert [i.severity for i in _issues(result, "apple_xpc_unvalidated_peer")] == ["low"]
    result = _analyze(tmp_path / "spm2", {"Sources/Helper/Delegate.swift": delegate, "Sources/Helper/main.swift": mach})
    assert [i.severity for i in _issues(result, "apple_xpc_unvalidated_peer")] == ["high"]
    # The delegate's own file sets up a bundled service: low despite a mach service nearby.
    result = _analyze(tmp_path / "own", {"Helper/main.swift": XPC_TEMPLATE, "Helper/Other.swift": mach})
    assert [i.severity for i in _issues(result, "apple_xpc_unvalidated_peer")] == ["low"]


def test_finalize_xpc_is_linear() -> None:
    import time

    from attackmap_analyzer_swift.apple_surface import XPC_MACH_HINT, finalize_xpc
    from attackmap.sdk import AppSurfaceIssue, EntrypointHint, ScanResult

    result = ScanResult(root=".")
    for i in range(8000):
        result.entrypoint_hints.append(EntrypointHint(hint=XPC_MACH_HINT, file=f"Mach{i}/main.swift", line=1))
        result.app_surface_issues.append(AppSurfaceIssue(
            kind="apple_xpc_unvalidated_peer", file=f"Delegate{i}/D.swift", line=1, severity="high"))
    start = time.perf_counter()
    finalize_xpc(result)
    assert time.perf_counter() - start < 1.0
    assert {i.severity for i in result.app_surface_issues} == {"low"}
