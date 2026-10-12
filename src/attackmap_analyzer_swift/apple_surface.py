"""The iOS/macOS app attack surface (AttackMap#188), shared by the Swift and
Objective-C analyzers.

Project files (any language):

- ``Info.plist`` (XML or binary, read with ``plistlib``, never executed):
  App Transport Security exceptions and ``CFBundleURLTypes`` custom URL
  schemes;
- ``*.entitlements``: hardened-runtime exceptions, ``get-task-allow``, and
  universal-link domains (``applinks:``);
- ``*.xcconfig``: hard-coded secrets in build settings;
- ``Cartfile.resolved``: the Carthage SBOM.

Swift sources: URL-scheme / universal-link handlers and XPC listeners (entry
points), WKWebView script built by interpolating into a JS string literal,
secrets written to UserDefaults or the pasteboard, XPC listeners that accept
every peer, and classes / selectors / libraries resolved from strings built at
the call site.

Every issue is a construct that is present (precision over recall). The
patterns are linear and bounded, and garbage input never raises.
"""

from __future__ import annotations

import plistlib
import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from attackmap.sdk import iter_repo_files, line_of, read_source, rel

from .contracts import AppSurfaceIssue, DependencyHint, EntrypointHint, ScanResult, SecretHint
from .swiftsrc import clip

_PLIST_MAX_BYTES = 1_000_000
_EVIDENCE_MAX = 200

# ---------- Secret-shaped names ----------

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|[_\-\s.]+")
# Name endings that hold a secret value (tokens of the split identifier).
_SECRET_TAILS = (
    ("password",), ("passwd",), ("passcode",), ("secret",), ("client", "secret"),
    ("api", "key"), ("apikey",), ("private", "key"), ("secret", "key"), ("access", "key"),
    ("access", "token"), ("refresh", "token"), ("auth", "token"), ("id", "token"),
    ("session", "token"), ("bearer", "token"), ("oauth", "token"), ("api", "token"),
    ("jwt",), ("credential",), ("credentials",),
)
# Leading words that make the name a flag or a label, not the secret itself.
_NOT_SECRET_HEADS = {"has", "is", "did", "should", "show", "can", "needs", "use", "uses", "enable", "enabled"}


def name_tokens(name: str) -> list[str]:
    return [t.lower() for t in _CAMEL.split(name.strip()) if t]


def is_secret_name(name: str) -> bool:
    """`accessToken`, `user_password`, `API_KEY` -> True; `deviceToken`,
    `passwordKey`, `hasPassword`, `tokenExpiry` -> False."""
    tokens = name_tokens(name)
    if not tokens or len(tokens) > 8 or tokens[0] in _NOT_SECRET_HEADS:
        return False
    return any(tuple(tokens[-len(tail):]) == tail for tail in _SECRET_TAILS)


# ---------- Info.plist ----------

_SCHEME_HINT = "url_scheme: "
_ATS_GLOBAL = "NSAllowsArbitraryLoads"
_ATS_SCOPED = ("NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia", "NSAllowsLocalNetworking")
_TLS_WEAK = {"TLSv1.0", "TLSv1.1"}


def _key_line(text: str | None, *keys: str) -> int | None:
    """Line of the last of ``keys``, found in order (`<key>A</key>` ... `<key>B</key>`)."""
    if not text:
        return None
    pos = 0
    found = -1
    for key in keys:
        found = text.find(f"<key>{key}</key>", pos)
        if found < 0:
            return None
        pos = found + 1
    return line_of(text, found)


def _string_line(text: str | None, after_key: str, value: str) -> int | None:
    if not text:
        return None
    start = text.find(f"<key>{after_key}</key>")
    if start < 0:
        return None
    found = text.find(f"<string>{value}</string>", start)
    return line_of(text, found) if found >= 0 else None


def _load_plist(path: Path) -> tuple[object | None, str | None]:
    """(parsed plist, XML text or None for binary); (None, None) on any failure."""
    try:
        data = path.read_bytes()
    except OSError:
        return None, None
    if len(data) > _PLIST_MAX_BYTES:
        return None, None
    try:
        parsed = plistlib.loads(data)
    except Exception:  # malformed / hostile plist: skip it, never fail the scan
        return None, None
    text = None
    if not data.startswith(b"bplist"):
        text = data.decode("utf-8", errors="replace")
    return parsed, text


def _is_true(value: object) -> bool:
    return value is True


def analyze_info_plist(rel_path: str, parsed: object, text: str | None, result: ScanResult) -> None:
    """ATS exceptions and custom URL schemes (as entry points)."""
    if not isinstance(parsed, dict):
        return
    ats = parsed.get("NSAppTransportSecurity")
    if isinstance(ats, dict):
        scoped = [k for k in _ATS_SCOPED if k in ats]
        if _is_true(ats.get(_ATS_GLOBAL)):
            if scoped:
                # iOS 10+/macOS 10.12+ ignore NSAllowsArbitraryLoads when a scoped key is present.
                severity, note = "low", f" (ignored on iOS 10+ because {scoped[0]} is set)"
            else:
                severity, note = "medium", ""
            result.app_surface_issues.append(AppSurfaceIssue(
                kind="apple_ats_insecure_loads", file=rel_path,
                line=_key_line(text, "NSAppTransportSecurity", _ATS_GLOBAL), severity=severity,
                evidence_text=f"NSAppTransportSecurity.{_ATS_GLOBAL} = true{note}",
            ))
        for key in ("NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia"):
            if _is_true(ats.get(key)):
                result.app_surface_issues.append(AppSurfaceIssue(
                    kind="apple_ats_insecure_loads", file=rel_path, severity="low",
                    line=_key_line(text, "NSAppTransportSecurity", key),
                    evidence_text=f"NSAppTransportSecurity.{key} = true",
                ))
        domains = ats.get("NSExceptionDomains")
        if isinstance(domains, dict):
            for domain, settings in list(domains.items())[:200]:
                if not isinstance(settings, dict):
                    continue
                reasons = [
                    k for k in ("NSExceptionAllowsInsecureHTTPLoads", "NSTemporaryExceptionAllowsInsecureHTTPLoads",
                                "NSThirdPartyExceptionAllowsInsecureHTTPLoads")
                    if _is_true(settings.get(k))
                ]
                tls = settings.get("NSExceptionMinimumTLSVersion") or settings.get("NSTemporaryExceptionMinimumTLSVersion")
                if isinstance(tls, str) and tls in _TLS_WEAK:
                    reasons.append(f"NSExceptionMinimumTLSVersion = {tls}")
                if not reasons:
                    continue
                result.app_surface_issues.append(AppSurfaceIssue(
                    kind="apple_ats_insecure_loads", file=rel_path, severity="low",
                    line=_key_line(text, "NSExceptionDomains", str(domain)),
                    evidence_text=clip(f"NSExceptionDomains.{domain}: {', '.join(reasons)}", _EVIDENCE_MAX),
                ))
    url_types = parsed.get("CFBundleURLTypes")
    if isinstance(url_types, list):
        for entry in url_types[:50]:
            if not isinstance(entry, dict):
                continue
            for scheme in (entry.get("CFBundleURLSchemes") or [])[:20] if isinstance(entry.get("CFBundleURLSchemes"), list) else []:
                if not isinstance(scheme, str) or not scheme.strip() or scheme.lower() in ("http", "https"):
                    continue
                line = _string_line(text, "CFBundleURLSchemes", scheme)
                result.entrypoint_hints.append(EntrypointHint(
                    hint=f"{_SCHEME_HINT}{clip(scheme, 80)}://", file=rel_path, line=line,
                    evidence_text="CFBundleURLTypes.CFBundleURLSchemes", confidence=0.95,
                ))


# ---------- Entitlements ----------

_HARDENED_RUNTIME = (
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-executable-page-protection",
)
_DEBUG_ENTITLEMENTS = ("get-task-allow", "com.apple.security.get-task-allow")
_DEBUG_NAME = re.compile(r"(?i)debug|develop|\bdev\b")


def analyze_entitlements(rel_path: str, parsed: object, text: str | None, result: ScanResult) -> None:
    if not isinstance(parsed, dict):
        return
    for key in _HARDENED_RUNTIME:
        if _is_true(parsed.get(key)):
            result.app_surface_issues.append(AppSurfaceIssue(
                kind="apple_hardened_runtime_exception", file=rel_path, line=_key_line(text, key),
                severity="medium", evidence_text=f"{key} = true",
            ))
    # Xcode adds get-task-allow to Debug builds itself; a Debug-only file is expected.
    if not _DEBUG_NAME.search(posixpath.basename(rel_path)):
        for key in _DEBUG_ENTITLEMENTS:
            if _is_true(parsed.get(key)):
                result.app_surface_issues.append(AppSurfaceIssue(
                    kind="apple_debuggable_entitlement", file=rel_path, line=_key_line(text, key),
                    severity="low", evidence_text=f"{key} = true",
                ))
    domains = parsed.get("com.apple.developer.associated-domains")
    if isinstance(domains, list):
        for domain in domains[:100]:
            if isinstance(domain, str) and domain.startswith("applinks:"):
                result.entrypoint_hints.append(EntrypointHint(
                    hint=f"universal_link: {clip(domain, 120)}", file=rel_path,
                    line=_string_line(text, "com.apple.developer.associated-domains", domain),
                    evidence_text="com.apple.developer.associated-domains", confidence=0.95,
                ))


# ---------- xcconfig ----------

_XCCONFIG_SETTING = re.compile(r"^[ \t]*([A-Za-z_][A-Za-z0-9_]{0,120})(?:\[[^\]\n]{0,120}\])?[ \t]*=[ \t]*([^\n]{0,500})$", re.MULTILINE)
_PLACEHOLDER = re.compile(r"(?i)^(?:your|my|<|\[|\{|x{3,}|\*{3,}|\.{3}|todo|changeme|change_me|placeholder|example|dummy|test|none|null|nil|false|true|yes|no)")


def analyze_xcconfig(rel_path: str, text: str, result: ScanResult) -> None:
    for m in _XCCONFIG_SETTING.finditer(text):
        key, raw = m.group(1), m.group(2)
        value = raw.split("//", 1)[0].strip().strip('"')
        if not is_secret_name(key) or len(value) < 8 or "$(" in value or "${" in value:
            continue
        if _PLACEHOLDER.match(value) or value.isdigit() or " " in value:
            continue
        masked = value[:4] + "…"
        result.secret_hints.append(SecretHint(
            name=key, file=rel_path, line=line_of(text, m.start()), confidence=0.8,
            kind="xcconfig_secret", evidence_text=f"{key} = {masked}",
        ))


# ---------- Cartfile.resolved ----------

_CARTFILE_LINE = re.compile(r'^[ \t]*(github|git|binary)[ \t]+"([^"\n]{1,300})"[ \t]+"([^"\n]{1,100})"', re.MULTILINE)
# Cartfile (not resolved): the version requirement is optional and unquoted.
_CARTFILE_DEP = re.compile(r'^[ \t]*(github|git|binary)[ \t]+"([^"\n]{1,300})"', re.MULTILINE)
_SEMVER_V = re.compile(r"^v(?=\d)")


def _carthage_identity(kind: str, origin: str) -> tuple[str, str | None]:
    """(name, repository URL) for one Cartfile origin."""
    if kind == "github":
        if "://" in origin:
            url = origin.rstrip("/")
            name = "/".join(url.split("/")[-2:])
        else:
            name = origin.strip("/")
            url = f"https://github.com/{name}"
        return name.removesuffix(".git"), url.removesuffix(".git")
    if kind == "git":
        tail = origin.rstrip("/").removesuffix(".git").split("/")
        name = "/".join(tail[-2:]) if len(tail) >= 2 else tail[-1]
        return name.split(":")[-1], origin
    return posixpath.basename(origin).removesuffix(".json"), None  # binary: not a repository


def analyze_cartfile(rel_path: str, resolved: str, cartfile: str | None, result: ScanResult) -> None:
    direct = {(m.group(1), m.group(2)) for m in _CARTFILE_DEP.finditer(cartfile or "")}
    direct_names = {_carthage_identity(k, o)[0] for k, o in direct}
    for m in _CARTFILE_LINE.finditer(resolved):
        kind, origin, version = m.group(1), m.group(2), m.group(3)
        name, url = _carthage_identity(kind, origin)
        if not name:
            continue
        result.dependencies.append(DependencyHint(
            name=name, version=_SEMVER_V.sub("", version), ecosystem="carthage", file=rel_path,
            line=line_of(resolved, m.start()), resolved=True,
            direct=(name in direct_names) if cartfile is not None else True,
            evidence_text=url, source_analyzer="swift",
        ))


# ---------- Project walk ----------

def analyze_project_files(root: Path, result: ScanResult, skip_dirs: Iterable[str], *, is_test) -> None:
    """Info.plist, entitlements, xcconfig and Cartfile.resolved."""
    cartfiles: dict[str, str] = {}
    resolved: list[tuple[str, str]] = []
    for path in iter_repo_files(
        root, suffixes={".plist", ".entitlements", ".xcconfig"}, names={"Cartfile", "Cartfile.resolved"},
        skip_dirs=set(skip_dirs),
    ):
        rel_path = rel(path, root)
        if is_test(rel_path):
            continue
        if path.name in ("Cartfile", "Cartfile.resolved"):
            text = read_source(path)
            if text is None:
                continue
            if path.name == "Cartfile":
                cartfiles[posixpath.dirname(rel_path)] = text
            else:
                resolved.append((rel_path, text))
        elif path.suffix == ".xcconfig":
            text = read_source(path)
            if text is not None:
                analyze_xcconfig(rel_path, text, result)
        elif path.suffix == ".entitlements":
            parsed, text = _load_plist(path)
            analyze_entitlements(rel_path, parsed, text, result)
        elif path.name.endswith("Info.plist"):
            parsed, text = _load_plist(path)
            analyze_info_plist(rel_path, parsed, text, result)
    for rel_path, text in resolved:
        analyze_cartfile(rel_path, text, cartfiles.get(posixpath.dirname(rel_path)), result)


# ---------- Swift sources ----------

@dataclass
class Handler:
    hint: str
    file: str
    line: int


_URL_HANDLERS = re.compile(
    r"\bfunc[ \t]+application[ \t]*\([^)]{0,200}\bopen[ \t]+(?:url|urls)[ \t]*:"
    r"|\bfunc[ \t]+scene[ \t]*\([^)]{0,200}\bopenURLContexts\b"
    r"|\.onOpenURL[ \t]*(?:\(|\{)"
    r"|\bhandleGetURLEvent\b"
)
_UNIVERSAL_LINK_HANDLERS = re.compile(
    r"\bfunc[ \t]+(?:application|scene)[ \t]*\([^)]{0,200}\bcontinue[ \t]+userActivity\b"
    r"|\.onContinueUserActivity[ \t]*\([ \t]*NSUserActivityTypeBrowsingWeb"
)
_XPC_MACH_LISTENER = re.compile(r"\bNSXPCListener[ \t]*\([ \t]*machServiceName[ \t]*:")
_XPC_LOCAL_LISTENER = re.compile(r"\bNSXPCListener[ \t]*\.[ \t]*(service|anonymous)[ \t]*\(")
_XPC_ACCEPT = re.compile(
    r"\bfunc[ \t]+listener[ \t]*\([^)]{0,200}\bshouldAcceptNewConnection[ \t]+(\w{1,60})[ \t]*:[^{]{0,200}\{"
)
XPC_MACH_HINT = "xpc_service: mach service (NSXPCListener(machServiceName:))"
_XPC_PEER_CHECK = re.compile(
    r"(?i)auditToken|processIdentifier|effectiveUserIdentifier|effectiveGroupIdentifier|CodeSigningRequirement"
    r"|\bSecCode|\bSecStaticCode|\bSecRequirement|\bSecTask|kSecGuestAttribute"
    r"|(?:valid|verif|authoriz|authentic|trust)\w{0,40}[ \t]*\("
)
_RETURN_TRUE = re.compile(r"\breturn[ \t]+true\b")

_EVAL_JS = re.compile(r"\.[ \t]*evaluateJavaScript[ \t]*\(")
_SET_CALL = re.compile(r"\.[ \t]*(?:set|setValue)[ \t]*\(")
# What sits between `...Defaults` and `.set(`: `.standard`, `(suiteName: "x")?`, ...
_DEFAULTS_RECEIVER_TAIL = re.compile(r"\w{0,40}(?:\([^()\n]{0,120}\))?[?!]?(?:\.\w{1,40}){0,3}[ \t]*")
_APP_STORAGE = re.compile(r'@AppStorage[ \t]*\([ \t]*"([^"\n]{1,120})"')
_PASTEBOARD_SET = re.compile(
    r"\b(?:UIPasteboard|NSPasteboard)[ \t]*\.[ \t]*general[ \t]*\.[ \t]*"
    r"(?:(?:string|url)[ \t]*=[ \t]*([^\n;]{1,200})|set(?:String|Value)[ \t]*\(([^\n]{1,200}))"
)
_DYNAMIC = re.compile(r"\b(NSClassFromString|NSSelectorFromString|dlopen)[ \t]*\(")
_BUILT_STRING = re.compile(r'\\\(|"[ \t]*\+|\+[ \t]*"|String[ \t]*\([ \t]*format[ \t]*:|\.appending\(|stringWithFormat')
_SIMPLE_EXPR = re.compile(r"[\w.?!]{1,200}")
_EXPR_SEP = re.compile(r"[.?!]+")
_SANITIZED = re.compile(r"(?i)saniti|escap|encod|json|quoted|jsString|jsLiteral|jsonString")


def xpc_peer_checked(body: str, connection: str) -> bool:
    """True when the accept body checks the peer: audit token / PID /
    code-signing APIs, a validate/verify/... helper call, or any call the
    connection is passed to (`isTrusted(newConnection)`, `[self check:conn]`)
    rather than called on (`newConnection.resume()`)."""
    if _XPC_PEER_CHECK.search(body):
        return True
    if not connection.isidentifier():
        return False
    at = body.find(connection)
    for _ in range(200):
        if at < 0:
            return False
        end = at + len(connection)
        before = body[max(0, at - 1)]
        after = body[end] if end < len(body) else ""
        if (at == 0 or not (before.isalnum() or before == "_")) and not (after.isalnum() or after == "_"):
            j = at - 1
            while j >= 0 and body[j] in " \t\n":
                j -= 1
            k = end
            while k < len(body) and body[k] in " \t\n":
                k += 1
            passed_in = j >= 0 and body[j] in "(,:" and not (k < len(body) and body[k] == ".")
            if passed_in:
                return True
        at = body.find(connection, end)
    return False


def finalize_xpc(result: ScanResult) -> None:
    """An XPC listener delegate is high only when a mach service
    (`NSXPCListener(machServiceName:)`) is registered in the same file or
    target (top-level directory): any local process can look one up. A
    bundled XPC service or an anonymous listener is reachable only by its
    parent app or an endpoint holder, so the issue drops to low."""
    mach = [h.file for h in result.entrypoint_hints if h.hint == XPC_MACH_HINT]

    def target(path: str) -> str:
        return path.split("/", 1)[0] if "/" in path else ""

    for issue in result.app_surface_issues:
        if issue.kind != "apple_xpc_unvalidated_peer" or issue.severity != "high":
            continue
        if any(f == issue.file or (target(f) and target(f) == target(issue.file)) for f in mach):
            continue
        issue.severity = "low"
        issue.evidence_text = (issue.evidence_text or "") + (
            "; no NSXPCListener(machServiceName:) in this target, so likely a bundled XPC service or "
            "anonymous listener reachable only by its parent app"
        )


def _ident_name(expr: str) -> str | None:
    """Last identifier of a simple expression (`self.user.accessToken` -> `accessToken`)."""
    expr = expr.strip()
    if not _SIMPLE_EXPR.fullmatch(expr):
        return None
    parts = [p for p in _EXPR_SEP.split(expr) if p]
    if not parts or not (parts[-1][0].isalpha() or parts[-1][0] == "_"):
        return None
    return parts[-1]


def _is_defaults_receiver(text: str, dot: int) -> bool:
    """`UserDefaults.standard.set(`, `defaults.set(`, `UserDefaults(suiteName: x)?.set(`."""
    window = text[max(0, dot - 200):dot]
    at = window.rfind("efaults")
    if at < 0 or (at > 0 and not window[at - 1] in "Dd"):
        return False
    return _DEFAULTS_RECEIVER_TAIL.fullmatch(window, at + len("efaults")) is not None


def _call_args(text: str, open_paren: int, limit: int = 2000) -> str | None:
    """Text inside the parentheses opening at ``open_paren`` (strings respected)."""
    depth = 0
    i = open_paren
    end = min(len(text), open_paren + limit)
    in_str = False
    while i < end:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:i]
        i += 1
    return None


def _swift_interpolations_in_js_quotes(literal: str) -> list[str]:
    """Interpolated expressions that sit inside a JS string literal ('…', "…",
    `…`) in the Swift string ``literal`` (the text between its quotes)."""
    out: list[str] = []
    quote: str | None = None
    i = 0
    n = len(literal)
    while i < n:
        ch = literal[i]
        if ch == "\\" and i + 1 < n:
            nxt = literal[i + 1]
            if nxt == "(":
                depth = 0
                j = i + 1
                while j < n:
                    if literal[j] == "(":
                        depth += 1
                    elif literal[j] == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                if quote is not None:
                    out.append(literal[i + 2:j])
                i = j + 1
                continue
            if nxt == '"':  # \" is a JS double quote inside the Swift string
                quote = None if quote == '"' else (quote or '"')
            i += 2
            continue
        if ch in "'`":
            quote = None if quote == ch else (quote or ch)
        i += 1
    return out


def js_injection_exprs(values: Iterable[str], before: str = "") -> list[str]:
    """The interpolated values that aren't visibly encoded for JavaScript,
    either inline (`\\(term.jsEscaped)`) or where the local was bound
    (`guard let term = raw?.sanitizedForJavaScript`, found in ``before``)."""
    out = []
    for value in values:
        if not value.strip() or _SANITIZED.search(value):
            continue
        name = _ident_name(value)
        if name and _bound_sanitized(name, before):
            continue
        out.append(value)
    return out


def _bound_sanitized(name: str, before: str) -> bool:
    """True when the nearest `let/var name = ...` in ``before`` encodes the value."""
    best = -1
    for keyword in ("let ", "var "):
        at = before.rfind(keyword + name)
        while at >= 0:
            end = at + len(keyword) + len(name)
            if end >= len(before) or not (before[end].isalnum() or before[end] == "_"):
                best = max(best, at)
                break
            at = before.rfind(keyword + name, 0, at)
    if best < 0:
        return False
    line_end = before.find("\n", best)
    return bool(_SANITIZED.search(before[best:line_end if line_end >= 0 else len(before)]))


# Names that suggest the value comes from the user, the page, a URL or a message.
_INPUT_NAME = re.compile(
    r"(?i)query|param|url|uri|fragment|anchor|term|search|input|text|message|msg|payload|body|title|name|user|"
    r"link|path|href|html|content|value|data|callback"
)


def js_injection_severity(values: Iterable[str]) -> str:
    """`medium` when an interpolated value is named like external data, else `low`."""
    return "medium" if any(_INPUT_NAME.search(v) for v in values) else "low"


def analyze_swift_source(rel_path: str, text: str, result: ScanResult, handlers: list[Handler]) -> None:
    from .swiftsrc import parse

    src = parse(text)

    def code(offset: int) -> bool:
        return not src.in_masked(offset)

    def snippet(offset: int) -> str:
        start = text.rfind("\n", 0, offset) + 1
        end = text.find("\n", offset)
        return clip(text[start:end if end >= 0 else len(text)], _EVIDENCE_MAX)

    for m in _URL_HANDLERS.finditer(text):
        if code(m.start()):
            handlers.append(Handler("url_scheme_handler", rel_path, line_of(text, m.start())))
            result.entrypoint_hints.append(EntrypointHint(
                hint="url_scheme_handler (opens URLs from other apps)", file=rel_path,
                line=line_of(text, m.start()), evidence_text=snippet(m.start()), confidence=0.9,
            ))
    for m in _UNIVERSAL_LINK_HANDLERS.finditer(text):
        if code(m.start()):
            result.entrypoint_hints.append(EntrypointHint(
                hint="universal_link_handler (continue userActivity)", file=rel_path,
                line=line_of(text, m.start()), evidence_text=snippet(m.start()), confidence=0.8,
            ))
    for m in _XPC_MACH_LISTENER.finditer(text):
        if code(m.start()):
            result.entrypoint_hints.append(EntrypointHint(
                hint=XPC_MACH_HINT, file=rel_path, line=line_of(text, m.start()),
                evidence_text=snippet(m.start()), confidence=0.9,
            ))
    for m in _XPC_LOCAL_LISTENER.finditer(text):
        if code(m.start()):
            kind = "bundled XPC service" if m.group(1) == "service" else "anonymous listener"
            result.entrypoint_hints.append(EntrypointHint(
                hint=f"xpc_service: {kind} (NSXPCListener.{m.group(1)}())", file=rel_path,
                line=line_of(text, m.start()), evidence_text=snippet(m.start()), confidence=0.9,
            ))
    for m in _XPC_ACCEPT.finditer(text):
        brace = m.end() - 1
        close = src.close_of(brace)
        if close < 0 or not code(m.start()):
            continue
        body = text[brace:close]
        if _RETURN_TRUE.search(body) and not xpc_peer_checked(body, m.group(1)):
            result.app_surface_issues.append(AppSurfaceIssue(
                kind="apple_xpc_unvalidated_peer", file=rel_path, line=line_of(text, m.start()), severity="high",
                evidence_text="listener(_:shouldAcceptNewConnection:) returns true without checking the peer's audit token or code signature",
            ))

    # WKWebView: a value interpolated into a JS string literal.
    for m in _EVAL_JS.finditer(text):
        if not code(m.start()):
            continue
        args = _call_args(text, m.end() - 1)
        if not args:
            continue
        first = args.lstrip()
        if not first.startswith('"') or first.startswith('"""'):
            continue
        end = _swift_string_end(first)
        if end < 0:
            continue
        exprs = js_injection_exprs(_swift_interpolations_in_js_quotes(first[1:end]), text[max(0, m.start() - 4000):m.start()])
        if exprs:
            result.app_surface_issues.append(AppSurfaceIssue(
                kind="apple_webview_js_injection", file=rel_path, line=line_of(text, m.start()),
                severity=js_injection_severity(exprs),
                evidence_text=clip(f"{snippet(m.start())} [interpolated: {', '.join(e.strip() for e in exprs[:3])}]", _EVIDENCE_MAX),
            ))

    # UserDefaults: a secret-named value or key.
    for m in _SET_CALL.finditer(text):
        if not code(m.start()) or not _is_defaults_receiver(text, m.start()):
            continue
        args = _call_args(text, m.end() - 1)
        if args is None or "forKey" not in args:
            continue
        value, _, key = args.partition("forKey")
        key = key.lstrip(" \t:").strip()
        value = value.rstrip(" \t,")
        key_literal = key[1:-1] if len(key) > 2 and key[0] == key[-1] == '"' else None
        value_name = _ident_name(value)
        if (key_literal and is_secret_name(key_literal)) or (value_name and is_secret_name(value_name)):
            _add_unique(result, AppSurfaceIssue(
                kind="apple_insecure_secret_storage", file=rel_path, line=line_of(text, m.start()), severity="medium",
                evidence_text=snippet(m.start()),
            ))
    for m in _APP_STORAGE.finditer(text):
        if code(m.start()) and is_secret_name(m.group(1)):
            _add_unique(result, AppSurfaceIssue(
                kind="apple_insecure_secret_storage", file=rel_path, line=line_of(text, m.start()), severity="medium",
                evidence_text=snippet(m.start()),
            ))

    # Pasteboard: a secret-named value copied to the general pasteboard.
    for m in _PASTEBOARD_SET.finditer(text):
        if not code(m.start()):
            continue
        value = m.group(1) if m.group(1) is not None else (m.group(2) or "").split(",", 1)[0]
        name = _ident_name(value)
        if name and is_secret_name(name):
            result.app_surface_issues.append(AppSurfaceIssue(
                kind="apple_pasteboard_secret", file=rel_path, line=line_of(text, m.start()), severity="low",
                evidence_text=snippet(m.start()),
            ))

    # Dynamic dispatch on a string built at the call site.
    for m in _DYNAMIC.finditer(text):
        if not code(m.start()):
            continue
        args = _call_args(text, m.end() - 1)
        if args is None:
            continue
        arg = args.split(",", 1)[0] if m.group(1) == "dlopen" else args
        if _BUILT_STRING.search(arg):
            result.app_surface_issues.append(AppSurfaceIssue(
                kind="apple_dynamic_dispatch", file=rel_path, line=line_of(text, m.start()), severity="medium",
                evidence_text=snippet(m.start()),
            ))


def _swift_string_end(text: str) -> int:
    """Index of the closing quote of the Swift string literal starting at text[0]."""
    i = 1
    n = len(text)
    depth = 0
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            if text[i + 1] == "(":
                depth += 1
                i += 2
                continue
            i += 2
            continue
        if depth:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == '"':
                # a string inside an interpolation: skip it
                close = text.find('"', i + 1)
                if close < 0:
                    return -1
                i = close
        elif ch == '"':
            return i
        elif ch == "\n":
            return -1
        i += 1
    return -1


def _add_unique(result: ScanResult, issue: AppSurfaceIssue) -> None:
    for existing in result.app_surface_issues:
        if (existing.kind, existing.file, existing.line, existing.evidence_text) == (
            issue.kind, issue.file, issue.line, issue.evidence_text
        ):
            return
    result.app_surface_issues.append(issue)


def report_url_schemes(result: ScanResult, handlers: list[Handler]) -> None:
    """One `apple_custom_url_scheme` issue per scheme declared in an
    Info.plist. The handlers that open the URLs are entry points of their own;
    they aren't folded into the evidence, so the Swift and Objective-C
    analyzers report the same issue and core's merge keeps one."""
    for hint in list(result.entrypoint_hints):
        if not hint.hint.startswith(_SCHEME_HINT):
            continue
        scheme = hint.hint[len(_SCHEME_HINT):]
        _add_unique(result, AppSurfaceIssue(
            kind="apple_custom_url_scheme", file=hint.file, line=hint.line, severity="low",
            evidence_text=clip(f"CFBundleURLSchemes: {scheme}", _EVIDENCE_MAX),
        ))


__all__ = [
    "analyze_cartfile",
    "analyze_entitlements",
    "analyze_info_plist",
    "analyze_project_files",
    "analyze_swift_source",
    "analyze_xcconfig",
    "is_secret_name",
    "js_injection_exprs",
    "report_url_schemes",
]
