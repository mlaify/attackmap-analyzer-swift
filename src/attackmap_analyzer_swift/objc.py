"""Objective-C / Objective-C++ analyzer (AttackMap#190), the package's second
analyzer entry point (``objc``). It shares the iOS/macOS surface model with the
Swift analyzer (``apple_surface.py``): the same project-file checks
(Info.plist, entitlements, xcconfig, Cartfile.resolved) and the same issue
kinds, applied to ``.m`` / ``.mm`` sources:

- entry points: URL-scheme handlers (``application:openURL:options:``,
  ``application:handleOpenURL:``, ``scene:openURLContexts:``,
  ``handleGetURLEvent:withReplyEvent:``), universal-link handlers
  (``application:continueUserActivity:...``) and ``NSXPCListener`` services;
- ``evaluateJavaScript:`` / ``stringByEvaluatingJavaScriptFromString:`` with a
  ``stringWithFormat:`` whose ``%@`` sits inside a JS string literal and whose
  argument isn't visibly encoded;
- secret-named values or keys written to ``NSUserDefaults`` or the general
  pasteboard;
- an XPC ``listener:shouldAcceptNewConnection:`` that returns ``YES`` without
  checking the peer;
- ``NSClassFromString`` / ``NSSelectorFromString`` / ``dlopen`` on a string
  built at the call site;
- native weaknesses shared with the C/C++ plugins (``CodeWeakness``): a
  non-literal, non-localized format string with no arguments
  (``[NSString stringWithFormat:msg]``, ``NSLog(msg)``) and a shell command
  built at runtime (``/bin/sh -c`` with a non-literal command, ``system()`` /
  ``popen()`` on a non-literal).

``NSFileManager`` / ``NSURL`` file sinks aren't reported: without a taint
pass for Objective-C they'd be guesses (precision over recall).
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

from attackmap.sdk import iter_repo_files, line_of, read_source, rel

from . import apple_surface
from .analyzer import SKIP_DIRS, _is_test_path
from .apple_surface import Handler, is_secret_name, js_injection_exprs, js_injection_severity
from .contracts import AnalyzerMetadata, AppSurfaceIssue, CodeWeakness, EntrypointHint, ScanResult
from .swiftsrc import Source, clip

OBJC_SUFFIXES = {".m", ".mm"}
_EVIDENCE_MAX = 200
# An Objective-C file, not MATLAB/Octave/Mercury `.m`.
_OBJC_MARKER = re.compile(r"@(?:implementation|interface|protocol|end)\b|^[ \t]*#import\b", re.MULTILINE)


# ---------- C-family masking (strings, chars, comments) and brackets ----------

_TOKEN = re.compile(r'//|/\*|@?"|\'|[()\[\]{}]')
_STRING_BODY = re.compile(r'(?:[^"\\\n]|\\.)*"?')
_CHAR_BODY = re.compile(r"(?:[^'\\\n]|\\.){0,10}'?")
_OPEN_TO_CLOSE = {"(": ")", "[": "]", "{": "}"}


@functools.lru_cache(maxsize=8)
def parse(text: str) -> Source:
    src = Source(text)
    stack: list[tuple[str, int]] = []
    pos = 0
    n = len(text)
    while pos < n:
        m = _TOKEN.search(text, pos)
        if m is None:
            break
        tok, start = m.group(0), m.start()
        if tok == "//":
            end = text.find("\n", start)
            end = n if end < 0 else end
            src.masked.append((start, end))
        elif tok == "/*":
            end = text.find("*/", start + 2)
            end = n if end < 0 else end + 2
            src.masked.append((start, end))
        elif tok.endswith('"'):
            end = _STRING_BODY.match(text, m.end()).end()
            src.masked.append((start, end))
            src.strings.append((start, end))
        elif tok == "'":
            end = _CHAR_BODY.match(text, m.end()).end()
            src.masked.append((start, end))
        elif tok in _OPEN_TO_CLOSE:
            stack.append((tok, start))
            end = m.end()
        else:
            for depth in range(len(stack) - 1, max(-1, len(stack) - 8), -1):
                if _OPEN_TO_CLOSE[stack[depth][0]] == tok:
                    open_at = stack[depth][1]
                    del stack[depth:]
                    src.pairs[open_at] = start
                    src.rpairs[start] = open_at
                    break
            end = m.end()
        pos = max(end, start + 1)
    src._starts = [s for s, _ in src.masked]
    return src


def _enclosing_bracket(src: Source, offset: int) -> tuple[int, int] | None:
    """The innermost `[...]` message send containing ``offset``."""
    text = src.text
    i = offset
    lo = max(0, offset - 2000)
    while i > lo:
        i -= 1
        ch = text[i]
        if ch in ")]}":
            open_ = src.open_of(i)
            if open_ >= 0:
                i = open_
            continue
        if ch == "[" and not src.in_masked(i):
            close = src.close_of(i)
            if close > offset:
                return (i, close)
    return None


# ---------- Patterns ----------

_URL_HANDLER_DEF = re.compile(
    r"^[ \t]*-[ \t]*\([ \t]*(?:BOOL|void)[ \t]*\)[ \t]*(?:application[ \t]*:[^{;]{0,300}?\b(?:openURL|handleOpenURL)[ \t]*:"
    r"|scene[ \t]*:[^{;]{0,200}?\bopenURLContexts[ \t]*:|handleGetURLEvent[ \t]*:)",
    re.MULTILINE,
)
_UNIVERSAL_LINK_DEF = re.compile(
    r"^[ \t]*-[ \t]*\([ \t]*BOOL[ \t]*\)[ \t]*application[ \t]*:[^{;]{0,300}?\bcontinueUserActivity[ \t]*:",
    re.MULTILINE,
)
_XPC_MACH_LISTENER = re.compile(r"\bNSXPCListener[ \t]+alloc[ \t]*\][ \t]*initWithMachServiceName[ \t]*:")
_XPC_LOCAL_LISTENER = re.compile(r"\[[ \t]*NSXPCListener[ \t]+(serviceListener|anonymousListener)[ \t]*\]")
_XPC_ACCEPT = re.compile(
    r"^[ \t]*-[ \t]*\([ \t]*BOOL[ \t]*\)[ \t]*listener[ \t]*:[^{;]{0,200}?\bshouldAcceptNewConnection[ \t]*:"
    r"[ \t]*\([^)\n]{0,80}\)[ \t]*(\w{1,60})[^{;]{0,200}\{",
    re.MULTILINE,
)
_RETURN_YES = re.compile(r"\breturn[ \t]+(?:YES|true)\b")

_EVAL_JS = re.compile(r"\b(?:evaluateJavaScript|stringByEvaluatingJavaScriptFromString)[ \t]*:[ \t]*\[[ \t]*NSString[ \t]+stringWithFormat[ \t]*:[ \t]*@\"")
_FORMAT_SPEC = re.compile(r"%(?:%|[-+ #0]{0,4}\d{0,4}(?:\.\d{1,4})?(?:hh|h|ll|l|q|z|t|j|L)?([@dDiuUxXoOfFeEgGcCsSpaA]))")

_DEFAULTS_VAR = re.compile(r"\bNSUserDefaults[ \t]*\*[ \t]*(\w{1,60})[ \t]*=")
_PASTEBOARD_VAR = re.compile(r"\b(?:UIPasteboard|NSPasteboard)[ \t]*\*[ \t]*(\w{1,60})[ \t]*=")
_SET_FOR_KEY = re.compile(
    r"\[[ \t]*(\[[^\[\]\n]{1,120}\]|[\w.]{1,120})[ \t]+set(?:Object|Value)[ \t]*:[ \t]*"
    r"(\[[^\[\]\n]{1,160}\]|[^\s\[\]]{1,160})[ \t]+forKey[ \t]*:[ \t]*(@\"[^\"\n]{0,120}\"|[\w.]{1,120})[ \t]*\]"
)
_PASTEBOARD_SET = re.compile(
    r"(\[[ \t]*(?:UIPasteboard|NSPasteboard)[ \t]+generalPasteboard[ \t]*\]|(?:UIPasteboard|NSPasteboard)\.generalPasteboard|\b\w{1,60})"
    r"(?:[ \t]*\.[ \t]*string[ \t]*=[ \t]*([^;\n]{1,160});|[ \t]+setString[ \t]*:[ \t]*([^\s\]]{1,160}))"
)
_DYNAMIC = re.compile(r"\b(NSClassFromString|NSSelectorFromString|dlopen)[ \t]*\(")
_BUILT_STRING = re.compile(r"stringWithFormat|initWithFormat|stringByAppending|\+[ \t]*@?\"")

_FORMAT_CALL = re.compile(
    r"\b(?:stringWithFormat|initWithFormat|appendFormat|stringByAppendingFormat|localizedStringWithFormat)[ \t]*:"
)
_NSLOG = re.compile(r"\bNSLog[ \t]*\(")
_LOCALIZED = re.compile(r"(?i)locali[sz]ed|\bNSLocalizedString|WMFLocalized")
# `initWithFormat:fmt arguments:va` / `locale:` forward a format the caller built.
_FORWARDED_FORMAT = re.compile(r"\b(?:arguments|locale)[ \t]*:")

_SHELL_PATH = re.compile(r'@"/(?:usr/)?bin/(?:ba|z|k|da)?sh"')
_SHELL_ARGS = re.compile(r'@\[[ \t]*@"-c"[ \t]*,[ \t]*([^\]\n]{1,200})\]')
_SYSTEM_CALL = re.compile(r"(?<![\w.])(system|popen)[ \t]*\(")


def _first_arg(text: str, open_paren: int, src: Source) -> str | None:
    close = src.close_of(open_paren)
    if close < 0:
        return None
    inner = text[open_paren + 1:close]
    depth = 0
    for i, ch in enumerate(inner):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0 and not src.in_masked(open_paren + 1 + i):
            return inner[:i]
    return inner


def _is_literal(expr: str) -> bool:
    return expr.strip().startswith(('@"', '"'))


def _split_message_args(body: str) -> list[str]:
    """Top-level comma-separated parts of ``body`` (outside brackets/strings)."""
    parts: list[str] = []
    depth = 0
    start = 0
    in_str = False
    i = 0
    while i < len(body):
        ch = body[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(body[start:i])
            start = i + 1
        i += 1
    parts.append(body[start:])
    return parts


def _objc_string_value(text: str, at: int) -> tuple[str, int] | None:
    """(contents, end offset) of the `@"..."` literal starting at ``at``
    (adjacent literals `@"a" @"b"` are concatenated)."""
    pieces: list[str] = []
    pos = at
    n = len(text)
    for _ in range(32):
        while pos < n and text[pos] in " \t\r\n":
            pos += 1
        if text.startswith('@"', pos):
            pos += 2
        elif text.startswith('"', pos) and pieces:
            pos += 1
        else:
            break
        m = _STRING_BODY.match(text, pos)
        end = m.end()
        pieces.append(text[pos:end - 1] if text[end - 1:end] == '"' else text[pos:end])
        pos = end
    return ("".join(pieces), pos) if pieces else None


def _quoted_format_args(fmt: str, args: list[str]) -> list[str]:
    """Arguments of the `%@` specifiers that sit inside a JS string literal."""
    out: list[str] = []
    quote: str | None = None
    index = 0
    i = 0
    n = len(fmt)
    while i < n:
        ch = fmt[i]
        if ch == "\\" and i + 1 < n:
            if fmt[i + 1] == '"':
                quote = None if quote == '"' else (quote or '"')
            i += 2
            continue
        if ch == "%":
            m = _FORMAT_SPEC.match(fmt, i)
            if m is None:
                i += 1
                continue
            conv = m.group(1)
            if conv is not None:
                if conv == "@" and quote is not None and index < len(args):
                    out.append(args[index])
                index += 1
            i = m.end()
            continue
        if ch in "'`":
            quote = None if quote == ch else (quote or ch)
        i += 1
    return out


def _value_name(expr: str) -> str | None:
    """The identifier a value expression ends in: `self.token`, `[user password]`."""
    expr = expr.strip().rstrip(";")
    if expr.startswith("[") and expr.endswith("]"):
        words = expr[1:-1].split()
        return words[-1] if len(words) == 2 and words[-1].isidentifier() else None
    tail = expr.rsplit(".", 1)[-1].strip()
    return tail if tail.isidentifier() else None


# ---------- Per-file analysis ----------

def analyze_objc_source(rel_path: str, text: str, result: ScanResult, handlers: list[Handler]) -> None:
    src = parse(text)

    def code(offset: int) -> bool:
        return not src.in_masked(offset)

    def snippet(offset: int) -> str:
        start = text.rfind("\n", 0, offset) + 1
        end = text.find("\n", offset)
        return clip(text[start:end if end >= 0 else len(text)], _EVIDENCE_MAX)

    def issue(kind: str, offset: int, severity: str, evidence: str | None = None) -> None:
        result.app_surface_issues.append(AppSurfaceIssue(
            kind=kind, file=rel_path, line=line_of(text, offset), severity=severity,  # type: ignore[arg-type]
            evidence_text=evidence or snippet(offset),
        ))

    def weakness(kind: str, offset: int, evidence: str | None = None) -> None:
        result.code_weaknesses.append(CodeWeakness(
            kind=kind, file=rel_path, line=line_of(text, offset), severity="medium",  # type: ignore[arg-type]
            confidence="medium", evidence_text=evidence or snippet(offset),
        ))

    # Entry points.
    for m in _URL_HANDLER_DEF.finditer(text):
        if code(m.start()):
            line = line_of(text, m.start())
            handlers.append(Handler("url_scheme_handler", rel_path, line))
            result.entrypoint_hints.append(EntrypointHint(
                hint="url_scheme_handler (opens URLs from other apps)", file=rel_path, line=line,
                evidence_text=snippet(m.start()), confidence=0.9,
            ))
    for m in _UNIVERSAL_LINK_DEF.finditer(text):
        if code(m.start()):
            result.entrypoint_hints.append(EntrypointHint(
                hint="universal_link_handler (continueUserActivity)", file=rel_path,
                line=line_of(text, m.start()), evidence_text=snippet(m.start()), confidence=0.8,
            ))
    for m in _XPC_MACH_LISTENER.finditer(text):
        if code(m.start()):
            result.entrypoint_hints.append(EntrypointHint(
                hint=apple_surface.XPC_MACH_HINT, file=rel_path, line=line_of(text, m.start()),
                evidence_text=snippet(m.start()), confidence=0.9,
            ))
    for m in _XPC_LOCAL_LISTENER.finditer(text):
        if code(m.start()):
            kind = "bundled XPC service" if m.group(1) == "serviceListener" else "anonymous listener"
            result.entrypoint_hints.append(EntrypointHint(
                hint=f"xpc_service: {kind} ([NSXPCListener {m.group(1)}])", file=rel_path,
                line=line_of(text, m.start()), evidence_text=snippet(m.start()), confidence=0.9,
            ))
    for m in _XPC_ACCEPT.finditer(text):
        brace = m.end() - 1
        close = src.close_of(brace)
        if close < 0 or not code(brace):
            continue
        body = text[brace:close]
        if _RETURN_YES.search(body) and not apple_surface.xpc_peer_checked(body, m.group(1)):
            issue("apple_xpc_unvalidated_peer", m.start(), "high",
                  "listener:shouldAcceptNewConnection: returns YES without checking the peer's audit token or code signature")

    # WKWebView / UIWebView script from stringWithFormat.
    for m in _EVAL_JS.finditer(text):
        if not code(m.start()):
            continue
        literal = _objc_string_value(text, m.end() - 2)
        if literal is None:
            continue
        fmt, after = literal
        bracket = _enclosing_bracket(src, after)
        if bracket is None:
            continue
        rest = text[after:bracket[1]]
        args = [a.strip() for a in _split_message_args(rest)[1:]] if rest.lstrip().startswith(",") else []
        exprs = js_injection_exprs(_quoted_format_args(fmt, args), text[max(0, m.start() - 4000):m.start()])
        if exprs:
            issue("apple_webview_js_injection", m.start(), js_injection_severity(exprs),
                  clip(f"{snippet(m.start())} [interpolated: {', '.join(exprs[:3])}]", _EVIDENCE_MAX))

    # NSUserDefaults: a secret-named value or key.
    defaults_vars = {v.group(1) for v in _DEFAULTS_VAR.finditer(text)}
    for m in _SET_FOR_KEY.finditer(text):
        if not code(m.start()):
            continue
        receiver, value, key = m.group(1), m.group(2), m.group(3)
        if "efaults" not in receiver and receiver not in defaults_vars:
            continue
        key_literal = key[2:-1] if key.startswith('@"') else None
        name = _value_name(value)
        if (key_literal and is_secret_name(key_literal)) or (name and is_secret_name(name)):
            issue("apple_insecure_secret_storage", m.start(), "medium")

    # Pasteboard: a secret-named value.
    pasteboard_vars = {v.group(1) for v in _PASTEBOARD_VAR.finditer(text)}
    for m in _PASTEBOARD_SET.finditer(text):
        if not code(m.start()):
            continue
        target = m.group(1)
        if "Pasteboard" not in target and target not in pasteboard_vars:
            continue
        name = _value_name(m.group(2) or m.group(3) or "")
        if name and is_secret_name(name):
            issue("apple_pasteboard_secret", m.start(), "low")

    # Dynamic dispatch on a string built at the call site.
    for m in _DYNAMIC.finditer(text):
        if not code(m.start()):
            continue
        arg = _first_arg(text, m.end() - 1, src)
        if arg is not None and _BUILT_STRING.search(arg):
            issue("apple_dynamic_dispatch", m.start(), "medium")

    # Format strings: a non-literal, non-localized format with nothing to format.
    for m in _FORMAT_CALL.finditer(text):
        if not code(m.start()):
            continue
        bracket = _enclosing_bracket(src, m.start())
        if bracket is None:
            continue
        rest = text[m.end():bracket[1]]
        parts = _split_message_args(rest)
        fmt = parts[0].strip()
        if (
            len(parts) == 1 and fmt and not _is_literal(fmt) and not _LOCALIZED.search(fmt)
            and not _FORWARDED_FORMAT.search(rest)
        ):
            weakness("format_string", m.start())
    for m in _NSLOG.finditer(text):
        if not code(m.start()):
            continue
        close = src.close_of(m.end() - 1)
        if close < 0:
            continue
        parts = _split_message_args(text[m.end():close])
        fmt = parts[0].strip()
        if len(parts) == 1 and fmt and not _is_literal(fmt) and not _LOCALIZED.search(fmt):
            weakness("format_string", m.start())

    # Shell commands built at runtime.
    for m in _SHELL_ARGS.finditer(text):
        if not code(m.start()):
            continue
        command = m.group(1).split(",", 1)[0].strip()
        window = text[max(0, m.start() - 1500):m.end() + 300]
        if command and not _is_literal(command) and _SHELL_PATH.search(window):
            weakness("native_command_exec", m.start())
    for m in _SYSTEM_CALL.finditer(text):
        if not code(m.start()):
            continue
        arg = _first_arg(text, m.end() - 1, src)
        if arg is not None and arg.strip() and not _is_literal(arg):
            weakness("native_command_exec", m.start())


def looks_like_objc(text: str) -> bool:
    return _OBJC_MARKER.search(text) is not None


class ObjCAnalyzer:
    metadata = AnalyzerMetadata(
        name="objc",
        display_name="Objective-C Analyzer",
        version="0.1.0",
        description="Objective-C / Objective-C++ analyzer: the iOS/macOS app attack surface (ATS, URL schemes, entitlements, WKWebView, NSUserDefaults, XPC), format strings, shell commands and dynamic dispatch.",
        scope="Objective-C and Objective-C++ (.m/.mm) iOS/macOS apps and frameworks, with their Info.plist, entitlements, xcconfig and Carthage files.",
        targets=["ios", "macos", "cocoa"],
        languages=["objective-c", "objective-c++"],
        priority=21,  # after `swift`, which wins a duplicate project-file signal
        experimental=True,
        enabled_by_default=False,  # opt-in via `-m objc` while experimental
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False
        checked = 0
        for path in iter_repo_files(root, suffixes=OBJC_SUFFIXES, skip_dirs=SKIP_DIRS):
            text = read_source(path)
            if text is not None and looks_like_objc(text):
                return True
            checked += 1
            if checked >= 64:
                break
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result
        apple_surface.analyze_project_files(root, result, SKIP_DIRS, is_test=_is_test_path)
        handlers: list[Handler] = []
        for path in iter_repo_files(root, suffixes=OBJC_SUFFIXES, skip_dirs=SKIP_DIRS):
            rel_path = rel(path, root)
            if _is_test_path(rel_path):
                continue
            text = read_source(path)
            if text is None or not looks_like_objc(text):
                continue
            result.files_scanned += 1
            analyze_objc_source(rel_path, text, result, handlers)
        apple_surface.report_url_schemes(result, handlers)
        apple_surface.finalize_xpc(result)
        if result.files_scanned:
            result.languages.append("objective-c")
        return result


__all__ = ["ObjCAnalyzer", "analyze_objc_source", "looks_like_objc", "parse"]
