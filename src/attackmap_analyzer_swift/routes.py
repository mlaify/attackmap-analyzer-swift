"""Server-side Swift routes (#187): Vapor 4 and Hummingbird 1.x/2.x.

Each route carries ``auth`` (``required`` / ``unknown``), the ``guards`` that
apply and the ``guard_evidence`` that established them (AttackMap#256). Only
what the source verifiably says is declared:

- A route is a verb call (``get``/``post``/..., ``on``, ``webSocket``/``ws``)
  with a handler (``use:`` or a trailing closure) whose receiver resolves to a
  router: ``app`` / ``app.routes`` / ``app.router``, ``Router(...)``,
  ``RouteCollection(...)``, a parameter typed ``Application`` /
  ``RoutesBuilder`` / ``Router`` / ``RouterGroup`` / ``RouterMethods``, a
  variable bound to one, or the parameter (or ``$0``) of a
  ``group(...) { ... }`` closure. Anything else (``parameters.get("id")``,
  ``cache.get(...)``) is not a route.
- Prefixes come from ``grouped("api", "v1")`` and ``group("x")`` (closure or
  chained), and from where a ``RouteCollection`` (Vapor
  ``register(collection:)``, Hummingbird ``addRoutes(_:atPath:)``) or a
  controller (``addRoutes(to:)``) is mounted, when every mount in the same
  Swift package agrees. An unknown mount is kept as ``$(TypeName)`` and a
  computed path (``SiteURL.faq.pathComponents``) as ``$(SiteURL.faq)``.
- ``required`` needs an enforcing guard: Vapor's ``X.guardMiddleware()`` /
  ``X.redirectMiddleware(...)``, Hummingbird's ``IsAuthenticatedMiddleware``,
  or a handler that calls ``req.auth.require(...)`` /
  ``context.requireIdentity()`` or opens with
  ``guard let user = context.identity else { throw HTTPError(.unauthorized) }``.
  An authenticator alone (``UserAuthenticator()``, ``SessionAuthenticator``)
  only identifies a caller who sent credentials, so the route stays
  ``unknown``.
- Hummingbird ``add(middleware:)`` / ``addMiddleware { }`` apply to routes
  added after them on that router or group, in source order. Middleware added
  under ``if`` / ``#if`` (or in a closure other than a ``group { }``) may not
  run, so it never makes a route ``required``. ``try?`` around an identity
  check swallows the rejection and doesn't count either.
- A ``use:`` handler is resolved in the type that registers it (or the type
  named, ``use: Controller.show``); an ambiguous name leaves auth unknown. A
  mount whose type can't be resolved (``register(collection: items[0])``), or
  more than 16 mounts, leaves every mount in that package unknown.

Linear per file: brackets are matched once (``swiftsrc.parse``), receiver
chains are bounded, and router resolution is memoized with a depth limit.
"""

from __future__ import annotations

import bisect
import posixpath
import re
from dataclasses import dataclass, field

from attackmap.sdk import line_of

from . import swiftsrc
from .swiftsrc import Source, arg_label, clip, split_args, string_value

REQUIRED = "required"
UNKNOWN = "unknown"

_VERBS = {
    "get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE",
    "head": "HEAD", "options": "OPTIONS", "on": None, "webSocket": "GET", "ws": "GET",
}
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_ROUTE_CALL = re.compile(r"\.[ \t]*(get|post|put|patch|delete|head|options|on|webSocket|ws)[ \t]*(?=[({])")
_IMPORT = re.compile(r"^[ \t]*(?:@\w+[ \t]+)*import[ \t]+(Vapor|Hummingbird\w*)\b", re.MULTILINE)
_IDENT = re.compile(r"\$\d+|[A-Za-z_]\w*")
_IDENT_TAIL = re.compile(r"[\w$]+$")
_BINDING = re.compile(r"\b(?:let|var)[ \t]+([A-Za-z_]\w*)[ \t]*(?::[^=\n{]{1,80})?=[ \t]*")
_PARAM_ROUTER_TYPE = re.compile(
    r"([A-Za-z_]\w*)[ \t]*:[ \t]*(?:inout[ \t]+)?(?:some[ \t]+|any[ \t]+)?(?:Vapor\.|Hummingbird\.)?"
    r"(Application|RoutesBuilder|HBApplication|HBRouterBuilder|HBRouterGroup|Router|RouterGroup|RouterMethods)\b"
)
_FUNC = re.compile(r"\bfunc[ \t]+([A-Za-z_]\w*)[ \t]*(?:<[^>\n]{0,200}>)?[ \t]*\(")
_TYPE_DECL = re.compile(r"\b(?:struct|class|extension|enum|actor)[ \t]+([A-Za-z_][\w.]*)")
# `{ r in`, `{ [weak self] (r) in`, `{ r, _ in`: parsed from a bounded window
# after the brace (see `_closure_param`), so hostile whitespace stays linear.
_CLOSURE_HEAD = re.compile(r"(?:\[[^\]\n]{0,80}\][ \t]*)?\(?[ \t]*([A-Za-z_]\w{0,60})[ \t]*(?:,[^)\n{]{0,80})?\)?")
_CLOSURE_WINDOW = 240
_REGISTER = re.compile(r"\.[ \t]*register[ \t]*\([ \t]*collection[ \t]*:")
_ADD_ROUTES = re.compile(r"\.[ \t]*addRoutes[ \t]*\(")
_MUTATION = re.compile(r"\.[ \t]*(?:add[ \t]*\([ \t]*middleware[ \t]*:|addMiddleware[ \t]*\{)")
_GROUP_CLOSURE = re.compile(r"\.[ \t]*group[ \t]*\(")
_CTOR = re.compile(r"\s*([A-Z]\w*)\s*(?:<[^>\n]{0,120}>)?\s*\(")
_METHOD = re.compile(r"\s*(?:HTTPMethod|HTTPRequest\.Method)?\.([A-Za-z]+)\s*")
_PATH_PARAM_CTOR = re.compile(r'(?:PathComponent)?\.(parameter|constant)\(\s*"([^"\\\n]{1,80})"\s*\)')
# Handler bodies that enforce authentication themselves.
_HANDLER_GUARD = re.compile(
    r"\bauth[ \t]*\.[ \t]*require[ \t]*\("
    r"|\brequireIdentity[ \t]*\("
    # `guard let user = context.identity else { throw HTTPError(.unauthorized) }`: a
    # guard on the request's identity that answers 401. (A login handler's
    # `guard let user = found else { throw .unauthorized }` checks credentials,
    # not the caller, so it doesn't count.)
    r"|\bguard\b[^{\n]{0,120}?\b(?:context|req|request)[ \t]*\.[ \t]*(?:identity|currentUser|user|auth)\b"
    r"[^{\n]{0,120}\belse[ \t]*\{[ \t\r\n]*throw[ \t]+(?:HTTPError|Abort)[ \t]*\([ \t]*\.unauthorized"
)

_MAX_CHAIN = 24
_MAX_NESTING_WALK = 256
_MAX_DEPTH = 8
_MAX_MOUNTS = 16
_PATH_EXPR_MAX = 60

# Router-ish property names that don't change the scope (`app.routes`, `app.router`).
_TRANSPARENT = {"routes", "router", "self"}
_ROOT_CTORS = {"Router", "HBRouter", "HBRouterBuilder", "HBApplication"}
_COLLECTION_CTORS = {"RouteCollection"}

_GUARD_MEMBER = re.compile(r"\.[ \t]*(?:guardMiddleware|redirectMiddleware)[ \t]*\(")
_GUARD_TYPES = re.compile(r"\bIsAuthenticatedMiddleware\b|\b\w*Authoriz\w*Middleware\b")
_AUTHENTICATOR = re.compile(r"(?i)authenticat")
# Role / permission checks in a handler body (Swift idioms), reported as guards
# so core's function-level authorization check (BFLA) sees them.
_HANDLER_ROLE = re.compile(
    r"\.(?:roles?|permissions?)[ \t]*\.[ \t]*contains[ \t]*\("
    r"|\bisAdmin\b|\bhasRole[ \t]*\(|\bhasPermission[ \t]*\(|\bRolePolicy[ \t]*\(|\bPermissionPolicy[ \t]*\("
)
_PP_DIRECTIVE = re.compile(r"^[ \t]*#(if|endif)\b", re.MULTILINE)
_MIDDLEWARE_NAME = re.compile(r"(?i)middleware|auth|guard|session|token|jwt|cors|limit|log|error|file")


@dataclass(frozen=True)
class Guard:
    name: str
    enforcing: bool  # False for an authenticator that only identifies the caller
    evidence: str
    # Added under `if` / `#if` / a non-group closure: it may not apply, so it
    # never makes a route `required` on its own.
    conditional: bool = False


@dataclass(frozen=True)
class Scope:
    """A router value: its path prefix and the middleware that applies to
    routes added on it."""

    prefix: tuple[str, ...] = ()
    guards: tuple[Guard, ...] = ()


@dataclass
class RouteHit:
    path: str
    method: str
    line: int
    auth: str = UNKNOWN
    guards: list[str] = field(default_factory=list)
    evidence: str | None = None


@dataclass
class _Seg:
    name: str
    start: int
    args: tuple[int, int] | None = None  # bracket offsets of a call's argument list
    closure: tuple[int, int] | None = None  # a trailing closure's braces


# ---------- Path components ----------

def _component(text: str) -> list[str] | None:
    """Path components for one argument; None when it isn't a path."""
    value = string_value(text)
    if value is not None:
        return [_normalize_segment(part) for part in value.split("/") if part]
    stripped = " ".join(text.split())
    if stripped in (".catchall", "PathComponent.catchall"):
        return ["**"]
    if stripped in (".anything", "PathComponent.anything"):
        return ["*"]
    m = _PATH_PARAM_CTOR.fullmatch(stripped)
    if m:
        return [f"{{{m.group(2)}}}" if m.group(1) == "parameter" else m.group(2)]
    if stripped.endswith((".pathComponents", ".pathComponent")):
        return [_computed(stripped.rsplit(".", 1)[0])]
    return None


def _computed(expr: str) -> str:
    return f"$({' '.join(expr.split())[:_PATH_EXPR_MAX]})"


def _normalize_segment(part: str) -> str:
    if part.startswith(":") and len(part) > 1:
        return "{" + part[1:] + "}"
    return part


def _is_middleware_expr(text: str) -> bool:
    stripped = text.strip()
    return "(" in stripped or bool(_MIDDLEWARE_NAME.search(stripped))


def _guard_for(text: str, evidence: str) -> Guard:
    enforcing = bool(_GUARD_MEMBER.search(text) or _GUARD_TYPES.search(text))
    return Guard(_guard_name(text), enforcing, evidence)


def _guard_name(text: str) -> str:
    """The middleware expression, without a trailing closure's body:
    `BasicAuthenticator { username, _ in ... }` -> `BasicAuthenticator`."""
    flat = " ".join(text.split())
    brace = flat.find("{")
    if brace > 0:
        head = flat[:brace].strip()
        if head and head.count("(") == head.count(")"):
            flat = head
    return clip(flat, 80)


def _closure_guards(body: str, evidence: str) -> tuple[Guard, ...]:
    """One guard per middleware listed in an `addMiddleware { ... }` builder:
    each top-level line, extended over the brackets it opens."""
    src = swiftsrc.parse(body)
    end = len(body) - 1 if body.endswith("}") else len(body)
    pos = 1 if body.startswith("{") else 0
    guards: list[Guard] = []
    for _ in range(64):
        while pos < end and body[pos].isspace():
            pos += 1
        if pos >= end:
            break
        start = pos
        nl = body.find("\n", pos, end)
        stop = end if nl < 0 else nl
        k = pos
        while k < stop:
            ch = body[k]
            if ch in "({[":
                close = src.close_of(k)
                if close < 0 or close >= end:
                    k = stop
                    break
                k = close + 1
                if k > stop:
                    nl = body.find("\n", k, end)
                    stop = end if nl < 0 else nl
                continue
            k += 1
        item = body[start:k].strip()
        if item and not item.startswith("//"):
            guards.append(_guard_for(item, evidence))
        pos = max(k, start + 1)
    return tuple(guards) or (_guard_for(body, evidence),)


def _method(value: str) -> str | None:
    m = _METHOD.fullmatch(value)
    if m is None:
        return None
    name = m.group(1).upper()
    return name if name in _HTTP_METHODS else None


# ---------- Per-file model ----------

class _SpanIndex:
    """Innermost-enclosing lookup over properly nested (open, close, payload)
    spans: a bisect plus a bounded walk up parent links."""

    def __init__(self, spans) -> None:
        self.spans = sorted(spans, key=lambda s: (s[0], -s[1]))
        self.opens = [s[0] for s in self.spans]
        self.parent: list[int] = []
        stack: list[int] = []
        for i, (open_, _close, *_rest) in enumerate(self.spans):
            while stack and self.spans[stack[-1]][1] < open_:
                stack.pop()
            self.parent.append(stack[-1] if stack else -1)
            stack.append(i)

    def innermost(self, offset: int):
        i = bisect.bisect_left(self.opens, offset) - 1
        for _ in range(_MAX_NESTING_WALK):
            if i < 0:
                return None
            span = self.spans[i]
            if span[0] < offset < span[1]:
                return span
            i = self.parent[i]
        return None

    def containing(self, offset: int):
        """Enclosing spans, innermost first (bounded)."""
        span = self.innermost(offset)
        if span is None:
            return
        i = bisect.bisect_left(self.opens, span[0])
        while i < len(self.spans) and self.spans[i] is not span:
            i += 1
        for _ in range(_MAX_NESTING_WALK):
            if i < 0:
                return
            if self.spans[i][0] < offset < self.spans[i][1]:
                yield self.spans[i]
            i = self.parent[i]


def _closure_param(text: str, brace: int, close: int) -> str:
    """The parameter of a `{ r in ...}` closure, else `$0`."""
    end = min(close, brace + _CLOSURE_WINDOW)
    pos = brace + 1
    while pos < end and text[pos].isspace():
        pos += 1
    m = _CLOSURE_HEAD.match(text, pos, end)
    if m is None:
        return "$0"
    k = m.end()
    while k < end and text[k] in " \t":
        k += 1
    if not text.startswith("in", k) or k + 2 > end or (k + 2 < len(text) and (text[k + 2].isalnum() or text[k + 2] == "_")):
        return "$0"
    return m.group(1)


@dataclass
class _Closure:
    open: int
    close: int
    param: str
    call_dot: int  # the `.group(` dot
    args: tuple[int, int]


class SwiftFile:
    def __init__(self, rel: str, text: str, package: str = "") -> None:
        self.rel = rel
        self.text = text
        self.package = package
        imports = {m.group(1) for m in _IMPORT.finditer(text)}
        self.vapor = "Vapor" in imports
        self.hummingbird = any(i.startswith("Hummingbird") for i in imports)
        self.closures: list[_Closure] = []
        self.bindings: dict[str, list[int]] = {}
        self.params: dict[str, list[tuple[int, int, str]]] = {}  # name -> (body_open, body_close, type)
        self.functions: dict[str, list[tuple[int, int]]] = {}
        self.types: list[tuple[int, int, str]] = []
        self.mutations: dict[str, list[tuple[int, Guard]]] = {}
        self.handler_cache: dict[tuple[int, int], tuple[tuple[str, str] | None, str | None]] = {}
        self.expression_end_cache: dict[int, int] = {}
        self.scope_cache: dict[tuple[str, int], Scope | None] = {}
        self.group_bodies: set[tuple[int, int]] = set()
        self.pp_if: list[int] = []
        self.pp_endif: list[int] = []
        self.function_index = _SpanIndex([])
        self.type_index = _SpanIndex([])
        self.block_index = _SpanIndex([])
        self.closure_index = _SpanIndex([])
        self.src: Source = swiftsrc.parse(text) if self.is_server else Source(text)
        if self.is_server:
            self._index()

    @property
    def is_server(self) -> bool:
        return self.vapor or self.hummingbird

    def code(self, offset: int) -> bool:
        return not self.src.in_masked(offset)

    def _index(self) -> None:
        text, src = self.text, self.src
        for m in _FUNC.finditer(text):
            if not self.code(m.start()):
                continue
            paren = m.end() - 1
            close = src.close_of(paren)
            if close < 0:
                continue
            body = text.find("{", close, close + 400)
            body_close = src.close_of(body) if body >= 0 else -1
            if body_close < 0:
                continue
            self.functions.setdefault(m.group(1), []).append((body, body_close))
            for p in _PARAM_ROUTER_TYPE.finditer(text, paren, close + 1):
                self.params.setdefault(p.group(1), []).append((body, body_close, p.group(2)))
        for m in _TYPE_DECL.finditer(text):
            if not self.code(m.start()):
                continue
            body = text.find("{", m.end(), m.end() + 600)
            close = src.close_of(body) if body >= 0 else -1
            if close > 0:
                self.types.append((body, close, m.group(1).rsplit(".", 1)[-1]))
        for m in _BINDING.finditer(text):
            if self.code(m.start()):
                self.bindings.setdefault(m.group(1), []).append(m.end())
        for m in _GROUP_CLOSURE.finditer(text):
            if not self.code(m.start()):
                continue
            paren = m.end() - 1
            close = src.close_of(paren)
            if close < 0:
                continue
            brace = _next_code_char(text, close + 1)
            if brace < 0 or text[brace] != "{":
                continue
            body_close = src.close_of(brace)
            if body_close < 0:
                continue
            param = _closure_param(text, brace, body_close)
            self.closures.append(_Closure(brace, body_close, param, m.start(), (paren, close)))
            self.group_bodies.add((brace, body_close))
        self.function_index = _SpanIndex([(o, c, n) for n, spans in self.functions.items() for o, c in spans])
        self.type_index = _SpanIndex(self.types)
        self.block_index = _SpanIndex([(o, c, "") for o, c in src.pairs.items() if text[o] == "{"])
        self.closure_index = _SpanIndex([(c.open, c.close, c) for c in self.closures])
        for m in _PP_DIRECTIVE.finditer(text):
            (self.pp_endif if m.group(1) == "endif" else self.pp_if).append(m.start())
        for m in _MUTATION.finditer(text):
            if not self.code(m.start()):
                continue
            start, chain = receiver_chain(self, m.start())
            # Only a call on the router itself (`router.add(middleware:)`, or later in
            # a chain of `add`/verb calls, which return the same group) mutates it.
            if not chain or chain[0].args is not None:
                continue
            if any(s.args is not None and s.name not in _VERBS and s.name != "add" for s in chain[1:]):
                continue
            if any(s.closure is not None and s.args is None and s.name != "addMiddleware" for s in chain[1:]):
                continue
            conditional = self.is_conditional(m.start())
            for guard in self._mutation_guard(m.start(), start) or ():
                if conditional:
                    guard = Guard(guard.name, guard.enforcing, guard.evidence, conditional=True)
                self.mutations.setdefault(chain[0].name, []).append((m.start(), guard))

    def _mutation_guard(self, dot: int, start: int) -> tuple[Guard, ...] | None:
        text, src = self.text, self.src
        opener = text.find("(", dot, dot + 40)
        brace = text.find("{", dot, dot + 40)
        if "addMiddleware" in text[dot:dot + 20] and brace >= 0:
            close = src.close_of(brace)
            if close < 0:
                return None
            return _closure_guards(text[brace:close + 1], clip(text[start:close + 1]))
        close = src.close_of(opener)
        if close < 0:
            return None
        args = split_args(src, opener, close)
        if not args:
            return None
        _, value = arg_label(text[args[0][0]:args[0][1]])
        return (_guard_for(value, clip(text[start:close + 1])),)

    def enclosing_type(self, offset: int) -> tuple[int, int, str] | None:
        found = self.type_index.innermost(offset)
        return found  # type: ignore[return-value]

    def enclosing_function(self, offset: int) -> tuple[int, int] | None:
        found = self.function_index.innermost(offset)
        return (found[0], found[1]) if found is not None else None

    def is_conditional(self, offset: int) -> bool:
        """True when ``offset`` sits in a block that may not run: inside an
        `if`/`for`/other closure body rather than directly in a function or a
        `group { }` closure, or between `#if` and `#endif`."""
        block = self.block_index.innermost(offset)
        function = self.function_index.innermost(offset)
        if block is not None and (function is None or block[0] != function[0]):
            if (block[0], block[1]) not in self.group_bodies:
                return True
        start = function[0] if function is not None else 0
        opened = bisect.bisect_left(self.pp_if, offset) - bisect.bisect_left(self.pp_if, start)
        closed = bisect.bisect_left(self.pp_endif, offset) - bisect.bisect_left(self.pp_endif, start)
        return opened > closed

    def function_body(self, name: str, near: int, type_name: str | None = None) -> tuple[int, int] | None:
        """Body of ``func name`` declared in ``type_name`` (default: the type
        enclosing ``near``, or top level), across its extensions in this file.
        None unless exactly one candidate: an ambiguous handler stays unseen."""
        spans = self.functions.get(name)
        if not spans:
            return None
        if type_name is None:
            owner = self.enclosing_type(near)
            type_name = owner[2] if owner is not None else None
        candidates = []
        for span in spans:
            declared = self.enclosing_type(span[0])
            if (declared[2] if declared is not None else None) == type_name:
                candidates.append(span)
        return candidates[0] if len(candidates) == 1 else None


def _next_code_char(text: str, pos: int, limit: int = 200) -> int:
    end = min(len(text), pos + limit)
    while pos < end:
        if not text[pos].isspace():
            return pos
        pos += 1
    return -1


def chain_start(f: SwiftFile, dot: int) -> int:
    """Offset where the receiver chain ending at ``dot`` begins (bounded)."""
    text, src = f.text, f.src
    pos = dot
    for _ in range(_MAX_CHAIN):
        j = pos - 1
        while j >= 0 and text[j].isspace():
            j -= 1
        while j >= 0 and text[j] in "?!":
            j -= 1
        if j < 0 or src.in_masked(j):
            return pos
        if text[j] == "}":  # a trailing closure: `.post("x") { ... }.get(...)`
            open_ = src.open_of(j)
            if open_ < 0:
                return pos
            j = open_ - 1
            while j >= 0 and text[j].isspace():
                j -= 1
            if j < 0:
                return pos
        if text[j] == ")":
            open_ = src.open_of(j)
            if open_ < 0:
                return pos
            j = open_ - 1
            while j >= 0 and text[j] in " \t":
                j -= 1
        if j >= 0 and text[j] == ">":
            open_ = text.rfind("<", max(0, j - 120), j)
            if open_ < 0:
                return pos
            j = open_ - 1
        m = _IDENT_TAIL.search(text, max(0, j - 80), j + 1) if j >= 0 else None
        if m is None or m.end() != j + 1:
            return pos
        start = m.start()
        k = start - 1
        while k >= 0 and text[k].isspace():
            k -= 1
        if k >= 0 and text[k] in "?!":
            k -= 1
        if k >= 0 and text[k] == "." and not src.in_masked(k):
            pos = k
            continue
        return start
    return pos


def parse_chain(f: SwiftFile, start: int, stop: int) -> list[_Seg] | None:
    """Segments of the chain expression ``text[start:stop]``: names, calls and
    trailing closures."""
    text, src = f.text, f.src
    segs: list[_Seg] = []
    pos = start
    for _ in range(_MAX_CHAIN):
        while pos < stop and text[pos].isspace():
            pos += 1
        if pos >= stop:
            break
        m = _IDENT.match(text, pos)
        if m is None or m.end() > stop:
            return None
        seg = _Seg(m.group(0), m.start())
        pos = m.end()
        if pos < stop and text[pos] == "<":
            close = text.find(">", pos, min(stop, pos + 120))
            if close < 0:
                return None
            pos = close + 1
        while pos < stop and text[pos] in " \t":
            pos += 1
        if pos < stop and text[pos] == "(":
            close = src.close_of(pos)
            if close < 0 or close >= stop:
                return None
            seg.args = (pos, close)
            pos = close + 1
        brace = _next_code_char(text, pos)
        if 0 <= brace < stop and text[brace] == "{":
            close = src.close_of(brace)
            if close < 0 or close >= stop:
                return None
            seg.closure = (brace, close)
            pos = close + 1
        segs.append(seg)
        while pos < stop and (text[pos].isspace() or text[pos] in "?!"):
            pos += 1
        if pos < stop and text[pos] == ".":
            pos += 1
            continue
        if pos < stop:
            return None
    return segs or None


def receiver_chain(f: SwiftFile, dot: int) -> tuple[int, list[_Seg] | None]:
    start = chain_start(f, dot)
    return start, parse_chain(f, start, dot)


# ---------- Resolution ----------

class RouteResolver:
    """Resolves routers across the repo's server files (memoized, bounded)."""

    def __init__(self, files: list[SwiftFile]) -> None:
        self.files = [f for f in files if f.is_server]
        # (package, type name) -> mount sites: (kind, file, offset or arg span, atPath prefix)
        self._mounts: dict[tuple[str, str], list[tuple[str, SwiftFile, object, tuple[str, ...]]]] | None = None
        self._type_scope: dict[tuple[str, str], Scope | None] = {}
        self._resolving: set[tuple[str, str]] = set()
        # Packages with a mount whose type can't be resolved.
        self.unresolved_packages: set[str] = set()

    def mounts(self) -> dict[tuple[str, str], list[tuple[str, SwiftFile, object, tuple[str, ...]]]]:
        if self._mounts is not None:
            return self._mounts
        mounts: dict[tuple[str, str], list[tuple[str, SwiftFile, object, tuple[str, ...]]]] = {}
        for f in self.files:
            text = f.text
            for m in _REGISTER.finditer(text):
                if not f.code(m.start()):
                    continue
                args = self._call_args(f, m.start())
                if not args:
                    self.unresolved_packages.add(f.package)
                    continue
                start, end = args[0]
                _, value = arg_label(text[start:end])
                start = end - len(value) - (len(text[start:end]) - len(text[start:end].rstrip()))
                chain = parse_chain(f, start, end)
                type_name = self._type_of(f, chain[0], m.start()) if chain and len(chain) == 1 else None
                if type_name is None:
                    # `register(collection: controllers[i])`: some type is mounted
                    # somewhere we can't see, so no mount in this package is certain.
                    self.unresolved_packages.add(f.package)
                    continue
                mounts.setdefault((f.package, type_name), []).append(("receiver", f, m.start(), ()))
            for m in _ADD_ROUTES.finditer(text):
                if not f.code(m.start()):
                    continue
                args = self._call_args(f, m.start())
                if not args:
                    continue
                label, value = arg_label(text[args[0][0]:args[0][1]])
                if label == "to":
                    # Controller(...).addRoutes(to: router.group("x"))
                    type_name = self._controller_type(f, m.start())
                    if type_name is None:
                        self.unresolved_packages.add(f.package)
                        continue
                    mounts.setdefault((f.package, type_name), []).append(("expr", f, args[0], ()))
                elif label is None:
                    # router.addRoutes(Controller(...).endpoints, atPath: "/x")
                    type_name = self._collection_type(f, args[0])
                    if type_name is None:
                        self.unresolved_packages.add(f.package)
                        continue
                    prefix: tuple[str, ...] = ()
                    for start, end in args[1:]:
                        alabel, avalue = arg_label(text[start:end])
                        if alabel == "atPath":
                            comps = _component(avalue)
                            prefix = tuple(comps) if comps is not None else (_computed(avalue),)
                    mounts.setdefault((f.package, type_name), []).append(("receiver", f, m.start(), prefix))
        self._mounts = mounts
        return mounts

    @staticmethod
    def _call_args(f: SwiftFile, dot: int) -> list[tuple[int, int]]:
        paren = f.text.find("(", dot, dot + 40)
        close = f.src.close_of(paren) if paren >= 0 else -1
        return split_args(f.src, paren, close) if close >= 0 else []

    def _controller_type(self, f: SwiftFile, dot: int) -> str | None:
        _, chain = receiver_chain(f, dot)
        if not chain:
            return None
        return self._type_of(f, chain[0], dot) if len(chain) == 1 else None

    def _collection_type(self, f: SwiftFile, span: tuple[int, int]) -> str | None:
        start, end = span
        while start < end and f.text[start].isspace():
            start += 1
        chain = parse_chain(f, start, end)
        if not chain or len(chain) > 3:
            return None
        return self._type_of(f, chain[0], start)

    @staticmethod
    def _type_of(f: SwiftFile, seg: _Seg, offset: int) -> str | None:
        if seg.args is not None and seg.name[:1].isupper():
            return seg.name
        if seg.args is None:
            binding = _nearest(f.bindings.get(seg.name, ()), offset)
            if binding is not None:
                ctor = _CTOR.match(f.text, binding)
                if ctor:
                    return ctor.group(1)
        return None

    def type_scope(self, f: SwiftFile, offset: int, depth: int) -> Scope:
        """Scope the type enclosing ``offset`` is mounted at, when every mount
        in the same package agrees; else ``$(TypeName)``."""
        owner = f.enclosing_type(offset)
        if owner is None:
            return Scope(("$(mount)",))
        key = (f.package, owner[2])
        if key not in self._type_scope:
            self._type_scope[key] = self._resolve_type(key, depth)
        scope = self._type_scope[key]
        return scope if scope is not None else Scope((f"$({owner[2]})",))

    def _resolve_type(self, key: tuple[str, str], depth: int) -> Scope | None:
        if key in self._resolving or depth > _MAX_DEPTH:
            return None
        sites = self.mounts().get(key, [])
        if key[0] in self.unresolved_packages or len(sites) > _MAX_MOUNTS:
            return None  # a mount we can't see (or too many to check) may differ
        self._resolving.add(key)
        try:
            scopes: list[Scope | None] = []
            for kind, f, where, prefix in sites:
                if kind == "receiver":
                    assert isinstance(where, int)
                    _, chain = receiver_chain(f, where)
                    scope = self.eval_chain(f, chain, where, depth + 1) if chain else None
                else:
                    assert isinstance(where, tuple)
                    start, end = where
                    _, value = arg_label(f.text[start:end])
                    vstart = end - len(value)
                    chain = parse_chain(f, vstart, end)
                    scope = self.eval_chain(f, chain, start, depth + 1) if chain else None
                if scope is not None and prefix:
                    scope = Scope(scope.prefix + prefix, scope.guards)
                scopes.append(scope)
        finally:
            self._resolving.discard(key)
        if not scopes or None in scopes:
            return None
        known = set(scopes)
        return known.pop() if len(known) == 1 else None

    def base_scope(self, f: SwiftFile, name: str, offset: int, depth: int) -> Scope | None:
        if depth > _MAX_DEPTH:
            return None
        # Innermost group closure binding this name ($0 or its parameter).
        best: _Closure | None = None
        for span in f.closure_index.containing(offset):
            if span[2].param == name:
                best = span[2]
                break
        if best is not None:
            key = ("closure", best.open)
            if key not in f.scope_cache:
                f.scope_cache[key] = None  # breaks self-reference cycles
                start, chain = receiver_chain(f, best.call_dot)
                parent = self.eval_chain(f, chain, best.call_dot, depth + 1) if chain else None
                evidence = clip(f.text[start:best.args[1] + 1])
                f.scope_cache[key] = _apply_args(f, parent, best.args, evidence) if parent is not None else None
            scope = f.scope_cache[key]
            if scope is None:
                return None
            return self._with_mutations(f, name, offset, scope, best.open)
        # A local binding: `let api = app.grouped("api")`.
        binding = _nearest(f.bindings.get(name, ()), offset)
        if binding is not None and _same_function(f, binding, offset):
            key = ("binding", binding)
            if key not in f.scope_cache:
                f.scope_cache[key] = None
                chain = parse_chain(f, binding, _expression_end(f, binding))
                f.scope_cache[key] = self.eval_chain(f, chain, binding, depth + 1) if chain is not None else None
            scope = f.scope_cache[key]
            if scope is not None:
                return self._with_mutations(f, name, offset, scope, binding)
        # A parameter typed as a router.
        for open_, close, type_name in f.params.get(name, ()):
            if open_ < offset < close:
                if type_name in ("Application", "HBApplication", "Router", "HBRouterBuilder"):
                    scope = Scope(())  # the root: only a RouterGroup / RoutesBuilder can carry a prefix
                else:
                    scope = self.type_scope(f, offset, depth + 1)
                return self._with_mutations(f, name, offset, scope, open_)
        if name == "app":  # Vapor's Application, Hummingbird 1.x's HBApplication
            return self._with_mutations(f, name, offset, Scope(()), -1)
        return None

    def _with_mutations(self, f: SwiftFile, name: str, offset: int, scope: Scope, since: int) -> Scope:
        """Apply `name.add(middleware: X)` statements made before ``offset``."""
        added = [
            g for at, g in f.mutations.get(name, ())
            if since < at < offset and g not in scope.guards and _same_function(f, at, offset)
        ]
        if not added:
            return scope
        return Scope(scope.prefix, scope.guards + tuple(dict.fromkeys(added)))

    def eval_chain(self, f: SwiftFile, chain: list[_Seg] | None, offset: int, depth: int) -> Scope | None:
        if not chain or depth > _MAX_DEPTH:
            return None
        base = chain[0]
        scope: Scope | None
        if base.args is not None:
            if base.name in _ROOT_CTORS:
                scope = Scope(())
            elif base.name in _COLLECTION_CTORS:
                scope = self.type_scope(f, offset, depth + 1)
            else:
                return None
        else:
            scope = self.base_scope(f, base.name, offset, depth + 1)
        if scope is None:
            return None
        text = f.text
        for seg in chain[1:]:
            if seg.args is None and seg.closure is None:
                if seg.name in _TRANSPARENT:
                    continue
                return None
            end = (seg.closure or seg.args)[1]  # type: ignore[index]
            evidence = clip(text[chain[0].start:end + 1])
            if seg.name in ("grouped", "group") and seg.args is not None:
                scope = _apply_args(f, scope, seg.args, evidence)
            elif seg.name == "add" and seg.args is not None:
                args = split_args(f.src, *seg.args)
                if not args:
                    return None
                label, value = arg_label(text[args[0][0]:args[0][1]])
                if label != "middleware":
                    return None
                scope = Scope(scope.prefix, scope.guards + (_guard_for(value, evidence),))
            elif seg.name == "addMiddleware" and seg.closure is not None:
                body = text[seg.closure[0]:seg.closure[1] + 1]
                scope = Scope(scope.prefix, scope.guards + _closure_guards(body, evidence))
            elif seg.name in _VERBS or seg.name == "addRoutes":
                continue  # Hummingbird verb calls and addRoutes return the router itself
            else:
                return None
        return scope


def _apply_args(f: SwiftFile, scope: Scope, span: tuple[int, int], evidence: str) -> Scope:
    prefix = list(scope.prefix)
    guards = list(scope.guards)
    for start, end in split_args(f.src, *span):
        label, value = arg_label(f.text[start:end])
        if label is not None:
            continue  # `context:` and other labeled arguments don't change the path
        comps = _component(value)
        if comps is not None:
            prefix.extend(comps)
        elif _is_middleware_expr(value):
            guards.append(_guard_for(value, evidence))
        else:
            prefix.append(_computed(value))
    return Scope(tuple(prefix), tuple(guards))


def _nearest(offsets, before: int) -> int | None:
    """The last offset before ``before`` (``offsets`` are ascending)."""
    i = bisect.bisect_left(offsets, before)
    return offsets[i - 1] if i > 0 else None


def _same_function(f: SwiftFile, a: int, b: int) -> bool:
    return f.enclosing_function(a) == f.enclosing_function(b)


def _expression_end(f: SwiftFile, start: int) -> int:
    """End of the expression starting at ``start``: its line, extended over
    brackets opened on it and over following lines that start with `.`
    (cached per start offset)."""
    cached = f.expression_end_cache.get(start)
    if cached is None:
        cached = f.expression_end_cache[start] = _compute_expression_end(f, start)
    return cached


def _compute_expression_end(f: SwiftFile, start: int) -> int:
    text, src = f.text, f.src
    n = len(text)
    pos = start
    for _ in range(_MAX_CHAIN * 4):
        nl = text.find("\n", pos)
        if nl < 0:
            return n
        k = pos
        while True:
            opener = _first_open(text, k, nl)
            if opener < 0:
                break
            close = src.close_of(opener)
            if close < 0:
                return nl
            if close > nl:
                nl = text.find("\n", close)
                if nl < 0:
                    return n
            k = close + 1
        nxt = _next_code_char(text, nl + 1)
        if nxt >= 0 and text[nxt] == ".":
            pos = nxt
            continue
        return nl
    return pos


_OPEN_BRACKET = re.compile(r"[(\[{]")


def _first_open(text: str, start: int, end: int) -> int:
    m = _OPEN_BRACKET.search(text, start, end)
    return m.start() if m else -1


# ---------- Route extraction ----------

def extract_routes(f: SwiftFile, resolver: RouteResolver) -> list[RouteHit]:
    if not f.is_server:
        return []
    text, src = f.text, f.src
    hits: list[RouteHit] = []
    for m in _ROUTE_CALL.finditer(text):
        dot = m.start()
        if not f.code(dot):
            continue
        verb = m.group(1)
        start, chain = receiver_chain(f, dot)
        if not chain:
            continue
        scope = resolver.eval_chain(f, chain, dot, 0)
        if scope is None:
            continue
        opener = m.end()
        args: list[tuple[int, int]] = []
        end = opener - 1
        if text[opener] == "(":
            end = src.close_of(opener)
            if end < 0:
                continue
            args = split_args(src, opener, end)
        method = _VERBS[verb]
        comps: list[str] = []
        use: str | None = None
        for a_start, a_end in args:
            label, value = arg_label(text[a_start:a_end])
            if label == "use":
                use = value
            elif label == "method":
                method = _method(value) or method
            elif label is None:
                if verb == "on" and method is None and _method(value):
                    method = _method(value)
                    continue
                part = _component(value)
                comps.extend(part if part is not None else [_computed(value)])
        handler = _handler_span(f, dot, end + 1, use)
        if method is None or (use is None and handler is None):
            continue  # not a route registration
        hit = RouteHit(path="/" + "/".join(scope.prefix + tuple(comps)), method=method, line=line_of(text, dot))
        _resolve_auth(f, hit, scope, handler)
        hits.append(hit)
    return hits


def _handler_span(f: SwiftFile, dot: int, after: int, use: str | None) -> tuple[int, int] | None:
    """The handler body: a trailing closure, or `use: name` resolved to a
    function in the same file."""
    text, src = f.text, f.src
    if use is None:
        brace = _next_code_char(text, after)
        if brace >= 0 and text[brace] == "{":
            end = src.close_of(brace)
            if end > 0:
                return (brace, end)
        return None
    qualifier, _, name = use.strip().rpartition(".")
    if not name.isidentifier():
        return None
    # `use: Controller.show` names the type; `self.x` / `x` / `Self.x` mean the enclosing one.
    owner = qualifier if qualifier[:1].isupper() and qualifier.isidentifier() and qualifier != "Self" else None
    return f.function_body(name, dot, owner)


# `try? req.auth.require(...)` / `(try? context.requireIdentity())` swallow the
# error: the handler carries on for anonymous callers.
_TRY_OPTIONAL_TAIL = re.compile(r"try\?[ \t]*(?:[\w$]{1,60}[ \t]*\.[ \t]*){0,6}$")


def _handler_checks(f: SwiftFile, handler: tuple[int, int]) -> tuple[tuple[str, str] | None, str | None]:
    """(identity guard name + line, role-guard line) in a handler body,
    computed once per handler."""
    cached = f.handler_cache.get(handler)
    if cached is not None:
        return cached
    text = f.text
    identity: tuple[str, str] | None = None
    for m in _HANDLER_GUARD.finditer(text, handler[0], handler[1]):
        if not f.code(m.start()):
            continue
        if _TRY_OPTIONAL_TAIL.search(text, max(handler[0], m.start() - 120), m.start()):
            continue
        identity = (_handler_guard_name(m.group(0)), clip(_line_at(text, m.start())))
        break
    role: str | None = None
    for m in _HANDLER_ROLE.finditer(text, handler[0], handler[1]):
        line = _line_at(text, m.start()).strip()
        if f.code(m.start()) and line.startswith("guard "):
            role = clip(line, 80)
            break
    f.handler_cache[handler] = (identity, role)
    return identity, role


def _resolve_auth(f: SwiftFile, hit: RouteHit, scope: Scope, handler: tuple[int, int] | None) -> None:
    enforcing = [g for g in scope.guards if g.enforcing and not g.conditional]
    identity, role = _handler_checks(f, handler) if handler is not None else (None, None)
    if enforcing:
        hit.auth = REQUIRED
        hit.guards = list(dict.fromkeys(
            g.name for g in scope.guards
            if not g.conditional and (g.enforcing or _AUTHENTICATOR.search(g.name))
        ))
        hit.evidence = clip("; ".join(dict.fromkeys(g.evidence for g in enforcing)))
    elif identity is not None:
        hit.auth = REQUIRED
        hit.guards = list(dict.fromkeys(
            [g.name for g in scope.guards if not g.conditional and _AUTHENTICATOR.search(g.name)] + [identity[0]]
        ))
        hit.evidence = identity[1]
    if hit.auth == REQUIRED and role is not None:
        # A `guard` on a role or permission in the handler is a guard too.
        hit.guards.append(role)


def _line_at(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    return text[start:end if end >= 0 else len(text)]


def _handler_guard_name(matched: str) -> str:
    if "require(" in matched.replace(" ", ""):
        return "auth.require"
    if "requireIdentity" in matched:
        return "requireIdentity"
    return "guard identity else unauthorized"


def package_of(rel: str, package_dirs: list[str]) -> str:
    """The nearest enclosing directory with a Package.swift ('' = repo root)."""
    parent = posixpath.dirname(rel)
    best = ""
    for d in package_dirs:
        if (d == "" or parent == d or parent.startswith(d + "/")) and len(d) >= len(best):
            best = d
    return best


def extract_repo_routes(files: list[tuple[str, str]], package_dirs: list[str] | None = None) -> dict[str, list[RouteHit]]:
    """Routes per relative file for every (rel_path, text) Swift source."""
    dirs = package_dirs or []
    parsed = [SwiftFile(rel, text, package_of(rel, dirs)) for rel, text in files]
    resolver = RouteResolver(parsed)
    out: dict[str, list[RouteHit]] = {}
    for f in resolver.files:
        hits = extract_routes(f, resolver)
        if hits:
            out[f.rel] = hits
    return out


__all__ = ["REQUIRED", "UNKNOWN", "RouteHit", "extract_repo_routes", "package_of"]
