"""Linear Swift source helpers: bracket matching that understands Swift string
literals (interpolation, multi-line, raw ``#"..."#``) and nested comments.

Everything here runs on hostile input, so it is one forward pass per file with
bounded work per character, never raises on garbage, and never recurses.
"""

from __future__ import annotations

import bisect
import functools
import re
from dataclasses import dataclass, field

# Code mode: the next string start, comment start or bracket.
_CODE_TOKEN = re.compile(r'#*"""|#*"|//|/\*|[()\[\]{}]')
_BLOCK_COMMENT_TOKEN = re.compile(r"/\*|\*/")
_OPEN_TO_CLOSE = {"(": ")", "[": "]", "{": "}"}


@dataclass
class Source:
    """Bracket pairs (both directions) for code brackets, and the sorted
    spans of string literals and comments (``masked``)."""

    text: str
    pairs: dict[int, int] = field(default_factory=dict)
    rpairs: dict[int, int] = field(default_factory=dict)
    masked: list[tuple[int, int]] = field(default_factory=list)
    strings: list[tuple[int, int]] = field(default_factory=list)
    _starts: list[int] = field(default_factory=list)

    def in_masked(self, offset: int) -> bool:
        """True when ``offset`` falls inside a string literal or comment."""
        i = bisect.bisect_right(self._starts, offset) - 1
        return i >= 0 and self.masked[i][0] <= offset < self.masked[i][1]

    def close_of(self, offset: int) -> int:
        """Offset of the bracket closing the one at ``offset``, or -1."""
        return self.pairs.get(offset, -1)

    def open_of(self, offset: int) -> int:
        return self.rpairs.get(offset, -1)


@functools.lru_cache(maxsize=8)
def parse(text: str) -> Source:
    src = Source(text)
    stack: list[tuple[str, int]] = []
    n = len(text)
    pos = 0
    while pos < n:
        m = _CODE_TOKEN.search(text, pos)
        if m is None:
            break
        tok = m.group(0)
        start = m.start()
        if tok == "//":
            end = text.find("\n", start)
            end = n if end < 0 else end
            src.masked.append((start, end))
            pos = end
        elif tok == "/*":
            end = _skip_block_comment(text, start)
            src.masked.append((start, end))
            pos = end
        elif tok.endswith('"'):
            end = _skip_string(text, start, tok)
            src.masked.append((start, end))
            src.strings.append((start, end))
            pos = end
        elif tok in _OPEN_TO_CLOSE:
            stack.append((tok, start))
            pos = m.end()
        else:
            # A closer: pop to its opener; an unmatched closer is ignored.
            for depth in range(len(stack) - 1, max(-1, len(stack) - 8), -1):
                if _OPEN_TO_CLOSE[stack[depth][0]] == tok:
                    open_at = stack[depth][1]
                    del stack[depth:]
                    src.pairs[open_at] = start
                    src.rpairs[start] = open_at
                    break
            pos = m.end()
    src._starts = [s for s, _ in src.masked]
    return src


def _skip_block_comment(text: str, start: int) -> int:
    """End offset of the (nestable) block comment starting at ``start``."""
    depth = 0
    pos = start
    while True:
        m = _BLOCK_COMMENT_TOKEN.search(text, pos)
        if m is None:
            return len(text)
        depth += 1 if m.group(0) == "/*" else -1
        pos = m.end()
        if depth == 0:
            return pos


# Interpolations nested deeper than this end the literal (hostile input).
_MAX_NESTING = 16


@functools.lru_cache(maxsize=32)
def _string_token(hashes: int, multiline: bool) -> re.Pattern[str]:
    closer = ('"""' if multiline else '"') + "#" * hashes
    escape = "\\" + "#" * hashes
    alternatives = [re.escape(closer), re.escape(escape)]
    if not multiline:
        alternatives.append("\n")
    return re.compile("|".join(alternatives))


def _skip_string(text: str, start: int, opener: str, depth: int = 0) -> int:
    """End offset of the string literal starting at ``start``. Interpolations
    (``\\(...)``) are skipped as code, including strings nested in them."""
    hashes = len(opener) - len(opener.lstrip("#"))
    multiline = opener.endswith('"""')
    token = _string_token(hashes, multiline)
    escape_len = 1 + hashes
    pos = start + len(opener)
    n = len(text)
    while pos < n:
        m = token.search(text, pos)
        if m is None:
            return n
        tok = m.group(0)
        if tok == "\n":
            return m.start()  # unterminated single-line string
        if tok.startswith("\\"):
            after = m.start() + escape_len
            if after < n and text[after] == "(":
                if depth >= _MAX_NESTING:
                    return n
                pos = _skip_interpolation(text, after, depth + 1)
            else:
                pos = after + 1  # escaped character
            continue
        return m.end()
    return n


_INTERP_TOKEN = re.compile(r'#*"""|#*"|[()]')


def _skip_interpolation(text: str, paren: int, depth: int) -> int:
    """Offset just past the ``)`` closing the interpolation at ``paren``."""
    parens = 0
    pos = paren
    n = len(text)
    while pos < n:
        m = _INTERP_TOKEN.search(text, pos)
        if m is None:
            return n
        tok = m.group(0)
        if tok == "(":
            parens += 1
            pos = m.end()
        elif tok == ")":
            parens -= 1
            pos = m.end()
            if parens == 0:
                return pos
        else:
            pos = _skip_string(text, m.start(), tok, depth)
    return n


# ---------- Small helpers over a parsed Source ----------

_STRING_LITERAL = re.compile(r'"((?:[^"\\\n]|\\.)*)"')


def string_value(text: str) -> str | None:
    """The value of a plain, interpolation-free string literal expression
    (``"users"``), else None."""
    stripped = text.strip()
    m = _STRING_LITERAL.fullmatch(stripped)
    if m is None or "\\(" in m.group(1):
        return None
    return m.group(1)


def split_args(src: Source, open_paren: int, close_paren: int) -> list[tuple[int, int]]:
    """Top-level argument spans between a matched pair of brackets."""
    text = src.text
    spans: list[tuple[int, int]] = []
    pos = open_paren + 1
    start = pos
    while pos < close_paren:
        ch = text[pos]
        if ch in "([{":
            close = src.close_of(pos)
            if close < 0 or close > close_paren:
                break
            pos = close + 1
            continue
        if ch == '"' or (ch == "#" and pos + 1 < close_paren and text[pos + 1] in '#"'):
            i = bisect.bisect_right(src._starts, pos) - 1
            if i >= 0 and src.masked[i][0] == pos:
                pos = max(src.masked[i][1], pos + 1)
                continue
        if ch == "/" and src.in_masked(pos):
            i = bisect.bisect_right(src._starts, pos) - 1
            pos = max(src.masked[i][1], pos + 1)
            continue
        if ch == ",":
            spans.append((start, pos))
            start = pos + 1
        pos += 1
    if text[start:close_paren].strip():
        spans.append((start, close_paren))
    return spans


_LABEL = re.compile(r"\s*([A-Za-z_]\w*)\s*:(?!:)")


def arg_label(text: str) -> tuple[str | None, str]:
    """Split ``label: value`` into (label, value); (None, text) if unlabeled."""
    m = _LABEL.match(text)
    if m is None:
        return None, text.strip()
    return m.group(1), text[m.end():].strip()


def clip(text: str, limit: int = 200) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
