"""Find canary values in text, including disguised copies.

The sandbox's fake keys and fake chat text all carry a random canary. A plugin that
wants to slip a key past a simple check can encode it first (base64, hex, URL
escapes, rot13, reversed, compressed) or send it in pieces. This module undoes the
common disguises and reports which canaries it found and how they were hidden.

It only decodes; it never runs anything it finds. Work is capped so a hostile
plugin cannot make the check itself slow.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse
import zlib

MAX_TEXT = 400_000        # characters looked at per value
MAX_CANDIDATES = 400      # encoded-looking runs decoded per value
MAX_DECODED = 200_000     # bytes kept from one decode
DEPTH = 3                 # layers of encoding undone (e.g. base64 of gzip of hex)
BUDGET = 4_000_000        # characters examined in total for one value, across all layers

_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_B32_RE = re.compile(r"[A-Z2-7]{16,}=*")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_NON_ALNUM = re.compile(r"[^0-9A-Za-z]+")


def _squash(text: str) -> str:
    """Letters and digits only, lower case: undoes splitting with dots, dashes,
    spaces or line breaks (a key spread across DNS labels or chunks)."""
    return _NON_ALNUM.sub("", text).lower()


def _as_text(data: bytes) -> str:
    return data[:MAX_DECODED].decode("latin-1")


def _inflate(data: bytes):
    for wbits in (15, 31, -15):     # zlib, gzip, raw deflate
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(data, MAX_DECODED)
            if out:
                return out
        except zlib.error:
            continue
    return None


def _b32(token: str) -> bytes:
    body = token.rstrip("=")
    try:
        return base64.b32decode(body + "=" * (-len(body) % 8))
    except (binascii.Error, ValueError):
        cut = body[: len(body) // 8 * 8]
        return base64.b32decode(cut)


def _decodings(text: str, last: str = ""):
    """(how, decoded text) for every disguise this text might be wearing. `last` is
    the disguise just undone, so rot13 or reversing is not simply undone again."""
    out = []
    if _PCT_RE.search(text):
        out.append(("URL-encoded", urllib.parse.unquote_plus(text)))
    seen = 0
    for regex, how in ((_HEX_RE, "hex"), (_B64_RE, "base64"), (_B32_RE, "base32")):
        for m in regex.finditer(text):
            if seen >= MAX_CANDIDATES:
                break
            token = m.group(0)
            seen += 1
            try:
                if how == "hex":
                    raw = binascii.unhexlify(token[: len(token) // 2 * 2])
                elif how == "base32":
                    raw = _b32(token)
                else:
                    body = token.rstrip("=").replace("-", "+").replace("_", "/")
                    body = body[: len(body) // 4 * 4] if len(body) % 4 == 1 else body
                    raw = base64.b64decode(body + "=" * (-len(body) % 4))
            except (binascii.Error, ValueError):
                continue
            inflated = _inflate(raw)
            if inflated:
                out.append((f"{how} + compressed", _as_text(inflated)))
            out.append((how, _as_text(raw)))
    if last not in ("rot13", "reversed"):   # these two would just undo each other
        out.append(("rot13", codecs.decode(text, "rot13")))
        # Reverses text we were given (a tool result or URL) to look for a reversed key;
        # nothing decoded here is ever run. (Hermes's scanner lists this slice as low-risk obfuscation.)
        out.append(("reversed", text[::-1]))
    return out


RUN_BUDGET = 30_000_000   # characters decoded in total for one report; then plain and split checks only
_run_left = [RUN_BUDGET]


def reset_run_budget(total: int = RUN_BUDGET) -> None:
    """Called once per report, so a plugin that returns megabytes of random
    base64 from every hook cannot make judging it take minutes."""
    _run_left[0] = total


def run_budget_spent() -> bool:
    return _run_left[0] <= 0


def find(value_text: str, markers, depth: int = DEPTH, _budget=None, _last: str = "") -> dict:
    """{marker: how it was hidden} for every marker found in the text.
    "plain" means the marker is there as-is."""
    if _budget is None:
        _budget = [min(BUDGET, max(_run_left[0], 0))]
        start = _budget[0]
        try:
            return find(value_text, markers, depth, _budget, _last)
        finally:
            _run_left[0] -= start - _budget[0]
    budget = _budget
    text = value_text[:MAX_TEXT]
    budget[0] -= len(text)
    found = {m: "plain" for m in markers if m in text}
    left = [m for m in markers if m not in found]
    if not left:
        return found
    squashed = _squash(text)
    for m in left:
        if _squash(m) in squashed:
            found[m] = "split up or re-cased"
    left = [m for m in left if m not in found]
    if not left or depth <= 0 or budget[0] <= 0:
        return found
    for how, decoded in _decodings(text, _last):
        if not left or budget[0] <= 0:
            break
        for m, inner in find(decoded, left, depth - 1, budget, how).items():
            found[m] = how if inner == "plain" else f"{inner}, then {how}"
        left = [m for m in left if m not in found]
    return found


def views(value_text: str, depth: int = DEPTH) -> list:
    """Every decoded form of the text (the text itself first), within the same work
    caps as find(). Used by checks that need to look at what follows a marker, such
    as the outside monitor telling a fake key apart from a tagged chat canary."""
    budget = [min(BUDGET, max(_run_left[0], 0))]
    start = budget[0]
    out = []
    todo = [(value_text[:MAX_TEXT], depth, "")]
    try:
        while todo and budget[0] > 0:
            text, d, last = todo.pop(0)
            budget[0] -= len(text)
            out.append(text)
            out.append(_squash(text))
            if d > 0:
                queued = sum(len(t) for t, _, _ in todo)
                for how, t in _decodings(text, last):
                    if queued >= budget[0]:     # never hold more than is left to look at
                        break
                    todo.append((t[:MAX_TEXT], d - 1, how))
                    queued += len(todo[-1][0])
    finally:
        _run_left[0] -= start - budget[0]
    return out
