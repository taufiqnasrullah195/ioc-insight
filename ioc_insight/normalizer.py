"""IOC normalization — type auto-detection, defang/refang, validation. TRD §2.1.

Supported types: ipv4, ipv6, domain, url, md5, sha1, sha256.
Defanged forms handled: hxxp(s)://, [.], (.) , [dot], hxxps, [:], @ -> [at].
"""
from __future__ import annotations

import ipaddress
import re

from .models import IOC, IOCType

_HASH_RE = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# order matters: longest/most-specific first
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_URL_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)

_DEFANG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[at\]", re.IGNORECASE), "@"),
]


class InvalidIOCError(ValueError):
    """Raised when input cannot be classified as any supported IOC type."""


def refang(text: str) -> str:
    """Convert defanged IOC text to its live form."""
    out = text.strip()
    for pattern, repl in _DEFANG_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def defang(text: str) -> str:
    """Convert a live IOC to safe defanged form for reports."""
    out = text.replace("https://", "hxxps://").replace("http://", "hxxp://")
    out = out.replace(".", "[.]")
    return out


def detect_type(value: str) -> IOCType:
    """Classify a refanged IOC string. Raises InvalidIOCError if no match."""
    v = value.strip()
    if not v:
        raise InvalidIOCError("empty input")

    # IP addresses first (cheap, unambiguous)
    try:
        ip = ipaddress.ip_address(v)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass

    # hashes: pure hex of specific length
    if _HEX_RE.match(v) and len(v) in _HASH_RE:
        return _HASH_RE[len(v)]  # type: ignore[return-value]

    # URL: has http(s) scheme
    if _URL_SCHEME_RE.match(v):
        return "url"

    # domain — strip trailing dot first; reject all-numeric dotted quads
    # like 999.999.999.999 that failed ip parsing but match domain syntax
    d = v.rstrip(".")
    if _DOMAIN_RE.match(d):
        labels = d.split(".")
        if not all(label.isdigit() for label in labels):
            return "domain"

    raise InvalidIOCError(f"cannot classify IOC: {v!r}")


def normalize(raw: str) -> IOC:
    """Full pipeline: defanged input → typed, refanged IOC."""
    value = refang(raw)
    ioc_type = detect_type(value)
    if ioc_type in ("md5", "sha1", "sha256"):
        value = value.lower()
    if ioc_type == "domain":
        value = value.lower().rstrip(".")
    return IOC(raw=raw, value=value, type=ioc_type)
