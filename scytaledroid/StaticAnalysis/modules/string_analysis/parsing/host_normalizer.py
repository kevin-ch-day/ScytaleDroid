"""Host normalisation helpers."""
# host_normalizer.py
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

# Your curated multi-level public suffixes (e.g., "co.uk", "com.au", "co.jp", ...)
from ..constants import MULTI_LEVEL_SUFFIXES


@dataclass(frozen=True)
class NormalizedHost:
    full_host: str | None      # host without port/brackets, IDNA-lowered (or raw IP)
    etld_plus_one: str | None  # registrable root for domain hosts; None for IPs
    is_ip: bool                # True for IPv4/IPv6 literals


def _strip_brackets_and_port(raw: str) -> tuple[str, bool]:
    """
    Return (host_no_port, is_bracketed_ipv6).

    Handles:
      - "[2001:db8::1]:443"  -> ("2001:db8::1", True)
      - "[fe80::1%eth0]"     -> ("fe80::1%eth0", True)
      - "example.com:8080"   -> ("example.com", False)   (only if :port looks numeric)
      - "example.com"        -> ("example.com", False)
    """
    s = raw.strip().strip(".")  # drop trailing dot if present
    if not s:
        return "", False

    # Bracketed IPv6 (possibly with port)
    if s.startswith("["):
        # Find closing bracket; ignore any text after it (may be :port)
        close = s.find("]")
        if close > 0:
            core = s[1:close]
            # If there's a ":<digits>" immediately after ']', drop it
            rest = s[close + 1 :]
            if rest.startswith(":"):
                # best-effort numeric check; don't be overly strict
                port = rest[1:]
                if port.isdigit():
                    return core, True
            return core, True
        # Malformed bracket; fall through (let ipaddress validation reject it)
        return s, True

    # Non-bracketed host: strip ":<digits>" if present at end
    # (Avoid breaking non-port colons inside tokens like "h:foo" by requiring digits)
    if ":" in s:
        looks_like_ipv6 = s.count(":") > 1 or "::" in s or "%" in s
        if looks_like_ipv6:
            try:
                ipaddress.ip_address(s)
                return s, False
            except ValueError:
                if "%" in s:
                    base, _, _ = s.partition("%")
                    try:
                        ipaddress.ip_address(base)
                        return s, False
                    except ValueError:
                        pass
        host, _, maybe_port = s.rpartition(":")
        if host and maybe_port.isdigit():
            return host, False

    return s, False


def registrable_domain(host: str | None) -> str | None:
    """Return the eTLD+1 (registrable root) for *host* if available."""
    if not host:
        return None

    lowered = host.strip(".").lower()
    if not lowered:
        return None

    # Special single-label host
    if lowered == "localhost":
        return "localhost"

    parts = lowered.split(".")
    if len(parts) <= 2:
        # "a.b" or single label → return as-is (policy layer can decide on placeholders)
        return lowered

    # last two labels always a candidate
    last_two = ".".join(parts[-2:])

    # If the last two labels form a known multi-level public suffix, take three
    if last_two in MULTI_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])

    # Otherwise eTLD+1 is the last two labels
    return last_two


def normalize_host(host: str | None) -> NormalizedHost:
    """
    Return a normalized host representation suitable for policy checks.

    Normalization rules:
      • Strip whitespace, trailing dot, enclosing IPv6 brackets, and :port.
      • Lowercase + IDNA-encode domain labels (preserve raw IPs).
      • eTLD+1 computed for domain hosts using MULTI_LEVEL_SUFFIXES; None for IPs.
      • 'localhost' is preserved as both full_host and etld_plus_one.
    """
    if not host:
        return NormalizedHost(full_host=None, etld_plus_one=None, is_ip=False)

    candidate, was_bracketed = _strip_brackets_and_port(host)
    candidate = candidate.lower()

    if not candidate:
        return NormalizedHost(full_host=None, etld_plus_one=None, is_ip=False)

    # 'localhost' shortcut
    if candidate == "localhost":
        return NormalizedHost(full_host="localhost", etld_plus_one="localhost", is_ip=False)

    # IP literal?
    is_ip_host = False
    try:
        # ipaddress doesn't accept brackets; we've stripped them above.
        ipaddress.ip_address(candidate)
        is_ip_host = True
    except ValueError:
        is_ip_host = False

    if is_ip_host:
        # For IPs there is no registrable root; keep the literal without brackets.
        return NormalizedHost(full_host=candidate, etld_plus_one=None, is_ip=True)

    # Domain name: IDNA punycode normalize, best-effort (don’t explode on bad input)
    try:
        # Normalize each label; this also normalizes Unicode dots only if already split.
        idna_host = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        idna_host = candidate  # fall back to lowercase candidate

    return NormalizedHost(
        full_host=idna_host,
        etld_plus_one=registrable_domain(idna_host),
        is_ip=False,
    )


__all__ = ["NormalizedHost", "normalize_host", "registrable_domain"]