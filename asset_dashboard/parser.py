"""Sanitize plaintext asset lines into canonical http(s) URLs."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class ParsedAsset:
    """A verified, canonical asset endpoint."""

    url: str
    scheme: str
    host: str
    port: int | None
    path: str
    source_line: str


def parse_asset_endpoint(raw_line: str) -> ParsedAsset | None:
    """Return a canonical asset URL, or None if the line is not a valid endpoint.

    Empty lines and ``#`` comments are ignored. Userinfo is stripped so credential
    material cannot be stored as part of the asset identity. Only ``http`` and
    ``https`` endpoints are accepted.
    """
    if raw_line is None:
        return None

    source_line = raw_line.strip()
    if not source_line or source_line.startswith("#"):
        return None

    candidate = _ensure_scheme(source_line)
    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return None

    host = (parts.hostname or "").lower().rstrip(".")
    if not _is_valid_host(host):
        return None

    try:
        port = parts.port
    except ValueError:
        return None

    if port is not None and not (1 <= port <= 65535):
        return None
    if port == _DEFAULT_PORTS[scheme]:
        port = None

    path = parts.path or "/"
    query = parts.query
    netloc = host if port is None else f"{host}:{port}"
    canonical = urlunsplit((scheme, netloc, path, query, ""))
    return ParsedAsset(
        url=canonical,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        source_line=source_line,
    )


def _ensure_scheme(value: str) -> str:
    parts = urlsplit(value)
    if parts.scheme:
        return value
    if value.startswith("//"):
        return f"https:{value}"
    return f"https://{value}"


def _is_valid_host(host: str) -> bool:
    if not host or host.startswith("[") or " " in host:
        return False
    if host in {"localhost"}:
        return True
    if _is_ipv4(host):
        return True
    if "." not in host:
        return False
    labels = host.split(".")
    return all(label and not label.startswith("-") and not label.endswith("-") for label in labels)


def _is_ipv4(host: str) -> bool:
    octets = host.split(".")
    if len(octets) != 4:
        return False
    try:
        return all(octet == str(int(octet)) and 0 <= int(octet) <= 255 for octet in octets)
    except ValueError:
        return False
