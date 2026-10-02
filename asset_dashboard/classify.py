"""Classify inventory criticality from URL structure only (no network I/O)."""

from __future__ import annotations

from .parser import ParsedAsset

# Highest matching bucket wins. Patterns describe asset *role*, not exploitability.
_CRITICAL_PATH_MARKERS = (
    "/admin",
    "/wp-admin",
    "/phpmyadmin",
    "/cpanel",
    "/console",
    "/actuator",
    "/idrac",
    "/ipmi",
    "/jenkins",
    "/grafana",
    "/kibana",
)
_CRITICAL_HOST_LABELS = frozenset({"vpn", "firewall", "idrac", "bastion", "jump", "kube", "k8s"})
_HIGH_PATH_MARKERS = (
    "/api",
    "/graphql",
    "/oauth",
    "/sso",
    "/auth",
    "/login",
    "/signin",
    "/token",
    "/billing",
    "/checkout",
    "/payment",
)
_HIGH_HOST_LABELS = frozenset({"auth", "sso", "api", "prod", "payment", "billing"})
_LOW_HOST_LABELS = frozenset({"dev", "staging", "stage", "test", "qa", "sandbox", "localhost", "local"})


def classify_asset_severity(asset: ParsedAsset) -> str:
    """Return an inventory severity label for a verified asset endpoint."""
    labels = _host_labels(asset.host)
    path = asset.path.lower()

    if _path_contains(path, _CRITICAL_PATH_MARKERS) or labels & _CRITICAL_HOST_LABELS:
        return "critical"
    if _path_contains(path, _HIGH_PATH_MARKERS) or labels & _HIGH_HOST_LABELS:
        return "high"
    if labels & _LOW_HOST_LABELS:
        return "low"
    if asset.scheme == "http":
        return "low"
    return "medium"


def _host_labels(host: str) -> set[str]:
    return {part for part in host.split(".") if part}


def _path_contains(path: str, markers: tuple[str, ...]) -> bool:
    return any(
        path == marker
        or path.startswith(f"{marker}/")
        or f"{marker}/" in path
        or path.endswith(marker)
        for marker in markers
    )
