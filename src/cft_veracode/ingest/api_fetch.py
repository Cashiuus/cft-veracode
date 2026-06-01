"""Live fetcher: pull Findings v2 from the Veracode REST API.

Authentication uses Veracode's HMAC signing scheme via the official
`veracode-api-signing` helper package. Credentials are discovered in
this priority order:

  1. Explicit (api_id, api_key) tuple passed in.
  2. Environment variables VERACODE_API_KEY_ID + VERACODE_API_KEY_SECRET.
  3. `~/.veracode/credentials` file (the standard Veracode tooling location).

The fetcher follows HAL pagination links (`_links.next.href`) and returns
a synthesized document whose shape matches the file-based Findings v2
JSON export, so it can be passed directly to `parse_findings_api()`.

API endpoints used:
  GET /appsec/v1/applications?name=<urlencoded>     (resolve name -> GUID)
  GET /appsec/v2/applications/{guid}/findings        (Findings v2)
  GET /appsec/v1/applications/{guid}/sandboxes       (sandbox resolution)
"""
from __future__ import annotations

import configparser
import os
import urllib.parse
from pathlib import Path
from typing import Optional, Tuple

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

API_BASE = "https://api.veracode.com"
APPS_URL = f"{API_BASE}/appsec/v1/applications"
FINDINGS_URL = f"{API_BASE}/appsec/v2/applications/{{guid}}/findings"
SANDBOXES_URL = f"{API_BASE}/appsec/v1/applications/{{guid}}/sandboxes"

DEFAULT_PAGE_SIZE = 500       # max permitted; minimises round-trips


class VeracodeAPIError(RuntimeError):
    """Raised on any non-2xx response or unexpected shape."""


class CredentialsNotFound(RuntimeError):
    """Raised when no Veracode credentials are discoverable."""


# ---------------------------------------------------------------------------
# Credential discovery
# ---------------------------------------------------------------------------

def discover_credentials(
    api_id: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Tuple[str, str]:
    """Return (api_id, api_key) using the standard Veracode lookup order.

    Raises CredentialsNotFound if nothing is available.
    """
    if api_id and api_key:
        return api_id, api_key

    env_id = os.environ.get("VERACODE_API_KEY_ID")
    env_key = os.environ.get("VERACODE_API_KEY_SECRET")
    if env_id and env_key:
        return env_id, env_key

    creds_path = Path.home() / ".veracode" / "credentials"
    if creds_path.is_file():
        cfg = configparser.ConfigParser()
        cfg.read(creds_path)
        # The Veracode credentials file uses a [default] section by convention.
        section = "default" if "default" in cfg else (cfg.sections()[0] if cfg.sections() else None)
        if section:
            file_id = cfg[section].get("veracode_api_key_id")
            file_key = cfg[section].get("veracode_api_key_secret")
            if file_id and file_key:
                return file_id, file_key

    raise CredentialsNotFound(
        "No Veracode credentials found. Set VERACODE_API_KEY_ID and "
        "VERACODE_API_KEY_SECRET environment variables, or create "
        "~/.veracode/credentials with a [default] section."
    )


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------

def resolve_app_guid(
    app_identifier: str,
    *,
    api_id: Optional[str] = None,
    api_key: Optional[str] = None,
    session: Optional[requests.Session] = None,
) -> str:
    """Return the app GUID. If `app_identifier` already looks like a GUID, returns it as-is."""
    if _looks_like_guid(app_identifier):
        return app_identifier

    sess = session or _make_session(api_id, api_key)
    # Pre-encode and build the URL manually: requests' default params encoder
    # uses quote_plus (spaces -> "+"), but Veracode's name filter expects strict
    # RFC 3986 percent-encoding. Passing a pre-encoded value through params=
    # would double-encode, so we splice it into the URL ourselves.
    encoded_name = urllib.parse.quote(app_identifier, safe="")
    r = sess.get(f"{APPS_URL}?name={encoded_name}&size=25")
    _raise_for_status(r, "applications lookup")
    embedded = (r.json().get("_embedded") or {}).get("applications") or []
    # Veracode's name filter is a substring match; pick exact name when present
    exact = [a for a in embedded if (a.get("profile") or {}).get("name") == app_identifier]
    chosen = exact[0] if exact else (embedded[0] if embedded else None)
    if chosen is None:
        raise VeracodeAPIError(f"No application matches name {app_identifier!r}")
    guid = chosen.get("guid")
    if not guid:
        raise VeracodeAPIError(f"Application record for {app_identifier!r} has no guid")
    return guid


def resolve_sandbox_guid(
    app_guid: str,
    sandbox_name: str,
    *,
    api_id: Optional[str] = None,
    api_key: Optional[str] = None,
    session: Optional[requests.Session] = None,
) -> str:
    sess = session or _make_session(api_id, api_key)
    r = sess.get(SANDBOXES_URL.format(guid=app_guid), params={"size": 100})
    _raise_for_status(r, "sandbox lookup")
    sandboxes = (r.json().get("_embedded") or {}).get("sandboxes") or []
    for s in sandboxes:
        if s.get("name") == sandbox_name:
            sg = s.get("guid")
            if sg:
                return sg
    raise VeracodeAPIError(f"No sandbox named {sandbox_name!r} on app {app_guid!r}")


# ---------------------------------------------------------------------------
# Findings fetch
# ---------------------------------------------------------------------------

def fetch_findings(
    app_identifier: str,
    *,
    sandbox: Optional[str] = None,
    scan_type: str = "STATIC",
    api_id: Optional[str] = None,
    api_key: Optional[str] = None,
    session: Optional[requests.Session] = None,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> dict:
    """Fetch all findings for an app and return a Findings-v2-shaped document.

    The returned dict matches the layout consumed by `parse_findings_api()`:
        {
          "application_name": ...,
          "sandbox_name": ...,
          "scan_type": "STATIC",
          "_embedded": { "findings": [...] }
        }
    """
    sess = session or _make_session(api_id, api_key)

    app_guid = resolve_app_guid(app_identifier, session=sess)
    sandbox_guid = resolve_sandbox_guid(app_guid, sandbox, session=sess) if sandbox else None

    params: dict[str, object] = {"size": page_size, "scan_type": scan_type}
    if sandbox_guid:
        params["context"] = sandbox_guid

    all_findings: list[dict] = []
    next_url: Optional[str] = FINDINGS_URL.format(guid=app_guid)
    first_query = True

    while next_url:
        r = sess.get(next_url, params=params if first_query else None)
        _raise_for_status(r, "findings fetch")
        body = r.json()
        embedded = (body.get("_embedded") or {}).get("findings") or []
        all_findings.extend(embedded)
        next_link = (body.get("_links") or {}).get("next")
        next_url = next_link.get("href") if isinstance(next_link, dict) else None
        first_query = False  # don't re-apply params to follow-up paginated URLs (they already encode page/size)

    return {
        "application_name": app_identifier if not _looks_like_guid(app_identifier) else None,
        "sandbox_name": sandbox,
        "scan_type": scan_type,
        "_embedded": {"findings": all_findings},
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session(api_id: Optional[str], api_key: Optional[str]) -> requests.Session:
    """Create a requests Session with the Veracode HMAC auth plugin attached.

    The plugin discovers credentials from env / ~/.veracode/credentials on its own
    if api_id/api_key aren't supplied, but we explicitly resolve first so we can
    raise a friendly error before the plugin tries.
    """
    resolved_id, resolved_key = discover_credentials(api_id, api_key)
    # The signing plugin reads from env vars; export them if not already set,
    # so the plugin sees them whether the caller put them there or not.
    os.environ.setdefault("VERACODE_API_KEY_ID", resolved_id)
    os.environ.setdefault("VERACODE_API_KEY_SECRET", resolved_key)
    sess = requests.Session()
    sess.auth = RequestsAuthPluginVeracodeHMAC()
    sess.headers.update({"Accept": "application/json"})
    return sess


def _looks_like_guid(s: str) -> bool:
    # Veracode GUIDs are UUID-format (8-4-4-4-12 hex chars)
    if not isinstance(s, str) or len(s) != 36:
        return False
    parts = s.split("-")
    if len(parts) != 5 or [len(p) for p in parts] != [8, 4, 4, 4, 12]:
        return False
    return all(c in "0123456789abcdefABCDEF" for p in parts for c in p)


def _raise_for_status(resp: requests.Response, what: str) -> None:
    if not resp.ok:
        # Veracode errors are usually JSON with `message` or `_embedded.errors`
        try:
            payload = resp.json()
        except Exception:
            payload = resp.text[:500]
        raise VeracodeAPIError(f"{what} failed ({resp.status_code}): {payload}")
