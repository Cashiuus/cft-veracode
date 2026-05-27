"""Tests for the Veracode API fetcher (mocked HTTP)."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
import responses

from cft_veracode.ingest.api_fetch import (
    APPS_URL,
    FINDINGS_URL,
    SANDBOXES_URL,
    CredentialsNotFound,
    VeracodeAPIError,
    discover_credentials,
    fetch_findings,
    resolve_app_guid,
    _looks_like_guid,
)


# ---------------------------------------------------------------------------
# Credential discovery
# ---------------------------------------------------------------------------

def test_explicit_credentials_passthrough():
    assert discover_credentials("explicit-id", "explicit-secret") == ("explicit-id", "explicit-secret")


def test_env_var_credentials(monkeypatch):
    monkeypatch.setenv("VERACODE_API_KEY_ID", "env-id")
    monkeypatch.setenv("VERACODE_API_KEY_SECRET", "env-secret")
    assert discover_credentials() == ("env-id", "env-secret")


def test_no_credentials_raises(monkeypatch, tmp_path):
    monkeypatch.delenv("VERACODE_API_KEY_ID", raising=False)
    monkeypatch.delenv("VERACODE_API_KEY_SECRET", raising=False)
    # Redirect HOME so the function can't find a real credentials file
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    with patch("cft_veracode.ingest.api_fetch.Path.home", return_value=tmp_path):
        with pytest.raises(CredentialsNotFound):
            discover_credentials()


def test_credentials_file_discovery(monkeypatch, tmp_path):
    monkeypatch.delenv("VERACODE_API_KEY_ID", raising=False)
    monkeypatch.delenv("VERACODE_API_KEY_SECRET", raising=False)
    creds_dir = tmp_path / ".veracode"
    creds_dir.mkdir()
    (creds_dir / "credentials").write_text(
        "[default]\n"
        "veracode_api_key_id = file-id\n"
        "veracode_api_key_secret = file-secret\n"
    )
    with patch("cft_veracode.ingest.api_fetch.Path.home", return_value=tmp_path):
        assert discover_credentials() == ("file-id", "file-secret")


# ---------------------------------------------------------------------------
# GUID heuristic
# ---------------------------------------------------------------------------

def test_guid_heuristic():
    assert _looks_like_guid("00000000-1111-2222-3333-444444444444")
    assert not _looks_like_guid("MyAppName")
    assert not _looks_like_guid("00000000-1111-2222-3333-44444444444")   # too short
    assert not _looks_like_guid("00000000-1111-2222-3333-44444444444Z")  # bad hex


# ---------------------------------------------------------------------------
# Helpers — preload env so the HMAC plugin doesn't complain
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    # The veracode-api-signing plugin validates that credentials look like real
    # API keys (32+ hex chars) before it will sign a request. The values below
    # pass that format check; the `responses` library intercepts every HTTP call
    # before it goes anywhere, so the signature itself is never verified.
    monkeypatch.setenv("VERACODE_API_KEY_ID", "0123456789abcdef0123456789abcdef")
    # Secret must be at least 128 chars of hex per the plugin's validator
    monkeypatch.setenv("VERACODE_API_KEY_SECRET", "fedcba9876543210" * 8)
    yield


# ---------------------------------------------------------------------------
# resolve_app_guid
# ---------------------------------------------------------------------------

@responses.activate
def test_resolve_app_guid_by_name():
    responses.add(
        method=responses.GET,
        url=APPS_URL,
        json={
            "_embedded": {
                "applications": [
                    {"guid": "11111111-1111-1111-1111-111111111111",
                     "profile": {"name": "DemoApp"}},
                ],
            },
        },
    )
    assert resolve_app_guid("DemoApp") == "11111111-1111-1111-1111-111111111111"


@responses.activate
def test_resolve_app_guid_prefers_exact_match():
    responses.add(
        method=responses.GET,
        url=APPS_URL,
        json={
            "_embedded": {
                "applications": [
                    {"guid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                     "profile": {"name": "DemoAppPrototype"}},   # substring match
                    {"guid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                     "profile": {"name": "DemoApp"}},             # exact match — should win
                ],
            },
        },
    )
    assert resolve_app_guid("DemoApp") == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


def test_resolve_app_guid_passthrough_when_guid():
    g = "deadbeef-dead-beef-dead-beefdeadbeef"
    # No HTTP call required when input is already a GUID
    assert resolve_app_guid(g) == g


@responses.activate
def test_resolve_app_guid_no_match_raises():
    responses.add(method=responses.GET, url=APPS_URL, json={"_embedded": {"applications": []}})
    with pytest.raises(VeracodeAPIError):
        resolve_app_guid("NonexistentApp")


# ---------------------------------------------------------------------------
# fetch_findings — single page
# ---------------------------------------------------------------------------

@responses.activate
def test_fetch_findings_single_page():
    guid = "33333333-3333-3333-3333-333333333333"
    # First: name -> GUID lookup
    responses.add(
        method=responses.GET,
        url=APPS_URL,
        json={"_embedded": {"applications": [
            {"guid": guid, "profile": {"name": "DemoApp"}},
        ]}},
    )
    # Then: findings (no next link)
    responses.add(
        method=responses.GET,
        url=FINDINGS_URL.format(guid=guid),
        json={
            "_embedded": {
                "findings": [
                    {
                        "issue_id": 1,
                        "scan_type": "STATIC",
                        "violates_policy": True,
                        "finding_status": {"status": "OPEN", "resolution": "UNRESOLVED"},
                        "finding_details": {
                            "severity": 4,
                            "cwe": {"id": 89, "name": "SQL Injection"},
                            "file_path": "src/Foo.java",
                            "file_line_number": 10,
                        },
                    },
                ],
            },
            "_links": {"self": {"href": "..."}},
        },
    )

    doc = fetch_findings("DemoApp")
    assert doc["scan_type"] == "STATIC"
    assert doc["application_name"] == "DemoApp"
    assert len(doc["_embedded"]["findings"]) == 1
    assert doc["_embedded"]["findings"][0]["issue_id"] == 1


# ---------------------------------------------------------------------------
# fetch_findings — pagination across two pages
# ---------------------------------------------------------------------------

@responses.activate
def test_fetch_findings_follows_pagination():
    guid = "44444444-4444-4444-4444-444444444444"
    responses.add(
        method=responses.GET,
        url=APPS_URL,
        json={"_embedded": {"applications": [
            {"guid": guid, "profile": {"name": "DemoApp"}},
        ]}},
    )
    page1_url = FINDINGS_URL.format(guid=guid)
    page2_url = "https://api.veracode.com/appsec/v2/applications/x/findings?page=1"
    responses.add(
        method=responses.GET,
        url=page1_url,
        json={
            "_embedded": {"findings": [{"issue_id": 1, "finding_details": {"severity": 2, "cwe": {"id": 89}}}]},
            "_links": {"next": {"href": page2_url}},
        },
    )
    responses.add(
        method=responses.GET,
        url=page2_url,
        json={
            "_embedded": {"findings": [
                {"issue_id": 2, "finding_details": {"severity": 2, "cwe": {"id": 89}}},
                {"issue_id": 3, "finding_details": {"severity": 2, "cwe": {"id": 79}}},
            ]},
            "_links": {"self": {"href": page2_url}},
        },
    )

    doc = fetch_findings("DemoApp")
    ids = [f["issue_id"] for f in doc["_embedded"]["findings"]]
    assert ids == [1, 2, 3]


# ---------------------------------------------------------------------------
# Sandbox flow
# ---------------------------------------------------------------------------

@responses.activate
def test_fetch_findings_with_sandbox():
    guid = "55555555-5555-5555-5555-555555555555"
    sg = "66666666-6666-6666-6666-666666666666"
    responses.add(method=responses.GET, url=APPS_URL,
                  json={"_embedded": {"applications": [{"guid": guid, "profile": {"name": "DemoApp"}}]}})
    responses.add(method=responses.GET, url=SANDBOXES_URL.format(guid=guid),
                  json={"_embedded": {"sandboxes": [{"guid": sg, "name": "DevSandbox"}]}})
    responses.add(method=responses.GET, url=FINDINGS_URL.format(guid=guid),
                  json={"_embedded": {"findings": []}, "_links": {}})

    doc = fetch_findings("DemoApp", sandbox="DevSandbox")
    assert doc["sandbox_name"] == "DevSandbox"


@responses.activate
def test_fetch_findings_unknown_sandbox_raises():
    guid = "77777777-7777-7777-7777-777777777777"
    responses.add(method=responses.GET, url=APPS_URL,
                  json={"_embedded": {"applications": [{"guid": guid, "profile": {"name": "DemoApp"}}]}})
    responses.add(method=responses.GET, url=SANDBOXES_URL.format(guid=guid),
                  json={"_embedded": {"sandboxes": [{"guid": "x", "name": "OtherSandbox"}]}})
    with pytest.raises(VeracodeAPIError):
        fetch_findings("DemoApp", sandbox="MissingSandbox")


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

@responses.activate
def test_fetch_findings_propagates_api_error():
    guid = "88888888-8888-8888-8888-888888888888"
    responses.add(method=responses.GET, url=APPS_URL,
                  json={"_embedded": {"applications": [{"guid": guid, "profile": {"name": "DemoApp"}}]}})
    responses.add(method=responses.GET, url=FINDINGS_URL.format(guid=guid),
                  json={"message": "internal server error"}, status=500)
    with pytest.raises(VeracodeAPIError) as ei:
        fetch_findings("DemoApp")
    assert "findings fetch" in str(ei.value)


# ---------------------------------------------------------------------------
# End-to-end: fetched doc → parse_findings_api → Finding[]
# ---------------------------------------------------------------------------

@responses.activate
def test_fetched_doc_feeds_existing_parser():
    """The whole point: a fetched doc must be consumable by parse_findings_api()."""
    from cft_veracode.ingest import parse_findings_api

    guid = "99999999-9999-9999-9999-999999999999"
    responses.add(method=responses.GET, url=APPS_URL,
                  json={"_embedded": {"applications": [{"guid": guid, "profile": {"name": "DemoApp"}}]}})
    responses.add(
        method=responses.GET,
        url=FINDINGS_URL.format(guid=guid),
        json={
            "_embedded": {
                "findings": [{
                    "issue_id": 7,
                    "scan_type": "STATIC",
                    "violates_policy": True,
                    "finding_status": {"status": "OPEN", "resolution": "UNRESOLVED"},
                    "finding_details": {
                        "severity": 4,
                        "cwe": {"id": 89, "name": "SQL Injection"},
                        "file_path": "src/Bar.java",
                        "file_line_number": 22,
                    },
                }],
            },
        },
    )

    doc = fetch_findings("DemoApp")
    findings = parse_findings_api(doc)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-89"
    assert findings[0].location.file_path == "src/Bar.java"
    assert findings[0].location.line == 22
    assert findings[0].severity == "High"
    assert findings[0].scanner == "veracode-api"
