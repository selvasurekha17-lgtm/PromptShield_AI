"""test_share_route.py — Automated Flask test client tests for the /share route.

Tests:
1. GET /share  — returns 200 with HTML
2. POST /share with text=Hello — returns 200 with prefill variable
3. POST /share with empty text — returns 200 (no crash, no prefill)
4. POST /share with oversized text — truncated to 5000 chars
5. POST /share with title + text + url — combines all three
6. GET /manifest.webmanifest — returns 200 with application/manifest+json
7. GET /static/js/service-worker.js — returns 200
8. GET /api/education — returns all 15 taxonomies
9. Education taxonomies have enriched fields (how_it_works, example_message_en, etc.)
"""

import json
import sys
import os

# Ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest
from server import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ── 1. GET /share ─────────────────────────────────────────────────────────────
def test_share_get_returns_200(client):
    resp = client.get("/share")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    assert b"PromptShield" in resp.data or b"promptshield" in resp.data.lower()
    print("PASS  GET /share returns 200")


# ── 2. POST /share with text ───────────────────────────────────────────────────
def test_share_post_with_text_prefills(client):
    test_message = "URGENT: Share your OTP to unblock your account."
    resp = client.post("/share", data={"text": test_message})
    assert resp.status_code == 200
    # The prefill message must appear as a JSON string in the page (Jinja tojson filter)
    assert test_message.encode() in resp.data or b"URGENT" in resp.data
    print("PASS  POST /share with text=... prefills message")


# ── 3. POST /share with empty text ────────────────────────────────────────────
def test_share_post_empty_text_no_crash(client):
    resp = client.post("/share", data={"text": ""})
    assert resp.status_code == 200
    # Page loads fine — prefill variable should be null
    assert b"null" in resp.data
    print("PASS  POST /share with empty text returns 200 and null prefill")


# ── 4. POST /share with oversized text — truncated to 5000 ───────────────────
def test_share_post_oversized_text_truncated(client):
    big_text = "X" * 7000
    resp = client.post("/share", data={"text": big_text})
    assert resp.status_code == 200
    # The raw 7000-char string must NOT appear verbatim; truncated version does
    decoded = resp.data.decode("utf-8", errors="replace")
    # JSON-encoded version of the first 5000 'X' chars
    truncated_json = json.dumps("X" * 5000)
    assert truncated_json in decoded, "Oversized text was not truncated to 5000 chars"
    # 7000-char string should not appear
    assert ("X" * 6000) not in decoded
    print("PASS  POST /share with 7000-char text is truncated to 5000")


# ── 5. POST /share with title + text + url ────────────────────────────────────
def test_share_post_combines_title_text_url(client):
    resp = client.post("/share", data={
        "title": "Suspicious Message",
        "text": "Click here to claim your prize.",
        "url": "http://fake-prize.xyz"
    })
    assert resp.status_code == 200
    decoded = resp.data.decode("utf-8", errors="replace")
    # Combined string should include all three parts
    assert "Suspicious Message" in decoded
    assert "Click here to claim your prize." in decoded
    assert "http://fake-prize.xyz" in decoded
    print("PASS  POST /share combines title + text + url correctly")


# ── 6. GET /manifest.webmanifest ──────────────────────────────────────────────
def test_manifest_returns_200(client):
    resp = client.get("/static/manifest.webmanifest")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    # Should be valid JSON
    manifest = json.loads(resp.data)
    assert manifest["name"] == "PromptShield AI"
    assert "share_target" in manifest
    assert manifest["share_target"]["action"] == "/share"
    assert manifest["share_target"]["method"] == "POST"
    print("PASS  GET /manifest.webmanifest returns valid PWA manifest with share_target")


# ── 7. GET /service-worker.js (root) & /static/js/service-worker.js ──────────
def test_service_worker_returns_200(client):
    resp_root = client.get("/service-worker.js")
    assert resp_root.status_code == 200, f"Expected 200, got {resp_root.status_code}"
    assert resp_root.headers.get("Service-Worker-Allowed") == "/"
    assert b"PromptShield" in resp_root.data or b"promptshield" in resp_root.data.lower()

    resp_static = client.get("/static/js/service-worker.js")
    assert resp_static.status_code == 200, f"Expected 200, got {resp_static.status_code}"
    print("PASS  GET /service-worker.js returns 200 with Service-Worker-Allowed: /")


# ── 8. 404 handler renders safely without Jinja Undefined error ──────────────
def test_404_html_renders_without_template_error(client):
    resp = client.get("/this-route-does-not-exist")
    assert resp.status_code == 404
    assert b"PromptShield" in resp.data
    print("PASS  GET /this-route-does-not-exist returns 404 cleanly without template error")


# ── 9. Website Share UX elements present on homepage ─────────────────────────
def test_homepage_contains_share_ux_elements(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"paste-clipboard-btn" in resp.data
    assert b"share-guide-panel" in resp.data
    print("PASS  Homepage includes Paste from Clipboard button and Share Guide panel")


# ── 8. GET /api/education — 15 taxonomies ─────────────────────────────────────
def test_education_returns_15_taxonomies(client):
    resp = client.get("/api/education")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "taxonomies" in data
    taxonomies = data["taxonomies"]
    count = len(taxonomies)
    assert count == 15, f"Expected 15 taxonomies, got {count}"
    print(f"PASS  GET /api/education returns 15 taxonomies (got {count})")


# ── 9. Enriched taxonomy fields ───────────────────────────────────────────────
def test_education_taxonomies_have_enriched_fields(client):
    resp = client.get("/api/education")
    data = resp.get_json()
    taxonomies = data["taxonomies"]
    required_fields = [
        "id", "title", "icon", "category", "summary",
        "how_it_works", "warning_signs",
        "example_message_en", "example_message_ta", "example_message_tanglish",
        "why_suspicious", "victim_steps", "recommended_action"
    ]
    for tax in taxonomies:
        for field in required_fields:
            assert field in tax, (
                f"Taxonomy '{tax.get('id', '?')}' is missing field '{field}'"
            )
    print(f"PASS  All 15 taxonomies have enriched fields: {required_fields}")


# ── Runner ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_cases = [
        test_share_get_returns_200,
        test_share_post_with_text_prefills,
        test_share_post_empty_text_no_crash,
        test_share_post_oversized_text_truncated,
        test_share_post_combines_title_text_url,
        test_manifest_returns_200,
        test_service_worker_returns_200,
        test_404_html_renders_without_template_error,
        test_homepage_contains_share_ux_elements,
        test_education_returns_15_taxonomies,
        test_education_taxonomies_have_enriched_fields,
    ]

    app.config["TESTING"] = True
    with app.test_client() as client_instance:
        passed = 0
        failed = 0
        for tc in test_cases:
            try:
                tc(client_instance)
                passed += 1
            except Exception as e:
                print(f"FAIL  {tc.__name__}: {e}")
                failed += 1

    print(f"\n{'='*55}")
    print(f"Share Route Tests: {passed}/{len(test_cases)} passed, {failed} failed")
    print(f"{'='*55}")
    sys.exit(0 if failed == 0 else 1)
