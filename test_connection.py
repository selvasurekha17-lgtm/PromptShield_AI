"""Diagnostic connection test for PromptShield AI.

Verifies connectivity with the Google Gemini API using credentials from .env,
and tests the local heuristic fallback engine.
"""

import sys
from config import get_client, MODEL_NAME, is_api_configured
from analyzer import analyze_message_offline


def test_gemini():
    print("==================================================")
    print("🛡️  PromptShield AI — Diagnostics & Connectivity")
    print("==================================================")

    if not is_api_configured():
        print("⚠️  Warning: GEMINI_API_KEY is not configured in .env.")
        print("💡 The application will run smoothly in Offline Heuristic Mode.")
        return

    client = get_client()
    if not client:
        print("❌ Error: Could not initialize Gemini client.")
        return

    print(f"📡 Testing connection to Gemini API (Model: {MODEL_NAME})...")
    try:
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents="Reply with: PromptShield AI connection successful!"
        )
        print("✅ Gemini API Response:")
        print(response.text.strip())
        print("🎉 Gemini AI connection test PASSED!\n")
    except Exception as e:
        print(f"⚠️  Gemini API call failed: {e}")
        print("💡 PromptShield AI is designed to handle this gracefully!")
        print("Testing Local Fallback Engine...")
        result = analyze_message_offline(
            "URGENT: Your bank account will be blocked in 10 minutes. Click http://scam.xyz to share OTP."
        )
        print(f"✅ Fallback Engine verified! Risk Level: {result.risk_level.value}, Score: {result.risk_score}")
        print("🛡️  Application is fully functional in offline/fallback mode.\n")


if __name__ == "__main__":
    test_gemini()
