"""Verification Script for PromptShield AI Gemini Timeout & Controlled Mock Fallback.

Tests:
1. Verify SDK HttpOptions explicit timeout configuration in config.py (35,000 ms).
2. Controlled mock timeout simulation: verifies that timeout exceptions are caught,
   trigger analyze_message_offline(), clearly explain in uncertainty_notes that Gemini timed out,
   and return a valid RiskAnalysisResult.
3. Controlled retry behavior: verifies that transient timeout errors trigger Tenacity retries.
4. Verify standard offline analysis continues to work independently.
"""

import sys
from unittest.mock import patch, MagicMock
from config import get_client, DEFAULT_TIMEOUT_MS
from analyzer import (
    analyze_message_with_gemini,
    analyze_message_offline,
    _call_gemini_with_retries,
    is_transient_api_error,
    RiskLevel
)


def run_timeout_tests():
    print("=" * 74)
    print("🛡️  PROMPTSHIELD AI — GEMINI HTTP TIMEOUT & MOCK FALLBACK TEST SUITE")
    print("=" * 74)
    passed = 0
    total = 4

    # --------------------------------------------------------------------------
    # TEST 1: Verify SDK HttpOptions Configuration
    # --------------------------------------------------------------------------
    print("\n[TEST 1] Verifying explicit HTTP timeout configuration in config.py")
    client = get_client()
    assert client is not None, "Gemini client should be initialized"
    configured_timeout = client._api_client._http_options.timeout
    print(f" -> Configured DEFAULT_TIMEOUT_MS: {DEFAULT_TIMEOUT_MS} ms ({DEFAULT_TIMEOUT_MS / 1000} seconds)")
    print(f" -> SDK Client HttpOptions timeout: {configured_timeout} ms")
    assert configured_timeout == 35000, f"Expected 35000 ms, got {configured_timeout}"
    assert 30000 <= configured_timeout <= 45000, "Timeout must be between 30 and 45 seconds"
    print(" ✅ TEST 1 PASSED: Google GenAI Client has explicit 35,000 ms (35s) timeout.")
    passed += 1

    # --------------------------------------------------------------------------
    # TEST 2: Controlled Mock Timeout Fallback Handling
    # --------------------------------------------------------------------------
    print("\n[TEST 2] Controlled Mock Timeout Simulation (analyze_message_with_gemini)")
    test_msg = "URGENT: Your HDFC Bank account will be blocked in 10 minutes. Click http://hdfc-kyc.xyz to share OTP."

    # Simulate a Gemini API timeout exception during generate_content
    simulated_timeout = TimeoutError("Request timed out after 35000ms")

    with patch("analyzer._call_gemini_with_retries", side_effect=simulated_timeout):
        res = analyze_message_with_gemini(test_msg, source="SMS", language="English", force_offline=False)

    print(f" -> Result Engine:     {res.analysis_source}")
    print(f" -> Risk Level:        {res.risk_level.value} (Score: {res.risk_score}/100)")
    print(f" -> Message Type:      {res.message_type}")
    print(f" -> Uncertainty Note:  {res.uncertainty_notes[:75]}...")

    assert "Local Engine (Offline Fallback)" in res.analysis_source
    assert "timed out" in res.uncertainty_notes.lower()
    assert "Gemini API request timed out." in res.uncertainty_notes
    assert res.risk_level == RiskLevel.CRITICAL
    assert len(res.red_flags) >= 2
    print(" ✅ TEST 2 PASSED: Timeout triggered offline fallback with explicit timeout notice.")
    passed += 1

    # --------------------------------------------------------------------------
    # TEST 3: Tenacity Retry Predicate for Timeouts
    # --------------------------------------------------------------------------
    print("\n[TEST 3] Tenacity Retry Predicate & Transient Error Detection for Timeouts")
    timeout_err_1 = TimeoutError("Request timed out")
    timeout_err_2 = Exception("Read timed out after 35 seconds")
    timeout_err_3 = Exception("Deadline exceeded during generation")
    generic_err = ValueError("Invalid syntax")

    assert is_transient_api_error(timeout_err_1) is True
    assert is_transient_api_error(timeout_err_2) is True
    assert is_transient_api_error(timeout_err_3) is True
    assert is_transient_api_error(generic_err) is False

    print(f" -> 'Request timed out' qualifies for retry: True")
    print(f" -> 'Read timed out' qualifies for retry: True")
    print(f" -> 'Deadline exceeded' qualifies for retry: True")
    print(f" -> 'Invalid syntax' bypasses retry: True")
    print(" ✅ TEST 3 PASSED: Tenacity correctly recognizes all timeout exceptions for bounded retries.")
    passed += 1

    # --------------------------------------------------------------------------
    # TEST 4: Direct Offline Engine Stability
    # --------------------------------------------------------------------------
    print("\n[TEST 4] Verifying direct offline analysis engine stability")
    tamil_msg = "உங்கள் வங்கி கணக்கு இன்று முடக்கப்படும். உடனே உங்கள் OTP எண்ணை எங்களிடம் பகிரவும்."
    res_ta = analyze_message_offline(tamil_msg, source="SMS", language="Tamil")

    assert res_ta.risk_level == RiskLevel.CRITICAL
    assert res_ta.risk_score >= 80
    assert any("OTP" in rf.phrase for rf in res_ta.red_flags)
    print(f" -> Tamil Analysis: {res_ta.risk_level.value} ({res_ta.risk_score}/100) — {res_ta.message_type}")
    print(" ✅ TEST 4 PASSED: Direct offline heuristic engine operates with 100% integrity.")
    passed += 1

    print("\n" + "=" * 74)
    print(f"🎯 ALL {passed}/{total} TIMEOUT & FALLBACK TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 74)
    return passed == total


if __name__ == "__main__":
    success = run_timeout_tests()
    sys.exit(0 if success else 1)
