"""Comprehensive Test Suite for PromptShield AI Tamil, Tanglish & English Heuristics.

Evaluates:
Case A: Tamil OTP scam
Case B: English OTP scam
Case C: Tamil normal conversation
Case D: Tanglish OTP scam
Case E: Tamil fake job offer with registration fee
Case F: English normal conversation
"""

from analyzer import analyze_message_offline, RiskLevel


def run_tests():
    print("=" * 76)
    print("🛡️  PROMPTSHIELD AI — TAMIL, TANGLISH & ENGLISH HEURISTIC EVALUATION")
    print("=" * 76)

    cases = [
        {
            "id": "CASE A",
            "name": "Tamil Bank OTP Phishing Scam",
            "lang": "Tamil",
            "text": "உங்கள் வங்கி கணக்கு இன்று முடக்கப்படும். உடனே உங்கள் OTP எண்ணை எங்களிடம் பகிரவும். இல்லையெனில் உங்கள் கணக்கு நிரந்தரமாக முடக்கப்படும்.",
            "expected_level": [RiskLevel.CRITICAL, RiskLevel.HIGH],
            "min_score": 75,
            "required_categories": ["Credential Theft & OTP Harvesting", "Artificial Urgency & Coercion"],
            "must_not_have": [],
        },
        {
            "id": "CASE B",
            "name": "English Bank OTP Phishing Scam",
            "lang": "English",
            "text": "URGENT: Your HDFC Bank account will be blocked in 10 minutes. Share the 6-digit OTP sent to your phone or click http://hdfc-kyc.xyz immediately.",
            "expected_level": [RiskLevel.CRITICAL, RiskLevel.HIGH],
            "min_score": 75,
            "required_categories": ["Credential Theft & OTP Harvesting", "Artificial Urgency & Coercion"],
            "must_not_have": [],
        },
        {
            "id": "CASE C",
            "name": "Tamil Normal Conversation",
            "lang": "Tamil",
            "text": "அம்மா, நான் இன்று மாலை கல்லூரி முடிந்து 6 மணிக்கு வீட்டிற்கு வருகிறேன். இரவு உணவிற்கு என்ன சமைக்கிறீர்கள்?",
            "expected_level": [RiskLevel.LOW],
            "max_score": 25,
            "required_categories": [],
            "must_not_have": ["Credential Theft & OTP Harvesting", "Artificial Urgency & Coercion", "Upfront Payment & Financial Fraud"],
        },
        {
            "id": "CASE D",
            "name": "Tanglish OTP Scam (Mixed Tamil-English)",
            "lang": "Tanglish",
            "text": "Unga SBI bank account inaiku block aaidum. Udane intha link click panni unga OTP number ah share pannunga.",
            "expected_level": [RiskLevel.CRITICAL, RiskLevel.HIGH],
            "min_score": 75,
            "required_categories": ["Credential Theft & OTP Harvesting", "Artificial Urgency & Coercion"],
            "must_not_have": [],
        },
        {
            "id": "CASE E",
            "name": "Tamil Fake Job Offer with Registration Fee",
            "lang": "Tamil",
            "text": "அமேசான் நிறுவனத்தில் வீட்டிலிருந்தே வேலை! தினமும் ரூ. 3000 வருமானம். உடனே பதிவு கட்டணம் ரூ. 999 செலுத்தவும்.",
            "expected_level": [RiskLevel.CRITICAL, RiskLevel.HIGH],
            "min_score": 70,
            "required_categories": ["Fake Job & Internship Lures", "Upfront Payment & Financial Fraud"],
            "must_not_have": [],
        },
        {
            "id": "CASE F",
            "name": "English Normal Conversation",
            "lang": "English",
            "text": "Hi Alex, hope you are having a productive week. Are we still on for the project sync tomorrow at 3 PM? Let me know if that time works.",
            "expected_level": [RiskLevel.LOW],
            "max_score": 25,
            "required_categories": [],
            "must_not_have": ["Credential Theft & OTP Harvesting", "Artificial Urgency & Coercion", "Upfront Payment & Financial Fraud"],
        },
    ]

    all_passed = True

    for c in cases:
        print(f"\n----------------------------------------------------------------------------")
        print(f"[{c['id']}] {c['name']} (Input Language: {c['lang']})")
        print(f"Payload: \"{c['text']}\"")
        res = analyze_message_offline(c["text"], source="SMS", language=c["lang"])

        print(f" -> Classification: {res.message_type}")
        print(f" -> Risk Level:     {res.risk_level.value}")
        print(f" -> Risk Score:     {res.risk_score}/100")
        print(f" -> Red Flags:      {[(rf.category, rf.phrase) for rf in res.red_flags]}")
        print(f" -> First Action:   {res.recommended_actions[0] if res.recommended_actions else 'None'}")

        # Verification logic
        case_passed = True

        # Level check
        if res.risk_level not in c["expected_level"]:
            print(f" ❌ Level check failed: Expected {c['expected_level']}, got {res.risk_level.value}")
            case_passed = False

        # Score floor/ceiling check
        if "min_score" in c and res.risk_score < c["min_score"]:
            print(f" ❌ Min score failed: Expected >= {c['min_score']}, got {res.risk_score}")
            case_passed = False
        if "max_score" in c and res.risk_score > c["max_score"]:
            print(f" ❌ Max score failed: Expected <= {c['max_score']}, got {res.risk_score}")
            case_passed = False

        # Category checks
        matched_cats = {rf.category for rf in res.red_flags}
        for req_cat in c["required_categories"]:
            if req_cat not in matched_cats:
                print(f" ❌ Missed required category: {req_cat}")
                case_passed = False

        for forbid_cat in c["must_not_have"]:
            if forbid_cat in matched_cats:
                print(f" ❌ False positive category: {forbid_cat}")
                case_passed = False

        if case_passed:
            print(f" ✅ {c['id']} PASSED")
        else:
            print(f" ❌ {c['id']} FAILED")
            all_passed = False

    print("\n" + "=" * 76)
    if all_passed:
        print("🎯 ALL 6 MULTILINGUAL HEURISTIC TEST CASES PASSED WITH 100% SUCCESS!")
    else:
        print("❌ SOME TEST CASES FAILED.")
    print("=" * 76)
    return all_passed


if __name__ == "__main__":
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
