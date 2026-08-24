"""
Unit tests for layer1_ner.py.

Every case here is one we manually traced and confirmed during development —
this file exists specifically so the next silent regression (like the missing
GEMINI_MODEL line, or a future copy-paste slip) gets caught by `pytest`
instead of an hour of manual debugging.

Run with:  pytest tests/test_layer1_ner.py -v
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from layer1_ner import run_layer1, _verhoeff_checksum_valid


class TestVerhoeffChecksum:
    """The checksum math itself, independent of Presidio — fast, no model load needed."""

    def test_known_valid_aadhaar_passes(self):
        # This number was confirmed checksum-valid during development.
        assert _verhoeff_checksum_valid("361234567890") is True

    def test_random_non_checksum_number_can_pass_or_fail(self):
        # Not every 12-digit number matters here — this just documents that
        # the function runs without error on arbitrary input.
        result = _verhoeff_checksum_valid("123456789012")
        assert isinstance(result, bool)


class TestAadhaarDetection:
    """The real regression tests — the exact cases from our manual debugging session."""

    def test_valid_aadhaar_with_context_is_flagged(self):
        text = "My Aadhaar is 3612 3456 7890 and that's my only ID here."
        redacted, findings = run_layer1(text)
        aadhaar_findings = [f for f in findings if f.entity_type == "IN_AADHAAR"]
        assert len(aadhaar_findings) == 1
        assert aadhaar_findings[0].score >= 0.9
        assert "<IN_AADHAAR>" in redacted

    def test_order_id_is_not_flagged_as_aadhaar(self):
        # THE regression test: a checksum-valid-by-coincidence number labeled
        # as an order ID must NOT be flagged as Aadhaar. This is the exact
        # case that first exposed the need for context-based disambiguation.
        text = "My order ID is 481029384756 (not an Aadhaar number)."
        redacted, findings = run_layer1(text)
        aadhaar_findings = [f for f in findings if f.entity_type == "IN_AADHAAR"]
        assert len(aadhaar_findings) == 0
        assert "481029384756" in redacted  # left untouched, not redacted

    def test_checksum_invalid_number_never_flagged_regardless_of_context(self):
        # A 12-digit number that fails Verhoeff shouldn't be flagged even if
        # the word "Aadhaar" is right next to it — checksum failure should
        # short-circuit before context is even checked.
        text = "My Aadhaar number is 000000000000, definitely fake."
        redacted, findings = run_layer1(text)
        aadhaar_findings = [f for f in findings if f.entity_type == "IN_AADHAAR"]
        assert len(aadhaar_findings) == 0


class TestPANDetection:
    def test_valid_pan_format_is_flagged(self):
        text = "My PAN is ABCDE1234F for tax purposes."
        redacted, findings = run_layer1(text)
        pan_findings = [f for f in findings if f.entity_type == "IN_PAN"]
        assert len(pan_findings) == 1
        assert "<IN_PAN>" in redacted

    def test_lowercase_pan_is_not_flagged(self):
        # PAN format is defined as uppercase; confirms we're not accidentally
        # over-matching lowercase text that merely resembles the pattern.
        text = "my pan is abcde1234f probably not real"
        redacted, findings = run_layer1(text)
        pan_findings = [f for f in findings if f.entity_type == "IN_PAN"]
        assert len(pan_findings) == 0


class TestPhoneDetection:
    def test_valid_indian_mobile_with_country_code_is_flagged(self):
        text = "Call me at +91 9876543210 anytime."
        redacted, findings = run_layer1(text)
        phone_findings = [f for f in findings if f.entity_type == "IN_PHONE"]
        assert len(phone_findings) == 1

    def test_phone_number_not_extracted_as_substring_of_longer_number(self):
        # Regression test for the boundary-tightening fix: a 10-digit phone
        # pattern must not match as a substring inside a longer digit run.
        text = "Reference number: 1198765432109999 is not a phone number."
        redacted, findings = run_layer1(text)
        phone_findings = [f for f in findings if f.entity_type == "IN_PHONE"]
        assert len(phone_findings) == 0


class TestUPIDetection:
    def test_valid_upi_handle_is_flagged(self):
        text = "Pay me at ramesh@okaxis for the split."
        redacted, findings = run_layer1(text)
        upi_findings = [f for f in findings if f.entity_type == "IN_UPI"]
        assert len(upi_findings) == 1


class TestMixedText:
    def test_multiple_entity_types_in_one_text(self):
        # The full combined case from our gate.py test — makes sure entities
        # don't interfere with each other's detection when several appear
        # in the same text.
        text = (
            "My Aadhaar is 3612 3456 7890 and my PAN is ABCDE1234F. "
            "Call me at +91 9876543210 or pay me at ramesh@okaxis."
        )
        redacted, findings = run_layer1(text)
        entity_types = {f.entity_type for f in findings}
        assert "IN_AADHAAR" in entity_types
        assert "IN_PAN" in entity_types
        assert "IN_PHONE" in entity_types
        assert "IN_UPI" in entity_types


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))