"""
Unit tests for layer2_regex_entropy.py.

Includes a dedicated regression test for the missing-`for`-loop bug found
during development (test_missing_loop_regression) — that bug silently
disabled KEY_SECRET detection with no error, and was only caught by manual
tracing. This test exists so that specific failure mode can never silently
reappear.

Run with:  pytest tests/test_layer2_regex.py -v
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from layer2_regex_entropy import run_layer2, _luhn_valid, calculate_entropy


class TestLuhnChecksum:
    def test_known_valid_test_card_passes(self):
        # 4111-1111-1111-1111 is a standard Luhn-valid Visa test number.
        assert _luhn_valid("4111111111111111") is True

    def test_luhn_invalid_number_fails(self):
        # One digit off from a valid card — should fail the checksum.
        assert _luhn_valid("4111111111111112") is False


class TestCreditCardDetection:
    def test_luhn_valid_card_is_flagged(self):
        text = "Also card 4111-1111-1111-1111."
        redacted, findings = run_layer2(text)
        card_findings = [f for f in findings if f["type"] == "CREDIT_CARD"]
        assert len(card_findings) == 1
        assert "<CREDIT_CARD>" in redacted

    def test_card_shaped_but_luhn_invalid_number_is_not_flagged(self):
        # THE regression test from our manual testing: a 13-digit number that
        # LOOKS like a card but fails Luhn must not be flagged.
        text = "My phone-shaped number 9876543210123 is not a card."
        redacted, findings = run_layer2(text)
        card_findings = [f for f in findings if f["type"] == "CREDIT_CARD"]
        assert len(card_findings) == 0
        assert "9876543210123" in redacted  # left untouched


class TestEntropyDetection:
    def test_known_high_entropy_secret_scores_above_threshold(self):
        assert calculate_entropy("sg862*&hbdne6152") > 3.7

    def test_missing_loop_regression(self):
        # THE bug: a missing `for m in re.finditer(r"\S+", text):` line once
        # silently reduced the entire entropy scan to a single leftover-
        # variable check, with no error thrown. This test fails loudly if
        # that ever happens again.
        text = (
            "My secret key is sg862*&hbdne6152. Also card 4111-1111-1111-1111. "
            "My phone-shaped number 9876543210123 is not a card."
        )
        redacted, findings = run_layer2(text)
        secret_findings = [f for f in findings if f["type"] == "KEY_SECRET"]
        assert len(secret_findings) == 1, (
            "KEY_SECRET was not detected — check that the entropy scan's "
            "`for m in re.finditer(r'\\S+', text):` loop is present and "
            "correctly indented (this is the exact bug found during "
            "development)."
        )
        assert secret_findings[0]["value"] == "sg862*&hbdne6152"

    def test_short_high_entropy_string_is_not_flagged(self):
        # Below the 14-character length threshold — should not trigger
        # regardless of entropy, since short strings are common (words,
        # short codes) and would otherwise cause excessive false positives.
        text = "My code is x7Kq9."
        redacted, findings = run_layer2(text)
        secret_findings = [f for f in findings if f["type"] == "KEY_SECRET"]
        assert len(secret_findings) == 0


class TestOffsetBasedRedaction:
    def test_duplicate_secret_both_occurrences_are_redacted(self):
        # Regression test for the string-value .replace() bug: if the same
        # secret appears twice, BOTH occurrences must be redacted correctly,
        # not just one (or corrupted), since redaction is now offset-based.
        secret = "sg862*&hbdne6152"
        text = f"First mention: {secret}. Later again: {secret}."
        redacted, findings = run_layer2(text)
        assert redacted.count(secret) == 0, "a raw secret leaked through redaction"
        assert redacted.count("<KEY_SECRET>") == 2

    def test_overlapping_findings_do_not_corrupt_output(self):
        # A card number embedded near a high-entropy string — findings must
        # not corrupt each other's offsets during redaction.
        text = "Card 4111-1111-1111-1111 and key sg862*&hbdne6152 in one message."
        redacted, findings = run_layer2(text)
        assert "<CREDIT_CARD>" in redacted
        assert "<KEY_SECRET>" in redacted
        # Original values must not leak through anywhere in the output.
        assert "4111-1111-1111-1111" not in redacted
        assert "sg862*&hbdne6152" not in redacted


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))