import re
import math

# ---------------------------------------------------------------------------
# Luhn checksum — same idea as the Verhoeff check we added to Layer 1.
# ---------------------------------------------------------------------------

def _luhn_valid(number_str):
    digits = [int(d) for d in number_str]
    checksum = 0
    # process from rightmost digit, doubling every second digit
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy -= p_x * math.log(p_x, 2)
    return entropy


def run_layer2(text):
    findings = []

    # 1. Credit cards — regex finds candidates, Luhn confirms them.

    card_pattern = r"\b(?:\d[ -]*?){13,16}\b"
    for m in re.finditer(card_pattern, text):
        raw = m.group()
        digits_only = re.sub(r"[ -]", "", raw)
        if 13 <= len(digits_only) <= 19 and _luhn_valid(digits_only):
            findings.append({
                "type": "CREDIT_CARD",
                "value": raw,
                "start": m.start(),
                "end": m.end(),
            })
        # else: shaped like a card number but fails Luhn — not flagged.
        # This is where most of the false-positive reduction happens,
        # exactly like the Aadhaar checksum in Layer 1.
    obfuscated_email = r"\b[\w\.-]+ ?\[at\] ?[\w\.-]+ ?\. ?\w+\b"
    for m in re.finditer(obfuscated_email, text):
        findings.append({
            "type": "OBFUSCATED_EMAIL",
            "value": m.group(),
            "start": m.start(),
            "end": m.end(),
        })

    for m in re.finditer(r"\S+", text):
        word = m.group()
        clean_word = word.strip(".,!?;:\"'")
        if len(clean_word) > 14:
            score = calculate_entropy(clean_word)
            if score > 3.7:
                strip_offset = len(word) - len(word.lstrip(".,!?;:\"'"))
                start = m.start() + strip_offset
                findings.append({
                    "type": "KEY_SECRET",
                    "value": clean_word,
                    "score": round(score, 2),
                    "start": start,
                    "end": start + len(clean_word),
                })

    # --- Redact by POSITION, not by string value ---
    # The original `redacted_text.replace(item["value"], ...)` redacts by
    # matching the string content anywhere it appears — so if a card
    # number occurs twice, or one finding's text is a substring of
    # another's, replace() can redact the wrong occurrence or corrupt
    # output silently. Building the redacted string by offset, back to
    # front, avoids all of that: each redaction happens at the exact
    # position it was found, regardless of duplicate or overlapping text.
    #
    # Overlaps: if two findings' spans overlap, we keep the earlier-listed
    # one and drop the later-starting overlapping one, rather than letting
    # them corrupt each other's offsets during the replace pass.
    findings_sorted = sorted(findings, key=lambda f: f["start"])
    non_overlapping = []
    last_end = -1
    for f in findings_sorted:
        if f["start"] >= last_end:
            non_overlapping.append(f)
            last_end = f["end"]
        # else: overlaps the previous finding — skip it rather than
        # corrupt the redaction pass. Worth logging in eval runs so
        # overlap frequency is visible, not silently dropped.

    redacted_chars = list(text)
    for f in sorted(non_overlapping, key=lambda f: f["start"], reverse=True):
        redacted_chars[f["start"]:f["end"]] = list(f"<{f['type']}>")
    redacted_text = "".join(redacted_chars)

    return redacted_text, findings


# --- TEST IT ---
if __name__ == "__main__":
    test_text = (
        "My secret key is sg862*&hbdne6152. Also card 4111-1111-1111-1111. "
        "My phone-shaped number 9876543210123 is not a card."
    )
    redacted, results = run_layer2(test_text)
    print("\n--- RESULTS ---")
    print(f"Original: {test_text}")
    print(f"Redacted: {redacted}")
    print("\nDetailed Findings:")
    for f in results:
        print(f"  - Found {f['type']}: {f['value']}")