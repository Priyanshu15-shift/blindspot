import re
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine

# ---------------------------------------------------------------------------
# Aadhaar validation we used Verhoeff checksum algorithm
# ---------------------------------------------------------------------------

_VERHOEFF_D = [
    [0,1,2,3,4,5,6,7,8,9], [1,2,3,4,0,6,7,8,9,5], [2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7], [4,0,1,2,3,9,5,6,7,8], [5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2], [7,6,5,9,8,2,1,0,4,3], [8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
]
_VERHOEFF_P = [
    [0,1,2,3,4,5,6,7,8,9], [1,5,7,6,2,8,3,0,9,4], [5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7], [9,4,5,3,1,2,6,8,7,0], [4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5], [7,0,4,6,9,1,3,2,5,8],
]


def _verhoeff_checksum_valid(number_str):
    """Returns True if the 12-digit string passes the Verhoeff checksum
    used by real Aadhaar numbers. This is the actual algorithm UIDAI uses,
    not a guess — it's what separates 'looks like an Aadhaar number' from
    'checksum-valid Aadhaar-shaped number'. It won't tell you a number is
    REAL (that needs UIDAI's API), but it rejects the vast majority of
    random 12-digit strings a naive regex would otherwise flag."""
    digits = [int(d) for d in number_str][::-1]
    c = 0
    for i, digit in enumerate(digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]
    return c == 0


aadhaar_pattern = Pattern(
    name="aadhaar_pattern",
    regex=r"(?<!\d)[2-9]\d{3}\s?\d{4}\s?\d{4}(?!\d)",
    score=0.4,  
)

# ---------------------------------------------------------------------------
# PAN — unchanged, this one was already well-formed
# ---------------------------------------------------------------------------
pan_pattern = Pattern(name="pan_pattern", regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", score=0.85)


india_phone_pattern = Pattern(
    name="india_phone_pattern",
    regex=r"(?<!\d)(?:\+91[\s-]?|0)?[6-9]\d{9}(?!\d)",
    score=0.6,
)

# ---------------------------------------------------------------------------
# UPI ID 
# ---------------------------------------------------------------------------
upi_pattern = Pattern(name="upi_pattern", regex=r"\b[\w.-]+@(?:upi|ok\w+)\b", score=0.7)

aadhaar_recognizer = PatternRecognizer(supported_entity="IN_AADHAAR", patterns=[aadhaar_pattern])
pan_recognizer = PatternRecognizer(supported_entity="IN_PAN", patterns=[pan_pattern])
phone_recognizer = PatternRecognizer(supported_entity="IN_PHONE", patterns=[india_phone_pattern])
upi_recognizer = PatternRecognizer(supported_entity="IN_UPI", patterns=[upi_pattern])

try:
    analyzer = AnalyzerEngine()
    analyzer.registry.add_recognizer(aadhaar_recognizer)
    analyzer.registry.add_recognizer(pan_recognizer)
    analyzer.registry.add_recognizer(phone_recognizer)
    analyzer.registry.add_recognizer(upi_recognizer)
    anonymizer = AnonymizerEngine()
except OSError as e:
    raise RuntimeError(
        "Presidio couldn't load its spaCy model. Run:\n"
        "  python -m spacy download en_core_web_lg\n"
        f"(original error: {e})"
    ) from e


# A checksum alone isn't enough: a Verhoeff check digit means roughly
# 1 in 10 random 12-digit numbers will pass it purely by chance (verified
# empirically — 200k random candidates, ~10% passed). "My order ID is
# 481029384756" happens to be one of them. Humans disambiguate this kind
# of thing using the words AROUND the number, not the number alone — so
# we do the same: look for Aadhaar-indicating context nearby, and use it
# to adjust confidence rather than treating checksum-pass as final proof.
_AADHAAR_CONTEXT_WORDS = re.compile(
    r"\b(aadhaar|aadhar|uid|uidai)\b", re.IGNORECASE
)
_NON_AADHAAR_CONTEXT_WORDS = re.compile(
    r"\b(order|invoice|tracking|reference|ticket|transaction|account\s*no)\b",
    re.IGNORECASE,
)
_CONTEXT_WINDOW_CHARS = 40  # how far around the match to look for context words


def _nearest_match_distance(pattern, text, pos):
    """Returns the character distance from `pos` to the closest match of
    `pattern` in `text`, or None if there's no match at all. Used instead
    of a simple "is the keyword anywhere in the window" check — a plain
    presence check breaks on sentences like '...order ID is 481029384756
    (not an Aadhaar number)', where the word 'Aadhaar' is technically in
    a 40-char window but is nine words away and inside a negation, while
    'order ID' sits immediately before the number. Proximity is a much
    better signal than presence for disambiguating which label the number
    actually belongs to."""
    best = None
    for m in pattern.finditer(text):
        # distance from the nearer edge of the keyword match to `pos`
        dist = min(abs(m.start() - pos), abs(m.end() - pos))
        if best is None or dist < best:
            best = dist
    return best


def run_layer1(text):
    entities_to_find = ["PERSON","EMAIL_ADDRESS","LOCATION","IN_AADHAAR","IN_PAN","IN_PHONE","IN_UPI",]

    results = analyzer.analyze(
        text=text,
        language="en",
        entities=entities_to_find
    )

    confirmed_results = []

    for res in results:

        # ---------------------------------------------------------------
        # Aadhaar validation
        # ---------------------------------------------------------------
        if res.entity_type == "IN_AADHAAR":
            candidate = re.sub(r"\s", "", text[res.start:res.end])

            if not (
                len(candidate) == 12
                and _verhoeff_checksum_valid(candidate)
            ):
                continue  # failed checksum

            window_start = max(
                0,
                res.start - _CONTEXT_WINDOW_CHARS
            )
            window_end = min(
                len(text),
                res.end + _CONTEXT_WINDOW_CHARS
            )

            window = text[window_start:window_end]
            pos_in_window = res.start - window_start

            aad_dist = _nearest_match_distance(
                _AADHAAR_CONTEXT_WORDS,
                window,
                pos_in_window
            )

            non_dist = _nearest_match_distance(
                _NON_AADHAAR_CONTEXT_WORDS,
                window,
                pos_in_window
            )

            if aad_dist is None and non_dist is None:
                res.score = 0.5

            elif non_dist is not None and (
                aad_dist is None or non_dist < aad_dist
            ):
                continue

            else:
                res.score = 0.95

            confirmed_results.append(res)

        # ---------------------------------------------------------------
        # PAN validation
        # ---------------------------------------------------------------
        elif res.entity_type == "IN_PAN":
            candidate = text[res.start:res.end]

            # PAN must strictly follow:
            # 5 uppercase letters + 4 digits + 1 uppercase letter
            if not re.fullmatch(
                r"[A-Z]{5}[0-9]{4}[A-Z]",
                candidate
            ):
                continue

            confirmed_results.append(res)

        # ---------------------------------------------------------------
        # All other entities
        # ---------------------------------------------------------------
        else:
            confirmed_results.append(res)

    anonymized_result = anonymizer.anonymize(
        text=text,
        analyzer_results=confirmed_results
    )

    return anonymized_result.text, confirmed_results


# --- TEST IT WITH INDIAN DATA ---
if __name__ == "__main__":
    india_test = """
    "Aadhaar-linked account, order ID 361234567890"
    """
    redacted, results = run_layer1(india_test)
    print(f"Original: {india_test}")
    print(f"\nRedacted: {redacted}")
    print("\nEntities Found:")
    for res in results:
        print(f"- Type: {res.entity_type}, Score: {res.score}")