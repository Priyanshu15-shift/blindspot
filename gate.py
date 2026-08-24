from layer1_ner import run_layer1
from layer2_regex_entropy import run_layer2
from layer3_llm_judge import run_layer3


def run_pipeline(text, use_layer3=True):
    """
    Runs text through all three layers and returns a combined result.

    use_layer3=False lets you demo/measure "what Layers 1+2 catch alone" —
    this is the toggle your Gradio demo should expose, since watching
    recall drop when Layer 3 is off is the most persuasive demo moment.
    """
    result = {
        "original_text": text,
        "layer1": {},
        "layer2": {},
        "layer3": {},
    }

    # Layer 1: NER
    redacted_l1, entities_l1 = run_layer1(text)
    result["layer1"] = {
        "redacted_text": redacted_l1,
        "findings": [
            {"type": e.entity_type, "score": e.score, "start": e.start, "end": e.end}
            for e in entities_l1
        ],
    }

    # Layer 2: regex + entropy (runs on the ORIGINAL text, not layer1's output,
    # so the two layers don't mask each other's findings)
    redacted_l2, findings_l2 = run_layer2(text)
    result["layer2"] = {
        "redacted_text": redacted_l2,
        "findings": findings_l2,
    }

    # Layer 3: LLM judge (contextual/semantic — the expensive layer)
    if use_layer3:
        raw_findings_l3, latency_l3 = run_layer3(text)
        # run_layer3 fails closed by returning [{"error": "..."}] rather than
        # raising — filter that out here so an API failure doesn't get
        # miscounted as "Layer 3 found PII" in the aggregate below.
        l3_error = None
        clean_findings_l3 = []
        for f in raw_findings_l3:
            if "error" in f:
                l3_error = f["error"]
            else:
                clean_findings_l3.append(f)
        result["layer3"] = {
            "findings": clean_findings_l3,
            "latency_seconds": latency_l3,
        }
        if l3_error:
            result["layer3"]["error"] = l3_error
    else:
        result["layer3"] = {"findings": [], "latency_seconds": 0, "skipped": True}

    # Aggregate: did ANY layer flag real PII? (errors don't count)
    result["any_pii_detected"] = bool(
        result["layer1"]["findings"]
        or result["layer2"]["findings"]
        or result["layer3"]["findings"]
    )

    return result


# --- TEST IT ---
if __name__ == "__main__":
    import json

    test_text = (
        "My Aadhaar is 3612 3456 7890, my secret key is sg862*&hbdne6152, "
        "and my brother-in-law the pilot's doctor friend Dr. Amrita Sharma "
        "treats my dog too."
    )

    print("=== Full pipeline (Layers 1+2+3) ===")
    full = run_pipeline(test_text, use_layer3=True)
    print(json.dumps(full, indent=2, default=str))

    print("\n=== Layers 1+2 only (Layer 3 off) ===")
    partial = run_pipeline(test_text, use_layer3=False)
    print(json.dumps(partial, indent=2, default=str))

    # The actual demo moment: how many findings did turning Layer 3 off cost you?
    full_count = len(full["layer1"]["findings"]) + len(full["layer2"]["findings"]) + len(full["layer3"]["findings"])
    partial_count = len(partial["layer1"]["findings"]) + len(partial["layer2"]["findings"])
    print(f"\nFindings with Layer 3 ON:  {full_count}")
    print(f"Findings with Layer 3 OFF: {partial_count}")
    print(f"Layer 3 contributed {full_count - partial_count} additional finding(s) Layers 1+2 alone missed.")