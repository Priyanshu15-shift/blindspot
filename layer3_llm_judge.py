import os
import json
import time
from google import genai
from google.genai import types

# Using the "gemini-flash-lite-latest" alias — the lite tier because it
# doesn't reason internally by default (fast), and the "-latest" alias
# because Google has repeatedly blocked new API keys from specific pinned
# model names mid-project (this happened twice already: gemini-2.5-flash
# and gemini-2.5-flash-lite were both blocked for this key despite showing
# up in list_available_models.py). The alias sidesteps that by always
# pointing at whatever Google currently serves as their lite-tier model.
GEMINI_MODEL = "gemini-flash-lite-latest"

_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY not set. Get a free key at "
            "https://aistudio.google.com/app/apikey and set it, e.g.\n"
            '  $env:GEMINI_API_KEY="your-key-here"   (PowerShell)'
        )
    _client = genai.Client(api_key=api_key)
    return _client


JUDGE_PROMPT = """You are a PII detection judge — the third and final layer of a
detection pipeline. Layers 1 (NER) and 2 (regex/entropy) have already
scanned this text and may have missed things. Your job is to catch what
they missed: PII that requires context, semantic understanding, or
reasoning to identify — not simple pattern matches.

Look specifically for:
- Semantic/contextual PII with no fixed pattern (e.g. identity triangulation
  via relationships: "my brother-in-law the pilot", indirect addresses:
  "the house two down from the blue one on 4th")
- Obfuscated PII that survives visual inspection but isn't a clean regex
  match (leetspeak, spacing tricks, homoglyphs, encoded text)
- Financial/personal info implied without keywords (e.g. "I make about
  what a senior SDE at Google makes")
- Multilingual or code-mixed PII (Hindi/Devanagari, Hinglish)

Do NOT re-flag things an ordinary regex or named-entity recognizer would
already catch cleanly (a plainly formatted email, a clearly labeled phone
number) — assume earlier layers handled those. Focus on what requires
judgment.

Respond with ONLY valid JSON, no markdown fences, no preamble, in this
exact shape:
{
  "findings": [
    {
      "text_span": "the exact substring you flagged",
      "pii_type": "short category label",
      "reasoning": "one sentence on why this is PII and why it needed
                     contextual/semantic judgment rather than a pattern match",
      "confidence": 0.0 to 1.0
    }
  ]
}

If there is no PII requiring this kind of judgment, respond with:
{"findings": []}

Text to analyze:
---
{TEXT}
---
"""


def run_layer3(text, retries=3, backoff_seconds=2):
    """
    Sends `text` to the Gemini free-tier model for contextual/semantic PII
    judgment. Returns (findings, raw_latency_seconds).

    findings: list of dicts with text_span, pii_type, reasoning, confidence
    """
    client = _get_client()
    prompt = JUDGE_PROMPT.replace("{TEXT}", text)

    # Not every model behind the "-latest" alias supports thinking_config
    # (older Flash generations reject it with a generic 400 rather than a
    # specific error). Try with it first for the latency benefit; if the
    # model rejects it, fall back to a plain call without it instead of
    # failing the whole layer.
    thinking_cfg = types.GenerateContentConfig(
        thinking_config=types.ThinkingConfig(thinking_budget=0),
    )

    last_error = None
    for attempt in range(retries):
        start = time.time()
        try:
            try:
                response = client.models.generate_content(
                    model=GEMINI_MODEL,
                    contents=prompt,
                    config=thinking_cfg,
                )
            except Exception as inner_e:
                if "INVALID_ARGUMENT" in str(inner_e) or "400" in str(inner_e):
                    # This model doesn't accept thinking_config — retry plain.
                    response = client.models.generate_content(
                        model=GEMINI_MODEL,
                        contents=prompt,
                    )
                else:
                    raise
            latency = time.time() - start
            raw = response.text.strip()
            # Strip markdown fences if the model adds them despite instructions
            if raw.startswith("```"):
                raw = raw.strip("`")
                if raw.lower().startswith("json"):
                    raw = raw[4:].strip()
            parsed = json.loads(raw)
            return parsed.get("findings", []), latency
        except json.JSONDecodeError as e:
            last_error = f"JSON parse failed: {e} | raw response: {raw[:200]}"
        except Exception as e:
            last_error = str(e)
            # 429 = rate limit hit; back off and retry
            if "429" in str(e) and attempt < retries - 1:
                time.sleep(backoff_seconds * (attempt + 1))
                continue
        break

    # Fail closed: return empty findings rather than crash the pipeline,
    # but surface the error so it's visible in eval runs, not silently swallowed.
    return [{"error": last_error}], time.time() - start


# --- TEST IT ---
if __name__ == "__main__":
    test_text = (
        "My dog's vet is Dr. Amrita Sharma, same one my brother-in-law "
        "the pilot uses. I make about what a senior SDE at Google makes, "
        "roughly 45L, and live in the house two down from the blue one "
        "on 4th, near the Shell station."
    )
    findings, latency = run_layer3(test_text)
    print(f"Original: {test_text}\n")
    print(f"Latency: {latency:.2f}s\n")
    print("Findings:")
    for f in findings:
        print(f"  - {f}")