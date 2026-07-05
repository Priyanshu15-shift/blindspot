import re
import math

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
    
    # 1. Improved Regex for Credit Cards
    card_pattern = r'\b(?:\d[ -]*?){13,16}\b'
    cards = re.findall(card_pattern, text)
    for card in cards:
        findings.append({"type": "CREDIT_CARD", "value": card})

    # 2. Improved Regex for Obfuscated Email
    obfuscated_email = r'\b[\w\.-]+ ?\[at\] ?[\w\.-]+ ?\. ?\w+\b'
    emails = re.findall(obfuscated_email, text)
    for email in emails:
        findings.append({"type": "OBFUSCATED_EMAIL", "value": email})

    # 3. IMPROVED Entropy Check
    words = text.split()
    for word in words:
        # CLEAN the word: remove dots, commas, or quotes from the ends
        clean_word = word.strip(".,!?;:\"'")
        
        # Lowered length to 12 to be safer
        if len(clean_word) > 14: 
            score = calculate_entropy(clean_word)
            # If it's a mix of numbers and letters, it's usually high entropy
            if score > 3.7: 
                findings.append({"type": "KEY_SECRET", "value": clean_word, "score": round(score, 2)})

    # Redact
    redacted_text = text
    for item in findings:
        redacted_text = redacted_text.replace(item["value"], f"<{item['type']}>")

    return redacted_text, findings

# --- TEST IT ---
if __name__ == "__main__":
    test_text = "My secret key is sg862*&hbdne6152. Also card 4111-1111-1111-1111."
    
    redacted, results = run_layer2(test_text)
    
    print("\n--- RESULTS ---")
    print(f"Original: {test_text}")
    print(f"Redacted: {redacted}")
    print("\nDetailed Findings:")
    for f in results:
        print(f" - Found {f['type']}: {f['value']}")