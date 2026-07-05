from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine


# Aadhaar: 12 digits (e.g., 1234 5678 9012)
aadhaar_pattern = Pattern(name="aadhaar_pattern", regex=r"\b[2-9]{1}\d{3}\s\d{4}\s\d{4}\b|\b[2-9]{1}\d{11}\b", score=0.5)

# PAN Card: 5 letters, 4 digits, 1 letter (e.g., ABCDE1234F)
pan_pattern = Pattern(name="pan_pattern", regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", score=0.5)

# Phone no: Handles +91, 0, or just 10 digits starting with 6-9
india_phone_pattern = Pattern(name="india_phone_pattern", regex=r"\b(?:\+91|0?)[6-9]\d{9}\b", score=0.5)

# UPI ID: common patterns like name@upi, name@bank
upi_pattern = Pattern(name="upi_pattern", regex=r"\b[\w.-]+@(?:upi|ok\w+)\b", score=0.5)

# 2. Register these patterns 
aadhaar_recognizer = PatternRecognizer(supported_entity="IN_AADHAAR", patterns=[aadhaar_pattern])
pan_recognizer = PatternRecognizer(supported_entity="IN_PAN", patterns=[pan_pattern])
phone_recognizer = PatternRecognizer(supported_entity="IN_PHONE", patterns=[india_phone_pattern])
upi_recognizer = PatternRecognizer(supported_entity="IN_UPI", patterns=[upi_pattern])

# 3. Initialize the Engine 
analyzer = AnalyzerEngine()
analyzer.registry.add_recognizer(aadhaar_recognizer)
analyzer.registry.add_recognizer(pan_recognizer)
analyzer.registry.add_recognizer(phone_recognizer)
analyzer.registry.add_recognizer(upi_recognizer)

anonymizer = AnonymizerEngine()

def run_layer1(text):
    
    entities_to_find = ["PERSON", "EMAIL_ADDRESS", "LOCATION", "IN_AADHAAR", "IN_PAN", "IN_PHONE", "IN_UPI"]
    
    results = analyzer.analyze(text=text, language='en', entities=entities_to_find)
    anonymized_result = anonymizer.anonymize(text=text, analyzer_results=results)
    
    return anonymized_result.text, results

# --- TEST IT WITH INDIAN DATA ---
if __name__ == "__main__":
    india_test = """
    My Aadhaar is 3612 3456 7890 and my PAN is ABCDE1234F. 
    Call me at +91 9876543210 or pay me at ramesh@okaxis.
    """
    redacted, results = run_layer1(india_test)
    
    print(f"Original: {india_test}")
    print(f"\nRedacted: {redacted}")
    print("\nEntities Found:")
    for res in results:
        print(f"- Type: {res.entity_type}, Score: {res.score}")