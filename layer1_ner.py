from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

def run_layer1(text):
    """
    This is Layer 1: It uses AI models to find standard PII 
    like names, emails, and phone numbers.
    """
    results = analyzer.analyze(text=text, language='en', 
                               entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "LOCATION"])
    
    anonymized_result = anonymizer.anonymize(
        text=text,
        analyzer_results=results
    )
    
    return anonymized_result.text, results

# TESTING
if __name__ == "__main__":
    test_text = "My name is Rajiv and my email is rajiv@example.com. I live in Pune,india."
    redacted_text, raw_results = run_layer1(test_text)
    
    print(f"Original: {test_text}")
    print(f"Redacted: {redacted_text}")
    print(f"Entities found: {len(raw_results)}")