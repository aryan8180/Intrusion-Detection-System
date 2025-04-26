import re

# Define some basic attack signatures (you can expand this later)
signature_patterns = {
    "SQL Injection": r"(SELECT|INSERT|UPDATE|DELETE)\s.+\sFROM\s.+",
    "Directory Traversal": r"\.\./\.\./",
    "Cross-Site Scripting (XSS)": r"(<script>|javascript:)",
    "Local File Inclusion": r"(etc/passwd|boot.ini)",
    "Command Injection": r"(;|\|\||&&)\s*(ls|cat|whoami|pwd)"
}

# Function to match packet payload against known signatures
def match_signature(payload):
    alerts = []

    if payload is None:
        return alerts

    for attack_type, pattern in signature_patterns.items():
        if re.search(pattern, payload, re.IGNORECASE):
            alerts.append(attack_type)

    return alerts

# Example for testing
if __name__ == "__main__":
    test_payload = "SELECT * FROM users WHERE username = 'admin';"
    matches = match_signature(test_payload)
    if matches:
        print(f"Signature Detected: {matches}")
    else:
        print("No signature detected.")
