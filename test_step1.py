# test_step1.py
from core.patterns import scan_text

# 1. Test a Safe String
safe_text = "Hello, I am writing some Python code today."
print(f"Testing Safe Text: {scan_text(safe_text)}") 
# Expected: None

# 2. Test a Fake Aadhaar
aadhaar_text = "My ID is 4589 1234 5678, please verify."
print(f"Testing Aadhaar: {scan_text(aadhaar_text)}") 
# Expected: {'type': 'Aadhaar Number', ...}

# 3. Test a Fake AWS Key
aws_text = "config.access_key = 'AKIAIOSFODNN7EXAMPLE'"
print(f"Testing AWS Key: {scan_text(aws_text)}") 
# Expected: {'type': 'AWS Access Key', ...}