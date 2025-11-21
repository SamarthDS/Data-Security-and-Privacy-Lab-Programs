#!/usr/bin/env python3
"""
Test file with intentional security issues for demonstrating the file scanner.
WARNING: This file contains potentially dangerous patterns for educational purposes only.
"""

import os
import subprocess
import base64

# Hardcoded credentials (HIGH RISK)
api_key = "sk-1234567890abcdef"
password = "admin123"
secret_token = "abc123xyz789"

# Dangerous eval usage (HIGH RISK)
user_input = "print('hello world')"
eval(user_input)

# Subprocess with shell=True (HIGH RISK)
subprocess.Popen("ls -la", shell=True)

# Direct system call (HIGH RISK)
os.system("whoami")

# Weak cryptography (MEDIUM RISK)
import hashlib
weak_hash = hashlib.md5(b"password").hexdigest()

# Suspicious URLs (LOW RISK)
malicious_url = "http://suspicious-site.com/download.exe"
phishing_url = "https://paypal-security-update.fake-domain.tk"

# Base64 encoded secret (MEDIUM RISK)
encoded_secret = base64.b64decode("c2VjcmV0UGFzc3dvcmQxMjM=")

# Suspicious file operations (MEDIUM RISK)
os.chmod("test_file.txt", 0o777)

print("This is a test file with security vulnerabilities for demonstration purposes.")
