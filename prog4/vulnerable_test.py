#!/usr/bin/env python3
"""
Test file with intentional security vulnerabilities for demonstration
WARNING: This file contains intentional security vulnerabilities for educational purposes only!
"""

import os
import subprocess
import pickle
import tempfile

# Hardcoded secrets (HIGH severity)
API_KEY = "sk-1234567890abcdef"
password = "mypassword123"
secret_token = "bearer_abc123def456"

def vulnerable_eval_function(user_input):
    # Dynamic code execution (HIGH severity)
    result = eval(user_input)
    return result

def vulnerable_exec_function(code):
    # Another form of dynamic execution (HIGH severity)
    exec(code)

def vulnerable_shell_command(filename):
    # Shell injection vulnerability (HIGH severity)
    subprocess.Popen(f"cat {filename}", shell=True)

def vulnerable_system_call(command):
    # Direct system call (HIGH severity)
    os.system(command)

def vulnerable_pickle_load(data):
    # Unsafe deserialization (HIGH severity)
    return pickle.loads(data)

def use_weak_crypto():
    # Weak cryptographic functions (MEDIUM severity)
    import hashlib
    return hashlib.md5(b"data").hexdigest()

def insecure_temp_file():
    # Insecure temporary file (HIGH severity)
    return tempfile.mktemp()

def disable_ssl_verification():
    # Disabled SSL verification (HIGH severity)
    import requests
    response = requests.get("https://example.com", verify=False)
    return response

def unsafe_file_permissions():
    # Insecure file permissions (MEDIUM severity)
    os.chmod("secret.txt", 0o777)

# HTTP endpoint (LOW severity)
API_ENDPOINT = "http://insecure-api.example.com/data"

if __name__ == "__main__":
    print("This is a test file with intentional vulnerabilities")
