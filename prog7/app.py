"""
This file combines all the functionality of the project into a single Streamlit application.
It includes hash functions, obfuscation techniques, practical examples, and tests, all accessible through a web interface.
"""

import streamlit as st
import hashlib
import os
from typing import Union, Optional
import base64
import marshal
import types
import zlib
import ast
import random
import string
import json
import time
import sys
import traceback
from io import StringIO

# --- Core Logic Classes (from the original project) ---

class HashGenerator:
    """A class to generate various hash values for strings and files"""
    
    def __init__(self):
        self.supported_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'sha224': hashlib.sha224,
            'sha384': hashlib.sha384
        }
    
    def hash_string(self, text: str, algorithm: str = 'sha256') -> str:
        if algorithm.lower() not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        hash_obj = self.supported_algorithms[algorithm.lower()]()
        hash_obj.update(text.encode('utf-8'))
        return hash_obj.hexdigest()
    
    def hash_file(self, file_bytes: bytes, algorithm: str = 'sha256', chunk_size: int = 8192) -> str:
        if algorithm.lower() not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        hash_obj = self.supported_algorithms[algorithm.lower()]()
        
        # Process bytes directly
        offset = 0
        while chunk := file_bytes[offset:offset + chunk_size]:
            hash_obj.update(chunk)
            offset += chunk_size
        
        return hash_obj.hexdigest()

    def hash_multiple_algorithms(self, text: str) -> dict:
        results = {}
        for algorithm in self.supported_algorithms:
            results[algorithm] = self.hash_string(text, algorithm)
        return results
    
    def compare_hashes(self, text1: str, text2: str, algorithm: str = 'sha256') -> bool:
        hash1 = self.hash_string(text1, algorithm)
        hash2 = self.hash_string(text2, algorithm)
        return hash1 == hash2
    
    def verify_file_integrity(self, file_bytes: bytes, expected_hash: str, algorithm: str = 'sha256') -> bool:
        actual_hash = self.hash_file(file_bytes, algorithm)
        return actual_hash.lower() == expected_hash.lower()

class CodeObfuscator:
    """A class to demonstrate various code obfuscation techniques"""
    
    def __init__(self):
        self.variable_mapping = {}
        self.function_mapping = {}
    
    def base64_obfuscation(self, code: str) -> str:
        encoded_code = base64.b64encode(code.encode()).decode()
        return f"import base64\nexec(base64.b64decode('{encoded_code}').decode())"
    
    def zlib_compression_obfuscation(self, code: str) -> str:
        compressed = zlib.compress(code.encode())
        encoded = base64.b64encode(compressed).decode()
        return f"import zlib, base64\nexec(zlib.decompress(base64.b64decode('{encoded}')).decode())"
    
    def marshal_obfuscation(self, code: str) -> str:
        compiled_code = compile(code, '<string>', 'exec')
        marshaled = marshal.dumps(compiled_code)
        encoded = base64.b64encode(marshaled).decode()
        return f"import marshal, base64\nexec(marshal.loads(base64.b64decode('{encoded}')))"
    
    def string_obfuscation(self, text: str) -> str:
        char_codes = [str(ord(c)) for c in text]
        return f"''.join(chr(x) for x in [{','.join(char_codes)}])"
    
    def multilayer_obfuscation(self, code: str) -> str:
        obfuscated = self.zlib_compression_obfuscation(code)
        obfuscated = self.base64_obfuscation(obfuscated)
        return obfuscated

class ObfuscatedFunction:
    """Example of an obfuscated function class"""
    
    def hidden_calculation(self, x: int, y: int) -> int:
        a = x.__mul__(y)
        b = a.__add__(10)
        return b
    
    def reveal_secret(self, password: str) -> str:
        correct_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        provided_hash = hashlib.sha256(password.encode()).hexdigest()
        if provided_hash == correct_hash:
            secret = self._string_obfuscation("The secret is: Code obfuscation is a technique to make code harder to understand!")
            return eval(secret)
        else:
            return "Access denied!"
    
    def _string_obfuscation(self, text: str) -> str:
        char_codes = [str(ord(c)) for c in text]
        return f"''.join(chr(x) for x in [{','.join(char_codes)}])"

class PasswordManager:
    """Simple password manager demonstrating hash function usage"""
    def __init__(self, session_state):
        self.hasher = HashGenerator()
        if 'users' not in session_state:
            session_state['users'] = {}
        self.users = session_state['users']

    def hash_password(self, password: str, salt: str = None) -> tuple:
        if salt is None:
            salt = os.urandom(32).hex()
        salted_password = password + salt
        password_hash = self.hasher.hash_string(salted_password, 'sha256')
        return password_hash, salt

    def register_user(self, username: str, password: str) -> bool:
        if username in self.users:
            return False
        password_hash, salt = self.hash_password(password)
        self.users[username] = {
            'password_hash': password_hash,
            'salt': salt,
            'created_at': time.time()
        }
        return True

    def authenticate_user(self, username: str, password: str) -> bool:
        if username not in self.users:
            return False
        user_data = self.users[username]
        salt = user_data['salt']
        stored_hash = user_data['password_hash']
        provided_hash, _ = self.hash_password(password, salt)
        return provided_hash == stored_hash

class FileIntegrityChecker:
    """File integrity checker using hash functions"""
    def __init__(self, session_state):
        self.hasher = HashGenerator()
        if 'file_hashes' not in session_state:
            session_state['file_hashes'] = {}
        self.file_hashes = session_state['file_hashes']

    def add_file(self, file_name: str, file_bytes: bytes) -> str:
        file_hash = self.hasher.hash_file(file_bytes, 'sha256')
        self.file_hashes[file_name] = {
            'hash': file_hash,
            'size': len(file_bytes),
            'added_at': time.time(),
        }
        return file_hash

    def check_file(self, file_name: str, file_bytes: bytes) -> dict:
        if file_name not in self.file_hashes:
            return {'status': 'not_monitored', 'message': 'File is not being monitored'}
        
        stored_data = self.file_hashes[file_name]
        current_hash = self.hasher.hash_file(file_bytes, 'sha256')
        current_size = len(file_bytes)

        if current_hash == stored_data['hash'] and current_size == stored_data['size']:
            return {'status': 'unchanged', 'message': 'File is unchanged'}
        else:
            return {
                'status': 'modified',
                'message': 'File has been modified',
                'original_hash': stored_data['hash'],
                'current_hash': current_hash,
            }

class LicenseKeyGenerator:
    """Obfuscated license key generator"""
    def __init__(self):
        self.hasher = HashGenerator()

    def generate_license_key(self, user_id: str, product_code: str) -> str:
        unique_string = f"{user_id}:{product_code}:{time.time()}"
        hash_value = self.hasher.hash_string(unique_string, 'sha256')
        key_core = hash_value[:16].upper()
        
        parts = [key_core[i:i+4] for i in range(0, len(key_core), 4)]
        formatted_key = f"LIC-{''.join(parts)}-2024"
        return formatted_key

    def validate_license_key(self, license_key: str) -> bool:
        if not license_key.startswith('LIC-') or not license_key.endswith('-2024'):
            return False
        parts = license_key.split('-')
        if len(parts) != 3:
            return False
        key_core = parts[1]
        return len(key_core) == 16 and all(c in string.hexdigits for c in key_core)

# --- UI Functions ---

def show_hash_functions():
    st.header("Hash Functions")
    hasher = HashGenerator()
    
    tab1, tab2 = st.tabs(["Interactive Demo", "Demonstration"])

    with tab1:
        st.subheader("Interactive Hashing")
        option = st.selectbox("Choose an operation", ["Hash a string", "Hash a file", "Compare two strings"])

        if option == "Hash a string":
            text = st.text_input("Enter text to hash:")
            algorithm = st.selectbox("Select algorithm", list(hasher.supported_algorithms.keys()), index=2)
            if st.button("Generate Hash"):
                if text:
                    hash_value = hasher.hash_string(text, algorithm)
                    st.success(f"**{algorithm.upper()} Hash:**")
                    st.code(hash_value, language="")
                else:
                    st.warning("Please enter some text.")

        elif option == "Hash a file":
            uploaded_file = st.file_uploader("Choose a file")
            algorithm = st.selectbox("Select algorithm ", list(hasher.supported_algorithms.keys()), index=2)
            if st.button("Generate File Hash"):
                if uploaded_file is not None:
                    file_bytes = uploaded_file.getvalue()
                    hash_value = hasher.hash_file(file_bytes, algorithm)
                    st.success(f"**{algorithm.upper()} Hash of `{uploaded_file.name}`:**")
                    st.code(hash_value, language="")
                else:
                    st.warning("Please upload a file.")

        elif option == "Compare two strings":
            col1, col2 = st.columns(2)
            with col1:
                text1 = st.text_area("First string:")
            with col2:
                text2 = st.text_area("Second string:")
            algorithm = st.selectbox("Select algorithm  ", list(hasher.supported_algorithms.keys()), index=2)
            if st.button("Compare Hashes"):
                are_same = hasher.compare_hashes(text1, text2, algorithm)
                if are_same:
                    st.success("The hashes of the two strings are identical.")
                else:
                    st.error("The hashes of the two strings are different.")
                st.write(f"**Hash 1:** `{hasher.hash_string(text1, algorithm)}`")
                st.write(f"**Hash 2:** `{hasher.hash_string(text2, algorithm)}`")

    with tab2:
        st.subheader("Avalanche Effect Demonstration")
        original = "password"
        modified = "Password"
        st.write(f"**Original:** `{original}`")
        st.write(f"**Modified:** `{modified}` (only one character changed)")
        st.write(f"**SHA-256 of '{original}':** `{hasher.hash_string(original)}`")
        st.write(f"**SHA-256 of '{modified}':** `{hasher.hash_string(modified)}`")
        st.info("Notice how a small change in input results in a completely different hash.")

def show_obfuscation():
    st.header("Code Obfuscation")
    obfuscator = CodeObfuscator()
    
    tab1, tab2 = st.tabs(["Interactive Demo", "Demonstration"])

    with tab1:
        st.subheader("Obfuscate Your Code")
        code = st.text_area("Enter Python code to obfuscate:", height=200, value="print('Hello from obfuscated code!')")
        method = st.selectbox("Choose obfuscation method", ["Base64", "Zlib + Base64", "Marshal + Base64", "Multilayer"])
        
        if st.button("Obfuscate"):
            if code:
                obfuscated_code = ""
                if method == "Base64":
                    obfuscated_code = obfuscator.base64_obfuscation(code)
                elif method == "Zlib + Base64":
                    obfuscated_code = obfuscator.zlib_compression_obfuscation(code)
                elif method == "Marshal + Base64":
                    obfuscated_code = obfuscator.marshal_obfuscation(code)
                elif method == "Multilayer":
                    obfuscated_code = obfuscator.multilayer_obfuscation(code)
                
                st.subheader("Obfuscated Code")
                st.code(obfuscated_code, language="python")

                with st.expander("Execute Obfuscated Code?"):
                    st.warning("Executing arbitrary code can be risky.")
                    if st.button("Yes, execute it"):
                        old_stdout = sys.stdout
                        sys.stdout = mystdout = StringIO()
                        try:
                            exec(obfuscated_code, {})
                            sys.stdout = old_stdout
                            st.text("Execution Output:")
                            st.code(mystdout.getvalue(), language="")
                        except Exception as e:
                            sys.stdout = old_stdout
                            st.error(f"Execution failed: {e}")
            else:
                st.warning("Please enter some code to obfuscate.")

    with tab2:
        st.subheader("Obfuscated Function Example")
        obf_func = ObfuscatedFunction()
        
        st.write("This demonstrates a function with hidden logic.")
        col1, col2 = st.columns(2)
        with col1:
            x = st.number_input("Enter first number (x)", value=7)
        with col2:
            y = st.number_input("Enter second number (y)", value=6)
        
        result = obf_func.hidden_calculation(x, y)
        st.write(f"The obfuscated calculation is `x * y + 10`.")
        st.success(f"Result of hidden calculation: {result}")

        st.subheader("Secret Reveal")
        password = st.text_input("Enter password to reveal secret:", type="password")
        if st.button("Reveal Secret"):
            secret = obf_func.reveal_secret(password)
            if "Access denied" in secret:
                st.error(secret)
            else:
                st.success(secret)
            st.info("The correct password is `secret123`")

def show_practical_examples():
    st.header("Practical Examples")

    with st.expander("1. Password Manager"):
        pm = PasswordManager(st.session_state)
        st.subheader("Register User")
        reg_user = st.text_input("Username", key="reg_user")
        reg_pass = st.text_input("Password", type="password", key="reg_pass")
        if st.button("Register"):
            if pm.register_user(reg_user, reg_pass):
                st.success(f"User '{reg_user}' registered successfully.")
            else:
                st.error(f"User '{reg_user}' already exists.")

        st.subheader("Authenticate User")
        auth_user = st.text_input("Username", key="auth_user")
        auth_pass = st.text_input("Password", type="password", key="auth_pass")
        if st.button("Authenticate"):
            if pm.authenticate_user(auth_user, auth_pass):
                st.success("Authentication successful.")
            else:
                st.error("Authentication failed.")
        
        if st.checkbox("Show registered users (for demo)"):
            st.json(st.session_state.get('users', {}))

    with st.expander("2. File Integrity Checker"):
        fic = FileIntegrityChecker(st.session_state)
        st.subheader("Monitor a File")
        monitored_file = st.file_uploader("Upload a file to add to monitoring", key="monitor_file")
        if st.button("Add to Monitoring"):
            if monitored_file:
                file_hash = fic.add_file(monitored_file.name, monitored_file.getvalue())
                st.success(f"File `{monitored_file.name}` added with hash: `{file_hash}`")
            else:
                st.warning("Please upload a file.")

        st.subheader("Check a File")
        checked_file = st.file_uploader("Upload a file to check its integrity", key="check_file")
        if st.button("Check Integrity"):
            if checked_file:
                result = fic.check_file(checked_file.name, checked_file.getvalue())
                if result['status'] == 'unchanged':
                    st.success(result['message'])
                elif result['status'] == 'modified':
                    st.warning(result['message'])
                    st.write(f"Original Hash: `{result['original_hash']}`")
                    st.write(f"Current Hash: `{result['current_hash']}`")
                else:
                    st.info(result['message'])
            else:
                st.warning("Please upload a file.")

        if st.checkbox("Show monitored files (for demo)"):
            st.json(st.session_state.get('file_hashes', {}))

    with st.expander("3. Obfuscated License Key Generator"):
        lkg = LicenseKeyGenerator()
        st.subheader("Generate License Key")
        user_id = st.text_input("User ID", value="user123")
        product_code = st.text_input("Product Code", value="PROD001")
        if st.button("Generate Key"):
            key = lkg.generate_license_key(user_id, product_code)
            st.success("Generated License Key:")
            st.code(key, language="")

        st.subheader("Validate License Key")
        key_to_validate = st.text_input("License Key to Validate")
        if st.button("Validate Key"):
            if lkg.validate_license_key(key_to_validate):
                st.success("License key is valid.")
            else:
                st.error("License key is invalid.")

def show_tests():
    st.header("Run Project Tests")
    if st.button("Run All Tests"):
        with st.spinner("Running tests..."):
            # Redirect stdout to capture test results
            old_stdout = sys.stdout
            sys.stdout = mystdout = StringIO()

            # Mock functions from the original test script that are not available in Streamlit
            def mock_demonstrate_practical_applications():
                pass
            
            original_practical_demo = None
            if 'demonstrate_practical_applications' in globals():
                original_practical_demo = globals()['demonstrate_practical_applications']
                globals()['demonstrate_practical_applications'] = mock_demonstrate_practical_applications

            # Test functions from the original project
            def test_hash_functions():
                print("Testing Hash Functions...")
                try:
                    hasher = HashGenerator()
                    test_hash = hasher.hash_string("test", "sha256")
                    expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                    assert test_hash == expected
                    assert len(hasher.hash_multiple_algorithms("test")) == 6
                    assert hasher.compare_hashes("same", "same")
                    print("✓ Hash Functions: All tests passed")
                    return True
                except Exception as e:
                    print(f"✗ Hash Functions: Test failed - {e}")
                    return False

            def test_obfuscation():
                print("Testing Obfuscation Techniques...")
                try:
                    obfuscator = CodeObfuscator()
                    original_code = "print('Hello, World!')"
                    obfuscated = obfuscator.base64_obfuscation(original_code)
                    assert "base64" in obfuscated and "exec" in obfuscated
                    obf_func = ObfuscatedFunction()
                    assert obf_func.hidden_calculation(5, 6) == 40
                    print("✓ Obfuscation: All tests passed")
                    return True
                except Exception as e:
                    print(f"✗ Obfuscation: Test failed - {e}")
                    return False

            def run_all_tests():
                tests = [test_hash_functions, test_obfuscation]
                passed = sum(1 for test in tests if test())
                print("\n" + "=" * 60)
                print(f"TEST RESULTS: {passed}/{len(tests)} tests passed")
                print("=" * 60)

            run_all_tests()
            
            # Restore stdout and globals
            sys.stdout = old_stdout
            if original_practical_demo:
                globals()['demonstrate_practical_applications'] = original_practical_demo

            st.text("Test Results:")
            st.code(mystdout.getvalue())

def main():
    st.sidebar.title("Navigation")
    choice = st.sidebar.radio("Go to", ["Hash Functions", "Code Obfuscation", "Practical Examples", "Run Tests"])

    if choice == "Hash Functions":
        show_hash_functions()
    elif choice == "Code Obfuscation":
        show_obfuscation()
    elif choice == "Practical Examples":
        show_practical_examples()
    elif choice == "Run Tests":
        show_tests()

if __name__ == "__main__":
    st.set_page_config(page_title="Security Concepts Demo", layout="wide")
    st.title("Hashing and Obfuscation: A Practical Demonstration")
    main()
