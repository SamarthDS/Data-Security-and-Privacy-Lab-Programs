"""
This file combines all the functionality of the project into a single script.
It includes hash functions, obfuscation techniques, practical examples, tests, and the main interactive demonstration.
"""

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

# --- From hash_functions.py ---

class HashGenerator:
    """A class to generate various hash values for strings and files"""
    
    def __init__(self):
        """Initialize the hash generator"""
        self.supported_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'sha224': hashlib.sha224,
            'sha384': hashlib.sha384
        }
    
    def hash_string(self, text: str, algorithm: str = 'sha256') -> str:
        """
        Generate hash for a string
        
        Args:
            text (str): Input string to hash
            algorithm (str): Hash algorithm to use (default: sha256)
            
        Returns:
            str: Hexadecimal hash value
        """
        if algorithm.lower() not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hash_obj = self.supported_algorithms[algorithm.lower()]()
        hash_obj.update(text.encode('utf-8'))
        return hash_obj.hexdigest()
    
    def hash_file(self, file_path: str, algorithm: str = 'sha256', chunk_size: int = 8192) -> str:
        """
        Generate hash for a file
        
        Args:
            file_path (str): Path to the file
            algorithm (str): Hash algorithm to use (default: sha256)
            chunk_size (int): Size of chunks to read (default: 8192 bytes)
            
        Returns:
            str: Hexadecimal hash value
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if algorithm.lower() not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hash_obj = self.supported_algorithms[algorithm.lower()]()
        
        with open(file_path, 'rb') as file:
            while chunk := file.read(chunk_size):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    def hash_multiple_algorithms(self, text: str) -> dict:
        """
        Generate hashes using multiple algorithms
        
        Args:
            text (str): Input string to hash
            
        Returns:
            dict: Dictionary with algorithm names as keys and hash values as values
        """
        results = {}
        for algorithm in self.supported_algorithms:
            results[algorithm] = self.hash_string(text, algorithm)
        return results
    
    def compare_hashes(self, text1: str, text2: str, algorithm: str = 'sha256') -> bool:
        """
        Compare hash values of two strings
        
        Args:
            text1 (str): First string
            text2 (str): Second string
            algorithm (str): Hash algorithm to use
            
        Returns:
            bool: True if hashes match, False otherwise
        """
        hash1 = self.hash_string(text1, algorithm)
        hash2 = self.hash_string(text2, algorithm)
        return hash1 == hash2
    
    def verify_file_integrity(self, file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """
        Verify file integrity by comparing with expected hash
        
        Args:
            file_path (str): Path to the file
            expected_hash (str): Expected hash value
            algorithm (str): Hash algorithm to use
            
        Returns:
            bool: True if file hash matches expected hash
        """
        actual_hash = self.hash_file(file_path, algorithm)
        return actual_hash.lower() == expected_hash.lower()


def demonstrate_hash_functions():
    """Demonstrate various hash function capabilities"""
    print("=" * 60)
    print("HASH FUNCTIONS DEMONSTRATION")
    print("=" * 60)
    
    hasher = HashGenerator()
    
    test_string = "Hello, World! This is a test string for hashing."
    print(f"\nOriginal String: {test_string}")
    print("-" * 40)
    
    hashes = hasher.hash_multiple_algorithms(test_string)
    for algorithm, hash_value in hashes.items():
        print(f"{algorithm.upper()}: {hash_value}")
    
    print("\n" + "=" * 40)
    print("HASH COMPARISON TEST")
    print("=" * 40)
    
    string1 = "identical"
    string2 = "identical"
    string3 = "different"
    
    print(f"String 1: '{string1}'")
    print(f"String 2: '{string2}'")
    print(f"String 3: '{string3}'")
    
    print(f"\nAre strings 1 and 2 identical? {hasher.compare_hashes(string1, string2)}")
    print(f"Are strings 1 and 3 identical? {hasher.compare_hashes(string1, string3)}")
    
    print("\n" + "=" * 40)
    print("AVALANCHE EFFECT DEMONSTRATION")
    print("=" * 40)
    
    original = "password"
    modified = "Password"
    
    print(f"Original: '{original}'")
    print(f"Modified: '{modified}'")
    print(f"\nSHA-256 of '{original}': {hasher.hash_string(original)}")
    print(f"SHA-256 of '{modified}': {hasher.hash_string(modified)}")
    
    print("\n" + "=" * 40)
    print("FILE HASHING DEMONSTRATION")
    print("=" * 40)
    
    test_file_path = "test_file.txt"
    test_content = "This is a test file for demonstrating file hashing.\nIt contains multiple lines.\nHash functions work on binary data."
    
    with open(test_file_path, 'w', encoding='utf-8') as f:
        f.write(test_content)
    
    print(f"Created test file: {test_file_path}")
    file_hash = hasher.hash_file(test_file_path)
    print(f"SHA-256 of file: {file_hash}")
    
    print(f"File integrity check: {hasher.verify_file_integrity(test_file_path, file_hash)}")
    
    if os.path.exists(test_file_path):
        os.remove(test_file_path)
        print(f"Cleaned up test file: {test_file_path}")

# --- From obfuscation_techniques.py ---

class CodeObfuscator:
    """A class to demonstrate various code obfuscation techniques"""
    
    def __init__(self):
        """Initialize the obfuscator"""
        self.variable_mapping = {}
        self.function_mapping = {}
    
    def base64_obfuscation(self, code: str) -> str:
        """Simple base64 encoding obfuscation"""
        encoded_code = base64.b64encode(code.encode()).decode()
        obfuscated = f"""
import base64
exec(base64.b64decode('{encoded_code}').decode())
"""
        return obfuscated
    
    def zlib_compression_obfuscation(self, code: str) -> str:
        """Obfuscation using zlib compression"""
        compressed = zlib.compress(code.encode())
        encoded = base64.b64encode(compressed).decode()
        obfuscated = f"""
import zlib, base64
exec(zlib.decompress(base64.b64decode('{encoded}')).decode())
"""
        return obfuscated
    
    def marshal_obfuscation(self, code: str) -> str:
        """Obfuscation using marshal serialization"""
        compiled_code = compile(code, '<string>', 'exec')
        marshaled = marshal.dumps(compiled_code)
        encoded = base64.b64encode(marshaled).decode()
        obfuscated = f"""
import marshal, base64
exec(marshal.loads(base64.b64decode('{encoded}')))
"""
        return obfuscated
    
    def generate_random_name(self, length: int = 8) -> str:
        """Generate a random variable/function name"""
        return ''.join(random.choices(string.ascii_letters + '_', k=length))
    
    def variable_name_obfuscation(self, code: str) -> str:
        """Simple variable name obfuscation"""
        lines = code.split('\n')
        obfuscated_lines = []
        
        for line in lines:
            if '=' in line and not line.strip().startswith('#'):
                parts = line.split('=', 1)
                if len(parts) == 2:
                    var_part = parts[0].strip()
                    if var_part.isidentifier() and var_part not in self.variable_mapping:
                        new_name = self.generate_random_name()
                        self.variable_mapping[var_part] = new_name
                    
                    for old_name, new_name in self.variable_mapping.items():
                        line = line.replace(old_name, new_name)
            else:
                for old_name, new_name in self.variable_mapping.items():
                    line = line.replace(old_name, new_name)
            
            obfuscated_lines.append(line)
        
        return '\n'.join(obfuscated_lines)
    
    def string_obfuscation(self, text: str) -> str:
        """Obfuscate strings by converting to character codes"""
        char_codes = [str(ord(c)) for c in text]
        return f"''.join(chr(x) for x in [{','.join(char_codes)}])"
    
    def multilayer_obfuscation(self, code: str) -> str:
        """Apply multiple layers of obfuscation"""
        obfuscated = self.variable_name_obfuscation(code)
        obfuscated = self.zlib_compression_obfuscation(obfuscated)
        obfuscated = self.base64_obfuscation(obfuscated)
        return obfuscated


class ObfuscatedFunction:
    """Example of an obfuscated function class"""
    
    def __init__(self):
        self._encoded_func = "aW1wb3J0IGJhc2U2NCwgemxpYg=="
        self._calc_data = "eJwLycgsVsjIzEvLL8pNzStRslIw0jM0MjEzMbZSUEovykvMTQWKFesZ6hkZGOkZmZjrKQAFjfQMDRTyi_KLShWMFYx1rRQ8SzJSixJzUhVySzMBZm1q8g=="
    
    def _decode_and_execute(self, encoded_data: str):
        """Decode and execute obfuscated code"""
        import base64, zlib
        try:
            decoded = base64.b64decode(encoded_data)
            decompressed = zlib.decompress(decoded).decode()
            return compile(decompressed, '<obfuscated>', 'eval')
        except:
            return None
    
    def hidden_calculation(self, x: int, y: int) -> int:
        """A function with hidden logic"""
        a = x.__mul__(y)
        b = a.__add__(10)
        return b
    
    def reveal_secret(self, password: str) -> str:
        """Function that reveals a secret if correct password is provided"""
        correct_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        
        import hashlib
        provided_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if provided_hash == correct_hash:
            secret = self.string_obfuscation("The secret is: Code obfuscation is a technique to make code harder to understand!")
            return eval(secret)
        else:
            return "Access denied!"
    
    def string_obfuscation(self, text: str) -> str:
        """Helper method for string obfuscation"""
        char_codes = [str(ord(c)) for c in text]
        return f"''.join(chr(x) for x in [{','.join(char_codes)}])"


def demonstrate_obfuscation():
    """Demonstrate various obfuscation techniques"""
    print("=" * 60)
    print("CODE OBFUSCATION DEMONSTRATION")
    print("=" * 60)
    
    obfuscator = CodeObfuscator()
    
    original_code = '''
def simple_function(x, y):
    result = x + y
    message = "The sum is: " + str(result)
    return message

print(simple_function(5, 3))
'''
    
    print("Original Code:")
    print("-" * 40)
    print(original_code)
    
    print("\n" + "=" * 60)
    print("OBFUSCATION TECHNIQUES")
    print("=" * 60)
    
    print("\n1. Base64 Obfuscation:")
    print("-" * 40)
    base64_obfuscated = obfuscator.base64_obfuscation(original_code)
    print(base64_obfuscated)
    
    print("\n2. Zlib Compression Obfuscation:")
    print("-" * 40)
    zlib_obfuscated = obfuscator.zlib_compression_obfuscation(original_code)
    print(zlib_obfuscated)
    
    print("\n3. Marshal Obfuscation:")
    print("-" * 40)
    marshal_obfuscated = obfuscator.marshal_obfuscation(original_code)
    print(marshal_obfuscated)
    
    print("\n4. Variable Name Obfuscation:")
    print("-" * 40)
    var_obfuscated = obfuscator.variable_name_obfuscation(original_code)
    print(var_obfuscated)
    
    print("\n5. Multilayer Obfuscation:")
    print("-" * 40)
    multilayer_obfuscated = obfuscator.multilayer_obfuscation(original_code)
    print(multilayer_obfuscated[:200] + "..." if len(multilayer_obfuscated) > 200 else multilayer_obfuscated)
    
    print("\n" + "=" * 60)
    print("OBFUSCATED FUNCTION DEMONSTRATION")
    print("=" * 60)
    
    obf_func = ObfuscatedFunction()
    
    result = obf_func.hidden_calculation(7, 6)
    print(f"Hidden calculation result (7, 6): {result}")
    
    print(f"Wrong password: {obf_func.reveal_secret('wrong')}")
    
    print(f"Correct password: {obf_func.reveal_secret('secret123')}")
    
    print("\n" + "=" * 60)
    print("TESTING OBFUSCATED CODE EXECUTION")
    print("=" * 60)
    
    print("Executing base64 obfuscated code:")
    try:
        exec(base64_obfuscated)
    except Exception as e:
        print(f"Error executing obfuscated code: {e}")

def _0x1a2b3c():
    """An example of extreme obfuscation"""
    _0x4d5e6f = lambda _0x7g8h9i: ''.join(chr(x) for x in [72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33])
    _0x1j2k3l = _0x4d5e6f(None)
    return _0x1j2k3l

# --- From practical_examples.py ---

class PasswordManager:
    """Simple password manager demonstrating hash function usage"""

    def __init__(self):
        self.users_file = "users.json"
        self.hasher = HashGenerator()
        self.load_users()

    def load_users(self):
        """Load users from file or create empty database"""
        try:
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        except FileNotFoundError:
            self.users = {}

    def save_users(self):
        """Save users to file"""
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=2)

    def hash_password(self, password: str, salt: str = None) -> tuple:
        """Hash a password with salt"""
        if salt is None:
            salt = os.urandom(32).hex()
        salted_password = password + salt
        password_hash = self.hasher.hash_string(salted_password, 'sha256')
        return password_hash, salt

    def register_user(self, username: str, password: str) -> bool:
        """Register a new user"""
        if username in self.users:
            return False
        password_hash, salt = self.hash_password(password)
        self.users[username] = {
            'password_hash': password_hash,
            'salt': salt,
            'created_at': time.time()
        }
        self.save_users()
        return True

    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate a user"""
        if username not in self.users:
            return False
        user_data = self.users[username]
        salt = user_data['salt']
        stored_hash = user_data['password_hash']
        provided_hash, _ = self.hash_password(password, salt)
        return provided_hash == stored_hash


class FileIntegrityChecker:
    """File integrity checker using hash functions"""

    def __init__(self):
        self.hasher = HashGenerator()
        self.integrity_file = "file_hashes.json"
        self.load_hashes()

    def load_hashes(self):
        """Load stored file hashes"""
        try:
            with open(self.integrity_file, 'r') as f:
                self.file_hashes = json.load(f)
        except FileNotFoundError:
            self.file_hashes = {}

    def save_hashes(self):
        """Save file hashes"""
        with open(self.integrity_file, 'w') as f:
            json.dump(self.file_hashes, f, indent=2)

    def add_file(self, file_path: str) -> str:
        """Add a file to integrity monitoring"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        file_hash = self.hasher.hash_file(file_path, 'sha256')
        file_size = os.path.getsize(file_path)
        self.file_hashes[file_path] = {
            'hash': file_hash,
            'size': file_size,
            'added_at': time.time(),
            'last_checked': time.time()
        }
        self.save_hashes()
        return file_hash

    def check_file(self, file_path: str) -> dict:
        """Check if a file has been modified"""
        if file_path not in self.file_hashes:
            return {'status': 'not_monitored', 'message': 'File is not being monitored'}
        if not os.path.exists(file_path):
            return {'status': 'missing', 'message': 'File is missing'}
        stored_data = self.file_hashes[file_path]
        current_hash = self.hasher.hash_file(file_path, 'sha256')
        current_size = os.path.getsize(file_path)
        stored_data['last_checked'] = time.time()
        self.save_hashes()
        if current_hash == stored_data['hash'] and current_size == stored_data['size']:
            return {'status': 'unchanged', 'message': 'File is unchanged'}
        else:
            return {
                'status': 'modified',
                'message': 'File has been modified',
                'original_hash': stored_data['hash'],
                'current_hash': current_hash,
                'original_size': stored_data['size'],
                'current_size': current_size
            }

    def check_all_files(self) -> dict:
        """Check all monitored files"""
        results = {}
        for file_path in self.file_hashes.keys():
            results[file_path] = self.check_file(file_path)
        return results


class LicenseKeyGenerator:
    """Obfuscated license key generator"""

    def __init__(self):
        self.obfuscator = CodeObfuscator()
        self.hasher = HashGenerator()
        self._key_parts = self._get_obfuscated_parts()

    def _get_obfuscated_parts(self) -> dict:
        """Get obfuscated key generation components"""
        return {
            'prefix': base64.b64encode(b'LIC').decode(),
            'separator': base64.b64encode(b'-').decode(),
            'suffix': base64.b64encode(b'2024').decode()
        }

    def generate_license_key(self, user_id: str, product_code: str) -> str:
        """Generate an obfuscated license key"""
        unique_string = f"{user_id}:{product_code}:{time.time()}"
        hash_value = self.hasher.hash_string(unique_string, 'sha256')
        key_core = hash_value[:16].upper()
        prefix = base64.b64decode(self._key_parts['prefix']).decode()
        separator = base64.b64decode(self._key_parts['separator']).decode()
        suffix = base64.b64decode(self._key_parts['suffix']).decode()
        formatted_key = f"{prefix}{separator}{key_core[:4]}{separator}{key_core[4:8]}{separator}{key_core[8:12]}{separator}{key_core[12:16]}{separator}{suffix}"
        return formatted_key

    def validate_license_key(self, license_key: str, user_id: str, product_code: str) -> bool:
        """Validate a license key (simplified validation)"""
        if not license_key.startswith('LIC-') or not license_key.endswith('-2024'):
            return False
        parts = license_key.split('-')
        if len(parts) != 6:
            return False
        key_core = ''.join(parts[1:5])
        try:
            int(key_core, 16)
            return len(key_core) == 16
        except ValueError:
            return False


def demonstrate_practical_applications():
    """Demonstrate practical applications"""
    print("=" * 80)
    print("PRACTICAL APPLICATIONS DEMONSTRATION")
    print("=" * 80)

    print("\n1. PASSWORD MANAGER DEMONSTRATION")
    print("-" * 50)
    pm = PasswordManager()
    print("Registering users...")
    success1 = pm.register_user("alice", "mypassword123")
    success2 = pm.register_user("bob", "securepwd456")
    success3 = pm.register_user("alice", "duplicate")
    print(f"Alice registration: {'Success' if success1 else 'Failed'}")
    print(f"Bob registration: {'Success' if success2 else 'Failed'}")
    print(f"Alice duplicate: {'Success' if success3 else 'Failed (expected)'}")
    print("\nAuthenticating users...")
    auth1 = pm.authenticate_user("alice", "mypassword123")
    auth2 = pm.authenticate_user("alice", "wrongpassword")
    auth3 = pm.authenticate_user("bob", "securepwd456")
    print(f"Alice correct password: {'Success' if auth1 else 'Failed'}")
    print(f"Alice wrong password: {'Success' if auth2 else 'Failed (expected)'}")
    print(f"Bob correct password: {'Success' if auth3 else 'Failed'}")

    print("\n2. FILE INTEGRITY CHECKER DEMONSTRATION")
    print("-" * 50)
    fic = FileIntegrityChecker()
    test_file = "integrity_test.txt"
    with open(test_file, 'w') as f:
        f.write("This is a test file for integrity checking.")
    print(f"Adding {test_file} to integrity monitoring...")
    file_hash = fic.add_file(test_file)
    print(f"File hash: {file_hash}")
    result1 = fic.check_file(test_file)
    print(f"First check: {result1['status']} - {result1['message']}")
    with open(test_file, 'a') as f:
        f.write(" Modified content!")
    result2 = fic.check_file(test_file)
    print(f"After modification: {result2['status']} - {result2['message']}")
    if result2['status'] == 'modified':
        print(f"Original hash: {result2['original_hash']}")
        print(f"Current hash: {result2['current_hash']}")

    print("\n3. OBFUSCATED LICENSE KEY GENERATOR DEMONSTRATION")
    print("-" * 50)
    lkg = LicenseKeyGenerator()
    key1 = lkg.generate_license_key("user123", "PROD001")
    key2 = lkg.generate_license_key("user456", "PROD002")
    print(f"License key for user123/PROD001: {key1}")
    print(f"License key for user456/PROD002: {key2}")
    valid1 = lkg.validate_license_key(key1, "user123", "PROD001")
    valid2 = lkg.validate_license_key("INVALID-KEY", "user123", "PROD001")
    print(f"Key1 validation: {'Valid' if valid1 else 'Invalid'}")
    print(f"Invalid key validation: {'Valid' if valid2 else 'Invalid (expected)'}")

    print("\n4. CLEANUP")
    print("-" * 50)
    files_to_clean = [test_file, "users.json", "file_hashes.json"]
    for file_path in files_to_clean:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Cleaned up: {file_path}")
    print("\nDemonstration completed!")

# --- From test_project.py ---

def test_hash_functions():
    """Test hash function implementations"""
    print("Testing Hash Functions...")
    try:
        hasher = HashGenerator()
        test_hash = hasher.hash_string("test", "sha256")
        expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        assert test_hash == expected, f"Expected {expected}, got {test_hash}"
        hashes = hasher.hash_multiple_algorithms("test")
        assert len(hashes) == 6, f"Expected 6 algorithms, got {len(hashes)}"
        assert hasher.compare_hashes("same", "same"), "Identical strings should have same hash"
        assert not hasher.compare_hashes("different", "strings"), "Different strings should have different hashes"
        print("✓ Hash Functions: All tests passed")
        return True
    except Exception as e:
        print(f"✗ Hash Functions: Test failed - {e}")
        traceback.print_exc()
        return False

def test_obfuscation():
    """Test obfuscation implementations"""
    print("Testing Obfuscation Techniques...")
    try:
        obfuscator = CodeObfuscator()
        original_code = "print('Hello, World!')"
        obfuscated = obfuscator.base64_obfuscation(original_code)
        assert "base64" in obfuscated, "Base64 obfuscation should contain 'base64'"
        assert "exec" in obfuscated, "Base64 obfuscation should contain 'exec'"
        obfuscated_str = obfuscator.string_obfuscation("test")
        result = eval(obfuscated_str)
        assert result == "test", f"String obfuscation failed: expected 'test', got '{result}'"
        obf_func = ObfuscatedFunction()
        result = obf_func.hidden_calculation(5, 6)
        assert result == 40, f"Hidden calculation failed: expected 40, got {result}"
        print("✓ Obfuscation: All tests passed")
        return True
    except Exception as e:
        print(f"✗ Obfuscation: Test failed - {e}")
        traceback.print_exc()
        return False

def test_practical_examples():
    """Test practical examples"""
    print("Testing Practical Examples...")
    try:
        pm = PasswordManager()
        assert pm.register_user("testuser", "testpass"), "User registration should succeed"
        assert pm.authenticate_user("testuser", "testpass"), "Authentication should succeed"
        assert not pm.authenticate_user("testuser", "wrongpass"), "Wrong password should fail"
        lkg = LicenseKeyGenerator()
        key = lkg.generate_license_key("user1", "prod1")
        assert key.startswith("LIC-"), "License key should start with 'LIC-'"
        assert key.endswith("-2024"), "License key should end with '-2024'"
        assert lkg.validate_license_key(key, "user1", "prod1"), "Generated key should be valid"
        print("✓ Practical Examples: All tests passed")
        return True
    except Exception as e:
        print(f"✗ Practical Examples: Test failed - {e}")
        traceback.print_exc()
        return False

def test_code_execution():
    """Test that obfuscated code actually executes"""
    print("Testing Obfuscated Code Execution...")
    try:
        obfuscator = CodeObfuscator()
        test_code = '''
result = 2 + 3
test_var = "success"
'''
        obfuscated = obfuscator.base64_obfuscation(test_code)
        namespace = {}
        exec(obfuscated, namespace)
        assert namespace.get('result') == 5, "Obfuscated code should execute correctly"
        assert namespace.get('test_var') == "success", "Variables should be set correctly"
        print("✓ Code Execution: All tests passed")
        return True
    except Exception as e:
        print(f"✗ Code Execution: Test failed - {e}")
        traceback.print_exc()
        return False

def run_all_tests():
    """Run all tests and report results"""
    print("=" * 60)
    print("RUNNING COMPREHENSIVE TESTS")
    print("=" * 60)
    tests = [
        test_hash_functions,
        test_obfuscation,
        test_practical_examples,
        test_code_execution
    ]
    passed = 0
    total = len(tests)
    for test in tests:
        if test():
            passed += 1
        print()
    print("=" * 60)
    print(f"TEST RESULTS: {passed}/{total} tests passed")
    print("=" * 60)
    if passed == total:
        print("🎉 All tests passed! The project is working correctly.")
        return True
    else:
        print("❌ Some tests failed. Please check the implementation.")
        return False

# --- From main.py ---

def interactive_hash_demo():
    """Interactive demonstration of hash functions"""
    print("\n" + "=" * 60)
    print("INTERACTIVE HASH FUNCTION DEMO")
    print("=" * 60)
    
    hasher = HashGenerator()
    
    while True:
        print("\nChoose an option:")
        print("1. Hash a string")
        print("2. Hash a file")
        print("3. Compare two strings")
        print("4. Generate multiple hashes")
        print("5. Return to main menu")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            text = input("Enter text to hash: ")
            algorithm = input("Enter algorithm (md5, sha1, sha256, sha512) [default: sha256]: ").strip() or 'sha256'
            try:
                hash_value = hasher.hash_string(text, algorithm)
                print(f"\n{algorithm.upper()} hash: {hash_value}")
            except ValueError as e:
                print(f"Error: {e}")
        
        elif choice == '2':
            file_path = input("Enter file path: ").strip()
            algorithm = input("Enter algorithm (md5, sha1, sha256, sha512) [default: sha256]: ").strip() or 'sha256'
            try:
                hash_value = hasher.hash_file(file_path, algorithm)
                print(f"\n{algorithm.upper()} hash of file: {hash_value}")
            except (FileNotFoundError, ValueError) as e:
                print(f"Error: {e}")
        
        elif choice == '3':
            text1 = input("Enter first string: ")
            text2 = input("Enter second string: ")
            algorithm = input("Enter algorithm [default: sha256]: ").strip() or 'sha256'
            try:
                are_same = hasher.compare_hashes(text1, text2, algorithm)
                print(f"\nStrings are {'identical' if are_same else 'different'}")
                print(f"Hash 1: {hasher.hash_string(text1, algorithm)}")
                print(f"Hash 2: {hasher.hash_string(text2, algorithm)}")
            except ValueError as e:
                print(f"Error: {e}")
        
        elif choice == '4':
            text = input("Enter text to hash: ")
            hashes = hasher.hash_multiple_algorithms(text)
            print(f"\nAll hashes for '{text}':")
            for algo, hash_val in hashes.items():
                print(f"{algo.upper()}: {hash_val}")
        
        elif choice == '5':
            break
        
        else:
            print("Invalid choice. Please try again.")

def interactive_obfuscation_demo():
    """Interactive demonstration of obfuscation techniques"""
    print("\n" + "=" * 60)
    print("INTERACTIVE OBFUSCATION DEMO")
    print("=" * 60)
    
    obfuscator = CodeObfuscator()
    
    while True:
        print("\nChoose an option:")
        print("1. Obfuscate custom code")
        print("2. Test obfuscated function")
        print("3. String obfuscation")
        print("4. Multilayer obfuscation")
        print("5. Return to main menu")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            print("Enter your Python code (end with 'END' on a new line):")
            code_lines = []
            while True:
                line = input()
                if line.strip() == 'END':
                    break
                code_lines.append(line)
            
            code = '\n'.join(code_lines)
            
            print("\nObfuscation methods:")
            print("1. Base64")
            print("2. Zlib compression")
            print("3. Marshal")
            method = input("Choose method (1-3): ").strip()
            
            try:
                if method == '1':
                    obfuscated = obfuscator.base64_obfuscation(code)
                elif method == '2':
                    obfuscated = obfuscator.zlib_compression_obfuscation(code)
                elif method == '3':
                    obfuscated = obfuscator.marshal_obfuscation(code)
                else:
                    print("Invalid method")
                    continue
                
                print("\nObfuscated code:")
                print("-" * 40)
                print(obfuscated)
                
                execute = input("\nExecute obfuscated code? (y/n): ").strip().lower()
                if execute == 'y':
                    try:
                        exec(obfuscated)
                    except Exception as e:
                        print(f"Execution error: {e}")
                        
            except Exception as e:
                print(f"Obfuscation error: {e}")
        
        elif choice == '2':
            obf_func = ObfuscatedFunction()
            
            print("Testing obfuscated function...")
            x = int(input("Enter first number: "))
            y = int(input("Enter second number: "))
            result = obf_func.hidden_calculation(x, y)
            print(f"Hidden calculation result: {result}")
            
            password = input("Enter password to reveal secret: ")
            secret = obf_func.reveal_secret(password)
            print(f"Result: {secret}")
        
        elif choice == '3':
            text = input("Enter string to obfuscate: ")
            obfuscated_str = obfuscator.string_obfuscation(text)
            print(f"\nObfuscated string: {obfuscated_str}")
            print(f"Deobfuscated result: {eval(obfuscated_str)}")
        
        elif choice == '4':
            print("Enter your Python code (end with 'END' on a new line):")
            code_lines = []
            while True:
                line = input()
                if line.strip() == 'END':
                    break
                code_lines.append(line)
            
            code = '\n'.join(code_lines)
            
            try:
                obfuscated = obfuscator.multilayer_obfuscation(code)
                print("\nMultilayer obfuscated code:")
                print("-" * 40)
                print(obfuscated)
            except Exception as e:
                print(f"Obfuscation error: {e}")
        
        elif choice == '5':
            break
        
        else:
            print("Invalid choice. Please try again.")

def create_sample_files():
    """Create sample files for demonstration"""
    sample_content = """This is a sample file for hash function testing.
It contains multiple lines of text.
Hash functions can process files of any size.
This demonstrates file integrity checking."""
    
    with open("sample.txt", "w") as f:
        f.write(sample_content)
    
    sample_script = '''# Sample Python script
def greet(name):
    return f"Hello, {name}!"

if __name__ == "__main__":
    print(greet("World"))
'''
    
    with open("sample_script.py", "w") as f:
        f.write(sample_script)
    
    print("Sample files created: sample.txt, sample_script.py")

def main():
    """Main program loop"""
    print("=" * 80)
    print("HASH FUNCTIONS AND OBFUSCATION DEMONSTRATION")
    print("=" * 80)
    print("This program demonstrates:")
    print("- Various hash function implementations (MD5, SHA-1, SHA-256, etc.)")
    print("- Code obfuscation techniques")
    print("- Practical applications of both concepts")
    
    while True:
        print("\n" + "=" * 50)
        print("MAIN MENU")
        print("=" * 50)
        print("1. Run hash function demonstrations")
        print("2. Run obfuscation demonstrations")
        print("3. Interactive hash function demo")
        print("4. Interactive obfuscation demo")
        print("5. Create sample files")
        print("6. Run all tests")
        print("7. Exit")
        
        choice = input("\nEnter your choice (1-7): ").strip()
        
        if choice == '1':
            demonstrate_hash_functions()
        
        elif choice == '2':
            demonstrate_obfuscation()
        
        elif choice == '3':
            interactive_hash_demo()
        
        elif choice == '4':
            interactive_obfuscation_demo()
        
        elif choice == '5':
            create_sample_files()
        
        elif choice == '6':
            run_all_tests()

        elif choice == '7':
            print("\nGoodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
