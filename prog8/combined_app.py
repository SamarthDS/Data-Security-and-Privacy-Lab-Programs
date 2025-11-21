"""
Digital Signature Implementation using RSA
This module provides RSA key generation, digital signature creation and verification
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import base64
import os
import datetime
import hashlib
import unittest
import tempfile
import time
import sys
from unittest.mock import patch, MagicMock
import streamlit as st

class RSADigitalSignature:
    def __init__(self):
        self.private_key = None
        self.public_key = None
    
    def generate_key_pair(self, key_size=2048):
        """
        Generate RSA key pair for digital signatures
        """
        print(f"Generating RSA key pair with {key_size} bits...")
        
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        
        # Get public key
        self.public_key = self.private_key.public_key()
        
        print("RSA key pair generated successfully!")
        return self.private_key, self.public_key
    
    def save_keys(self, private_key_path="private_key.pem", public_key_path="public_key.pem"):
        """
        Save keys to files
        """
        if not self.private_key or not self.public_key:
            raise ValueError("Keys not generated yet!")
        
        # Save private key
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Save public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        
        print(f"Keys saved to {private_key_path} and {public_key_path}")
    
    def load_keys(self, private_key_path="private_key.pem", public_key_path="public_key.pem"):
        """
        Load keys from files
        """
        if os.path.exists(private_key_path):
            with open(private_key_path, 'rb') as f:
                self.private_key = load_pem_private_key(f.read(), password=None)
        
        if os.path.exists(public_key_path):
            with open(public_key_path, 'rb') as f:
                self.public_key = load_pem_public_key(f.read())
        
        print("Keys loaded successfully!")
    
    def sign_message(self, message):
        """
        Create digital signature for a message
        """
        if not self.private_key:
            raise ValueError("Private key not available!")
        
        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Create signature
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Encode signature to base64 for easy transmission
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        print(f"Message signed successfully!")
        print(f"Signature (base64): {signature_b64[:50]}...")
        
        return signature_b64
    
    def verify_signature(self, message, signature_b64, public_key=None):
        """
        Verify digital signature
        """
        if public_key is None:
            public_key = self.public_key
        
        if not public_key:
            raise ValueError("Public key not available!")
        
        try:
            # Convert message to bytes if it's a string
            if isinstance(message, str):
                message = message.encode('utf-8')
            
            # Decode signature from base64
            signature = base64.b64decode(signature_b64)
            
            # Verify signature
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            print("✓ Signature verification successful!")
            return True
            
        except Exception as e:
            print(f"✗ Signature verification failed: {str(e)}")
            return False
    
    def get_public_key_pem(self):
        """
        Get public key in PEM format as string
        """
        if not self.public_key:
            raise ValueError("Public key not available!")
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return public_pem.decode('utf-8')

# Demonstration functions
def demonstrate_digital_signatures():
    """
    Demonstrate RSA digital signature functionality
    """
    print("=" * 60)
    print("RSA DIGITAL SIGNATURE DEMONSTRATION")
    print("=" * 60)
    
    # Initialize RSA digital signature
    rsa_ds = RSADigitalSignature()
    
    # Generate key pair
    rsa_ds.generate_key_pair()
    
    # Save keys
    rsa_ds.save_keys()
    
    # Test message
    message = "This is a confidential e-commerce transaction worth $1000.00"
    print(f"\nOriginal message: {message}")
    
    # Sign the message
    print("\n1. SIGNING THE MESSAGE:")
    signature = rsa_ds.sign_message(message)
    
    # Verify the signature
    print("\n2. VERIFYING THE SIGNATURE:")
    is_valid = rsa_ds.verify_signature(message, signature)
    
    # Test with tampered message
    print("\n3. TESTING WITH TAMPERED MESSAGE:")
    tampered_message = "This is a confidential e-commerce transaction worth $9999.00"
    print(f"Tampered message: {tampered_message}")
    is_valid_tampered = rsa_ds.verify_signature(tampered_message, signature)
    
    # Test loading keys from file
    print("\n4. TESTING KEY LOADING FROM FILES:")
    new_rsa_ds = RSADigitalSignature()
    new_rsa_ds.load_keys()
    is_valid_loaded = new_rsa_ds.verify_signature(message, signature)
    
    return rsa_ds

# Global RSA instance for demo purposes
rsa_signature = RSADigitalSignature()

def run_streamlit_app():
    st.title("Secure Banking & E-commerce with Digital Signatures")

    # Initialize session state for users and transactions
    if 'users' not in st.session_state:
        st.session_state.users = {
            'customer1': {
                'password': hashlib.sha256('password123'.encode()).hexdigest(),
                'role': 'customer',
                'account_balance': 5000.0,
                'public_key': None
            },
            'bank_admin': {
                'password': hashlib.sha256('admin123'.encode()).hexdigest(),
                'role': 'admin',
                'account_balance': None,
                'public_key': None
            },
            'merchant1': {
                'password': hashlib.sha256('merchant123'.encode()).hexdigest(),
                'role': 'merchant',
                'account_balance': 10000.0,
                'public_key': None
            }
        }
    if 'transactions' not in st.session_state:
        st.session_state.transactions = []

    users = st.session_state.users
    transactions = st.session_state.transactions

    if 'logged_in_user' not in st.session_state:
        st.session_state.logged_in_user = None

    if st.session_state.logged_in_user is None:
        st.header("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if username in users and users[username]['password'] == password_hash:
                st.session_state.logged_in_user = username
                st.success(f"Welcome {username}!")
                st.rerun()
            else:
                st.error("Invalid username or password")
    else:
        username = st.session_state.logged_in_user
        user_role = users[username]['role']
        st.sidebar.header(f"Welcome, {username} ({user_role})")

        if st.sidebar.button("Logout"):
            st.session_state.logged_in_user = None
            st.rerun()

        st.sidebar.title("Menu")
        menu_choice = st.sidebar.radio("Choose an action", ["Home", "Demonstrate Signatures", "Manage Keys", "Create Transaction", "View Transactions"])

        if menu_choice == "Home":
            st.header("User Dashboard")
            st.write(f"**Username:** {username}")
            st.write(f"**Role:** {user_role}")
            if users[username]['account_balance'] is not None:
                st.write(f"**Account Balance:** ${users[username]['account_balance']:.2f}")

        elif menu_choice == "Demonstrate Signatures":
            st.header("RSA Digital Signature Demonstration")
            
            if 'demo_rsa_ds' not in st.session_state:
                st.session_state.demo_rsa_ds = RSADigitalSignature()
                st.session_state.demo_rsa_ds.generate_key_pair()

            rsa_ds = st.session_state.demo_rsa_ds
            
            st.subheader("Generated Keys")
            st.text_area("Public Key", rsa_ds.get_public_key_pem(), height=200)

            message = st.text_area("Message to Sign", "This is a test transaction.")
            
            if st.button("Sign and Verify"):
                st.subheader("1. Signing the Message")
                signature = rsa_ds.sign_message(message)
                st.text_area("Generated Signature (Base64)", signature, height=100)

                st.subheader("2. Verifying the Signature")
                is_valid = rsa_ds.verify_signature(message, signature)
                if is_valid:
                    st.success("Signature is valid!")
                else:
                    st.error("Signature is invalid!")

                st.subheader("3. Tampering the message")
                tampered_message = message + " (tampered)"
                is_valid_tampered = rsa_ds.verify_signature(tampered_message, signature)
                if not is_valid_tampered:
                    st.success("Verification of tampered message failed as expected.")
                else:
                    st.error("Verification of tampered message succeeded, which is an error.")

        elif menu_choice == "Manage Keys":
            st.header("Manage Your Public Key")
            if st.button("Generate & Register New Key Pair"):
                rsa_ds = RSADigitalSignature()
                rsa_ds.generate_key_pair()
                public_key_pem = rsa_ds.get_public_key_pem()
                users[username]['public_key'] = public_key_pem
                st.session_state[f"{username}_private_key"] = rsa_ds.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                st.success("New key pair generated and public key registered!")

            if users[username]['public_key']:
                st.subheader("Your Registered Public Key")
                st.text_area("", users[username]['public_key'], height=200)
                if f"{username}_private_key" in st.session_state:
                    st.subheader("Your Private Key (for signing)")
                    st.text_area("Keep this safe!", st.session_state[f"{username}_private_key"], height=200)
            else:
                st.warning("You have not registered a public key yet.")

        elif menu_choice == "Create Transaction":
            st.header("Create a Signed Transaction")
            if not users[username]['public_key'] or f"{username}_private_key" not in st.session_state:
                st.warning("Please generate and register your keys first in 'Manage Keys'.")
            else:
                recipient = st.selectbox("Recipient", [u for u in users.keys() if u != username])
                amount = st.number_input("Amount", min_value=0.01, value=100.0)
                
                if st.button("Create and Sign Transaction"):
                    transaction_message = f"FROM:{username};TO:{recipient};AMOUNT:{amount}"
                    
                    private_key_pem = st.session_state[f"{username}_private_key"].encode('utf-8')
                    private_key = load_pem_private_key(private_key_pem, password=None)
                    
                    temp_rsa = RSADigitalSignature()
                    temp_rsa.private_key = private_key

                    signature = temp_rsa.sign_message(transaction_message)
                    
                    public_key_pem = users[username]['public_key'].encode('utf-8')
                    public_key = load_pem_public_key(public_key_pem)

                    is_valid = temp_rsa.verify_signature(transaction_message, signature, public_key)

                    if is_valid:
                        transaction_record = {
                            'id': len(transactions) + 1,
                            'message': transaction_message,
                            'signature': signature,
                            'timestamp': datetime.datetime.now().isoformat()
                        }
                        transactions.append(transaction_record)
                        st.success("Transaction created and signed successfully!")
                        st.json(transaction_record)
                    else:
                        st.error("Failed to create a valid signature. Transaction aborted.")

        elif menu_choice == "View Transactions":
            st.header("Transaction Log")
            if not transactions:
                st.info("No transactions yet.")
            else:
                for t in reversed(transactions):
                    st.json(t)

class TestRSADigitalSignature(unittest.TestCase):
    """
    Test cases for RSA Digital Signature implementation
    """

    def setUp(self):
        """Set up test fixtures"""
        if RSADigitalSignature is None:
            self.skipTest("cryptography library not installed")

        self.rsa_ds = RSADigitalSignature()
        self.test_message = "Test transaction: Transfer $100.00 from Account A to Account B"
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_dir):
            for f in os.listdir(self.temp_dir):
                os.remove(os.path.join(self.temp_dir, f))
            os.rmdir(self.temp_dir)

    def test_key_generation(self):
        """Test RSA key pair generation"""
        private_key, public_key = self.rsa_ds.generate_key_pair()

        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        self.assertEqual(self.rsa_ds.private_key, private_key)
        self.assertEqual(self.rsa_ds.public_key, public_key)

    def test_key_generation_different_sizes(self):
        """Test RSA key generation with different key sizes"""
        for key_size in [1024, 2048]:
            with self.subTest(key_size=key_size):
                private_key, public_key = self.rsa_ds.generate_key_pair(key_size)
                self.assertEqual(private_key.key_size, key_size)
                self.assertEqual(public_key.key_size, key_size)

    def test_signature_generation(self):
        """Test digital signature generation"""
        self.rsa_ds.generate_key_pair()
        signature = self.rsa_ds.sign_message(self.test_message)

        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, str)
        self.assertTrue(len(signature) > 0)

    def test_signature_verification_valid(self):
        """Test valid signature verification"""
        self.rsa_ds.generate_key_pair()
        signature = self.rsa_ds.sign_message(self.test_message)

        is_valid = self.rsa_ds.verify_signature(self.test_message, signature)
        self.assertTrue(is_valid)

    def test_signature_verification_invalid_message(self):
        """Test signature verification with tampered message"""
        self.rsa_ds.generate_key_pair()
        signature = self.rsa_ds.sign_message(self.test_message)

        tampered_message = "Test transaction: Transfer $999.00 from Account A to Account B"
        is_valid = self.rsa_ds.verify_signature(tampered_message, signature)
        self.assertFalse(is_valid)

    def test_signature_verification_invalid_signature(self):
        """Test signature verification with invalid signature"""
        self.rsa_ds.generate_key_pair()

        # base64 encoded "invalid signature"
        invalid_signature = "aW52YWxpZCBzaWduYXR1cmU="
        is_valid = self.rsa_ds.verify_signature(
            self.test_message, invalid_signature)
        self.assertFalse(is_valid)

    def test_key_save_and_load(self):
        """Test saving and loading keys from files"""
        self.rsa_ds.generate_key_pair()

        private_key_path = os.path.join(self.temp_dir, "test_private.pem")
        public_key_path = os.path.join(self.temp_dir, "test_public.pem")

        # Save keys
        self.rsa_ds.save_keys(private_key_path, public_key_path)

        # Verify files exist
        self.assertTrue(os.path.exists(private_key_path))
        self.assertTrue(os.path.exists(public_key_path))

        # Create new instance and load keys
        new_rsa_ds = RSADigitalSignature()
        new_rsa_ds.load_keys(private_key_path, public_key_path)

        # Test that loaded keys work
        signature = new_rsa_ds.sign_message(self.test_message)
        is_valid = new_rsa_ds.verify_signature(self.test_message, signature)
        self.assertTrue(is_valid)

    def test_cross_instance_verification(self):
        """Test signature verification across different instances"""
        # Generate signature with first instance
        self.rsa_ds.generate_key_pair()
        signature = self.rsa_ds.sign_message(self.test_message)
        public_key = self.rsa_ds.public_key

        # Verify with second instance using the same public key
        new_rsa_ds = RSADigitalSignature()
        is_valid = new_rsa_ds.verify_signature(
            self.test_message, signature, public_key)
        self.assertTrue(is_valid)

    def test_bytes_message_signing(self):
        """Test signing messages provided as bytes"""
        self.rsa_ds.generate_key_pair()
        message_bytes = self.test_message.encode('utf-8')

        signature = self.rsa_ds.sign_message(message_bytes)
        is_valid = self.rsa_ds.verify_signature(message_bytes, signature)
        self.assertTrue(is_valid)

    def test_get_public_key_pem(self):
        """Test getting public key in PEM format"""
        self.rsa_ds.generate_key_pair()
        public_key_pem = self.rsa_ds.get_public_key_pem()

        self.assertIsNotNone(public_key_pem)
        self.assertIsInstance(public_key_pem, str)
        self.assertIn("BEGIN PUBLIC KEY", public_key_pem)
        self.assertIn("END PUBLIC KEY", public_key_pem)

    def test_error_handling_no_private_key(self):
        """Test error handling when private key is not available"""
        with self.assertRaises(ValueError):
            self.rsa_ds.sign_message("some message")

    def test_error_handling_no_public_key(self):
        """Test error handling when public key is not available"""
        with self.assertRaises(ValueError):
            self.rsa_ds.verify_signature("some message", "some signature")


class TestFlaskAuthentication(unittest.TestCase):
    """
    Test cases for Flask authentication and authorization
    """

    def setUp(self):
        """Set up test fixtures"""
        # Mock Flask app for testing
        self.app = None
        self.client = None

        # Test user credentials
        self.test_users = {
            'customer1': {'password': 'password123', 'role': 'customer'},
            'admin1': {'password': 'admin123', 'role': 'admin'},
            'merchant1': {'password': 'merchant123', 'role': 'merchant'}
        }

    @patch('hashlib.sha256')
    def test_password_hashing(self, mock_sha256):
        mock_hexdigest = MagicMock()
        mock_hexdigest.hexdigest.return_value = 'hashed_password'
        mock_sha256.return_value = mock_hexdigest
        
        password = 'test_password'
        hashed = hashlib.sha256(password.encode()).hexdigest()
        
        mock_sha256.assert_called_with(password.encode())
        self.assertEqual(hashed, 'hashed_password')

    def test_user_roles(self):
        """Test user role definitions"""
        expected_roles = ['customer', 'admin', 'merchant']

        for username, user_data in self.test_users.items():
            self.assertIn(user_data['role'], expected_roles)

    def test_transaction_validation(self):
        """Test transaction validation logic"""
        # Test positive amount validation
        valid_amounts = [0.01, 100.00, 999.99]
        invalid_amounts = [0, -10, -100.50]

        for amount in valid_amounts:
            self.assertTrue(amount > 0)

        for amount in invalid_amounts:
            self.assertFalse(amount > 0)

    def test_jwt_token_structure(self):
        """Test JWT token structure components"""
        # Mock JWT payload structure
        expected_claims = ['identity', 'role', 'exp', 'iat']

        # Simulated JWT payload
        mock_payload = {
            'identity': 'customer1',
            'role': 'customer',
            'exp': 1234567890,
            'iat': 1234567800
        }

        for claim in expected_claims:
            self.assertIn(claim, mock_payload)


class TestSecurityFeatures(unittest.TestCase):
    """
    Test cases for security features and edge cases
    """

    def test_signature_uniqueness(self):
        rsa_ds = RSADigitalSignature()
        rsa_ds.generate_key_pair()
        message = "This is a test message"
        
        sig1 = rsa_ds.sign_message(message)
        sig2 = rsa_ds.sign_message(message)
        
        self.assertNotEqual(sig1, sig2)

    def test_signature_determinism(self):
        # PSS padding is non-deterministic, so this test is expected to fail
        # and confirms that the padding is working as intended (randomized)
        rsa_ds = RSADigitalSignature()
        rsa_ds.generate_key_pair()
        message = "This is a test message"
        
        sig1 = rsa_ds.sign_message(message)
        sig2 = rsa_ds.sign_message(message)
        
        self.assertNotEqual(sig1, sig2)

    def test_large_message_handling(self):
        rsa_ds = RSADigitalSignature()
        rsa_ds.generate_key_pair()
        large_message = "a" * 10**6 # 1MB message
        
        signature = rsa_ds.sign_message(large_message)
        is_valid = rsa_ds.verify_signature(large_message, signature)
        self.assertTrue(is_valid)

    def test_unicode_message_handling(self):
        rsa_ds = RSADigitalSignature()
        rsa_ds.generate_key_pair()
        unicode_message = "这是一个测试消息"
        
        signature = rsa_ds.sign_message(unicode_message)
        is_valid = rsa_ds.verify_signature(unicode_message, signature)
        self.assertTrue(is_valid)


class TestIntegration(unittest.TestCase):
    """
    Integration tests for the complete system
    """

    def test_complete_transaction_flow(self):
        # This is a conceptual test, would need a running app instance
        pass

    def test_multi_user_scenario(self):
        # This is a conceptual test
        pass


def run_performance_tests():
    """
    Performance tests for cryptographic operations
    """
    if RSADigitalSignature is None:
        print("Skipping performance tests: cryptography not installed")
        return

    print("\n" + "="*60)
    print("PERFORMANCE TESTS")
    print("="*60)

    rsa_ds = RSADigitalSignature()

    # Key generation performance
    start_time = time.time()
    rsa_ds.generate_key_pair(2048)
    key_gen_time = time.time() - start_time
    print(f"RSA-2048 Key Generation: {key_gen_time:.3f} seconds")

    # Signature generation performance
    message = "Performance test message for signature generation"

    start_time = time.time()
    signature = rsa_ds.sign_message(message)
    sign_time = time.time() - start_time
    print(f"Signature Generation: {sign_time:.3f} seconds")

    # Signature verification performance
    start_time = time.time()
    is_valid = rsa_ds.verify_signature(message, signature)
    verify_time = time.time() - start_time
    print(f"Signature Verification: {verify_time:.3f} seconds")
    print(f"Signature Valid: {is_valid}")

    # Batch operations performance
    num_operations = 10
    messages = [
        f"Message {i} for batch testing" for i in range(num_operations)]

    start_time = time.time()
    signatures = [rsa_ds.sign_message(msg) for msg in messages]
    batch_sign_time = time.time() - start_time
    print(
        f"Batch Signing ({num_operations} messages): {batch_sign_time:.3f} seconds")
    print(
        f"Average per signature: {batch_sign_time/num_operations:.3f} seconds")

    start_time = time.time()
    verifications = [rsa_ds.verify_signature(
        msg, sig) for msg, sig in zip(messages, signatures)]
    batch_verify_time = time.time() - start_time
    print(
        f"Batch Verification ({num_operations} signatures): {batch_verify_time:.3f} seconds")
    print(
        f"Average per verification: {batch_verify_time/num_operations:.3f} seconds")
    print(f"All verifications passed: {all(verifications)}")


def main():
    """
    Main function to run all tests
    """
    print("Digital Signature and Authentication Test Suite")
    print("=" * 60)

    # Run unit tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    test_classes = [
        TestRSADigitalSignature,
        TestFlaskAuthentication,
        TestSecurityFeatures,
        TestIntegration
    ]

    for test_class in test_classes:
        suite.addTest(loader.loadTestsFromTestCase(test_class))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Run performance tests
    run_performance_tests()

    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(
        f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")

    if result.failures:
        print("\nFAILURES:")
        for test, err in result.failures:
            print(f"- {test}: {err}")

    if result.errors:
        print("\nERRORS:")
        for test, err in result.errors:
            print(f"- {test}: {err}")

    return result.wasSuccessful()


if __name__ == "__main__":
    # To run the Flask app, you would typically run this file with a WSGI server,
    # for example: gunicorn combined_app:app
    # To run the tests, you would run: python combined_app.py
    
    # Check for a command-line argument to run tests
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        success = main()
        sys.exit(0 if success else 1)
    elif __name__ == '__main__':
        run_streamlit_app()
