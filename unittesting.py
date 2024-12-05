import unittest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import rsa
import bcrypt
import os


class TestChatAppSecurity(unittest.TestCase):
    def setUp(self):
        #intitalizing parameters for the test
        # AES key and data for testing
        self.aes_key = os.urandom(16)
        self.test_message = "This is a test message."
        self.iv = os.urandom(16)

        # RSA key pair for testing
        self.public_key, self.private_key = rsa.newkeys(2048)

        # Password for testing
        self.test_password = "secure_password123"

    def test_aes_encryption_decryption(self):

        # Encrypt the message
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        encrypted_message = self.iv + cipher.encrypt(pad(self.test_message.encode(), AES.block_size))

        # Decrypt the message
        iv = encrypted_message[:16]
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(encrypted_message[16:]), AES.block_size).decode()

        # Assert the decrypted message matches the original
        self.assertEqual(decrypted_message, self.test_message, "AES decryption did not return the original message.")

    def test_password_hashing(self):

        # Hash the password
        hashed_password = bcrypt.hashpw(self.test_password.encode(), bcrypt.gensalt())

        # Verify the password against the hash
        self.assertTrue(bcrypt.checkpw(self.test_password.encode(), hashed_password), "Password verification failed.")

    def test_rsa_key_pair(self):

        # Encrypt a message with the public key
        encrypted_message = rsa.encrypt(self.test_message.encode(), self.public_key)

        # Decrypt the message with the private key
        decrypted_message = rsa.decrypt(encrypted_message, self.private_key).decode()

        # Assert the decrypted message matches the original
        self.assertEqual(decrypted_message, self.test_message, "RSA decryption did not return the original message.")


if __name__ == "__main__":
    unittest.main()
