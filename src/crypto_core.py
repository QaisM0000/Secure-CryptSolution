"""
Core Cryptographic Operations Module

This module provides fundamental cryptographic operations including:
- Symmetric encryption (AES-256-GCM) for confidentiality
- Asymmetric encryption (RSA-2048) for key exchange
- Digital signatures (RSA-PSS with SHA-256) for non-repudiation
- Cryptographic hashing (SHA-256) for integrity verification

All operations use the 'cryptography' library which implements
NIST-approved algorithms with secure defaults.
"""

import os
import hashlib
import base64
from datetime import datetime
from typing import Tuple, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class SymmetricEncryption:
    """
    AES-256-GCM Symmetric Encryption

    Provides authenticated encryption with associated data (AEAD).
    GCM mode ensures both confidentiality and integrity of the encrypted data.
    """

    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits, recommended for GCM

    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically secure random key."""
        return os.urandom(SymmetricEncryption.KEY_SIZE)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.

        Args:
            plaintext: Data to encrypt
            key: 256-bit encryption key
            associated_data: Optional additional authenticated data (AAD)

        Returns:
            Tuple of (nonce, ciphertext with authentication tag)
        """
        if len(key) != SymmetricEncryption.KEY_SIZE:
            raise ValueError(f"Key must be {SymmetricEncryption.KEY_SIZE} bytes")

        nonce = os.urandom(SymmetricEncryption.NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

        return nonce, ciphertext

    @staticmethod
    def decrypt(nonce: bytes, ciphertext: bytes, key: bytes,
                associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using AES-256-GCM.

        Args:
            nonce: The nonce used during encryption
            ciphertext: Encrypted data with authentication tag
            key: 256-bit decryption key
            associated_data: Optional AAD used during encryption

        Returns:
            Decrypted plaintext

        Raises:
            InvalidTag: If authentication fails (data tampered)
        """
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)


class AsymmetricEncryption:
    """
    RSA-2048 Asymmetric Encryption and Digital Signatures

    Uses OAEP padding for encryption and PSS padding for signatures,
    both of which are the recommended secure padding schemes.
    """

    KEY_SIZE = 2048
    PUBLIC_EXPONENT = 65537

    @staticmethod
    def generate_key_pair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate an RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=AsymmetricEncryption.PUBLIC_EXPONENT,
            key_size=AsymmetricEncryption.KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def encrypt_key(symmetric_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        """
        Encrypt a symmetric key using RSA-OAEP.

        This is used in hybrid encryption where the symmetric key
        is encrypted with RSA for secure key exchange.
        """
        return public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt_key(encrypted_key: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """Decrypt a symmetric key using RSA-OAEP."""
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def sign(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Create a digital signature using RSA-PSS.

        RSA-PSS (Probabilistic Signature Scheme) is the recommended
        signature padding scheme, providing provable security.
        """
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    @staticmethod
    def verify(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
        """
        Verify a digital signature.

        Returns True if valid, False otherwise.
        """
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


class HashOperations:
    """
    Cryptographic Hashing Operations

    Provides SHA-256 hashing for data integrity verification.
    """

    @staticmethod
    def sha256(data: bytes) -> bytes:
        """Compute SHA-256 hash of data."""
        return hashlib.sha256(data).digest()

    @staticmethod
    def sha256_hex(data: bytes) -> str:
        """Compute SHA-256 hash and return as hex string."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def verify_hash(data: bytes, expected_hash: bytes) -> bool:
        """Verify data integrity by comparing hashes."""
        computed_hash = HashOperations.sha256(data)
        # Use constant-time comparison to prevent timing attacks
        return hashlib.compare_digest(computed_hash, expected_hash)


class KeySerializer:
    """
    Secure Key Serialization and Deserialization

    Handles conversion of cryptographic keys to/from PEM format
    with optional password protection.
    """

    @staticmethod
    def serialize_private_key(private_key: rsa.RSAPrivateKey,
                              password: Optional[bytes] = None) -> bytes:
        """
        Serialize private key to PEM format.

        If password is provided, the key is encrypted using
        PBKDF2-HMAC-SHA256 with AES-256-CBC.
        """
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        else:
            encryption = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

    @staticmethod
    def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
        """Serialize public key to PEM format."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_private_key(pem_data: bytes,
                                password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
        """Load private key from PEM format."""
        return serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend()
        )

    @staticmethod
    def deserialize_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
        """Load public key from PEM format."""
        return serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )


class HybridEncryption:
    """
    Hybrid Encryption System

    Combines RSA and AES for efficient encryption of large data:
    1. Generate random AES key
    2. Encrypt data with AES-GCM
    3. Encrypt AES key with recipient's RSA public key

    This provides the security of asymmetric encryption with
    the efficiency of symmetric encryption.
    """

    @staticmethod
    def encrypt(plaintext: bytes, recipient_public_key: rsa.RSAPublicKey,
                associated_data: Optional[bytes] = None) -> dict:
        """
        Encrypt data using hybrid encryption.

        Returns a dictionary containing all components needed for decryption.
        """
        # Generate random symmetric key
        symmetric_key = SymmetricEncryption.generate_key()

        # Encrypt data with symmetric key
        nonce, ciphertext = SymmetricEncryption.encrypt(
            plaintext, symmetric_key, associated_data
        )

        # Encrypt symmetric key with recipient's public key
        encrypted_key = AsymmetricEncryption.encrypt_key(
            symmetric_key, recipient_public_key
        )

        return {
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'algorithm': 'RSA-OAEP-AES-256-GCM'
        }

    @staticmethod
    def decrypt(encrypted_data: dict, private_key: rsa.RSAPrivateKey,
                associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using hybrid encryption.
        """
        # Decode components
        encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])

        # Decrypt symmetric key
        symmetric_key = AsymmetricEncryption.decrypt_key(encrypted_key, private_key)

        # Decrypt data
        return SymmetricEncryption.decrypt(nonce, ciphertext, symmetric_key, associated_data)
