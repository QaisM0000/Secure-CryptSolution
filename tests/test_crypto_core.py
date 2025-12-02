"""
Unit tests for the core cryptographic operations module.

These tests verify the correct implementation of:
- AES-256-GCM symmetric encryption
- RSA-2048 asymmetric encryption and signatures
- SHA-256 hashing
- Hybrid encryption
"""

import pytest
import os

from src.crypto_core import (
    SymmetricEncryption,
    AsymmetricEncryption,
    HashOperations,
    KeySerializer,
    HybridEncryption
)


class TestSymmetricEncryption:
    """Tests for AES-256-GCM encryption."""

    def test_key_generation(self):
        """Test that generated keys have correct length."""
        key = SymmetricEncryption.generate_key()
        assert len(key) == 32  # 256 bits

    def test_encrypt_decrypt(self):
        """Test basic encryption and decryption."""
        key = SymmetricEncryption.generate_key()
        plaintext = b"Hello, World! This is a test message."

        nonce, ciphertext = SymmetricEncryption.encrypt(plaintext, key)
        decrypted = SymmetricEncryption.decrypt(nonce, ciphertext, key)

        assert decrypted == plaintext

    def test_encrypt_with_aad(self):
        """Test encryption with associated authenticated data."""
        key = SymmetricEncryption.generate_key()
        plaintext = b"Secret message"
        aad = b"Additional context data"

        nonce, ciphertext = SymmetricEncryption.encrypt(plaintext, key, aad)
        decrypted = SymmetricEncryption.decrypt(nonce, ciphertext, key, aad)

        assert decrypted == plaintext

    def test_tampered_ciphertext_fails(self):
        """Test that modified ciphertext is detected."""
        key = SymmetricEncryption.generate_key()
        plaintext = b"Test message"

        nonce, ciphertext = SymmetricEncryption.encrypt(plaintext, key)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(Exception):  # InvalidTag
            SymmetricEncryption.decrypt(nonce, tampered, key)

    def test_wrong_key_fails(self):
        """Test that wrong key fails decryption."""
        key1 = SymmetricEncryption.generate_key()
        key2 = SymmetricEncryption.generate_key()
        plaintext = b"Test message"

        nonce, ciphertext = SymmetricEncryption.encrypt(plaintext, key1)

        with pytest.raises(Exception):
            SymmetricEncryption.decrypt(nonce, ciphertext, key2)


class TestAsymmetricEncryption:
    """Tests for RSA encryption and signatures."""

    def test_key_generation(self):
        """Test RSA key pair generation."""
        private_key, public_key = AsymmetricEncryption.generate_key_pair()
        assert private_key is not None
        assert public_key is not None

    def test_encrypt_decrypt_key(self):
        """Test RSA encryption of symmetric keys."""
        private_key, public_key = AsymmetricEncryption.generate_key_pair()
        symmetric_key = os.urandom(32)

        encrypted = AsymmetricEncryption.encrypt_key(symmetric_key, public_key)
        decrypted = AsymmetricEncryption.decrypt_key(encrypted, private_key)

        assert decrypted == symmetric_key

    def test_sign_verify(self):
        """Test RSA-PSS signature creation and verification."""
        private_key, public_key = AsymmetricEncryption.generate_key_pair()
        message = b"This is the message to sign."

        signature = AsymmetricEncryption.sign(message, private_key)
        assert AsymmetricEncryption.verify(message, signature, public_key)

    def test_verify_wrong_message_fails(self):
        """Test that signature verification fails for wrong message."""
        private_key, public_key = AsymmetricEncryption.generate_key_pair()
        message = b"Original message"

        signature = AsymmetricEncryption.sign(message, private_key)
        assert not AsymmetricEncryption.verify(b"Wrong message", signature, public_key)

    def test_verify_wrong_key_fails(self):
        """Test that signature verification fails with wrong key."""
        private_key1, public_key1 = AsymmetricEncryption.generate_key_pair()
        _, public_key2 = AsymmetricEncryption.generate_key_pair()
        message = b"Test message"

        signature = AsymmetricEncryption.sign(message, private_key1)
        assert not AsymmetricEncryption.verify(message, signature, public_key2)


class TestHashOperations:
    """Tests for SHA-256 hashing."""

    def test_sha256_consistency(self):
        """Test that same input produces same hash."""
        data = b"Test data for hashing"
        hash1 = HashOperations.sha256(data)
        hash2 = HashOperations.sha256(data)
        assert hash1 == hash2

    def test_sha256_length(self):
        """Test SHA-256 hash length."""
        data = b"Test data"
        hash_bytes = HashOperations.sha256(data)
        assert len(hash_bytes) == 32  # 256 bits

    def test_sha256_hex(self):
        """Test hex encoding of hash."""
        data = b"Test data"
        hash_hex = HashOperations.sha256_hex(data)
        assert len(hash_hex) == 64  # 64 hex characters

    def test_verify_hash(self):
        """Test hash verification."""
        data = b"Important data"
        expected_hash = HashOperations.sha256(data)
        assert HashOperations.verify_hash(data, expected_hash)

    def test_verify_hash_different_data_fails(self):
        """Test that different data fails hash verification."""
        original_hash = HashOperations.sha256(b"Original data")
        assert not HashOperations.verify_hash(b"Modified data", original_hash)


class TestKeySerializer:
    """Tests for key serialization."""

    def test_serialize_deserialize_private_key(self):
        """Test private key serialization without password."""
        private_key, _ = AsymmetricEncryption.generate_key_pair()

        pem_data = KeySerializer.serialize_private_key(private_key)
        loaded_key = KeySerializer.deserialize_private_key(pem_data)

        assert loaded_key is not None

    def test_serialize_deserialize_private_key_with_password(self):
        """Test private key serialization with password protection."""
        private_key, _ = AsymmetricEncryption.generate_key_pair()
        password = b"secure_password_123"

        pem_data = KeySerializer.serialize_private_key(private_key, password)
        loaded_key = KeySerializer.deserialize_private_key(pem_data, password)

        assert loaded_key is not None

    def test_serialize_deserialize_public_key(self):
        """Test public key serialization."""
        _, public_key = AsymmetricEncryption.generate_key_pair()

        pem_data = KeySerializer.serialize_public_key(public_key)
        loaded_key = KeySerializer.deserialize_public_key(pem_data)

        assert loaded_key is not None


class TestHybridEncryption:
    """Tests for hybrid encryption system."""

    def test_encrypt_decrypt(self):
        """Test hybrid encryption and decryption."""
        private_key, public_key = AsymmetricEncryption.generate_key_pair()
        plaintext = b"This is a longer message that benefits from hybrid encryption."

        encrypted = HybridEncryption.encrypt(plaintext, public_key)
        decrypted = HybridEncryption.decrypt(encrypted, private_key)

        assert decrypted == plaintext

    def test_encrypt_with_aad(self):
        """Test hybrid encryption with associated data."""
        private_key, public_key = AsymmetricEncryption.generate_key_pair()
        plaintext = b"Secret message"
        aad = b"Context data"

        encrypted = HybridEncryption.encrypt(plaintext, public_key, aad)
        decrypted = HybridEncryption.decrypt(encrypted, private_key, aad)

        assert decrypted == plaintext

    def test_encrypted_structure(self):
        """Test that encrypted data has expected structure."""
        _, public_key = AsymmetricEncryption.generate_key_pair()
        plaintext = b"Test"

        encrypted = HybridEncryption.encrypt(plaintext, public_key)

        assert 'encrypted_key' in encrypted
        assert 'nonce' in encrypted
        assert 'ciphertext' in encrypted
        assert 'algorithm' in encrypted
        assert encrypted['algorithm'] == 'RSA-OAEP-AES-256-GCM'
