"""
Tests for document signing and verification functionality.
"""

import pytest
import tempfile
import os
from pathlib import Path

from src.crypto_core import AsymmetricEncryption
from src.document_signing import (
    SignedDocument,
    DocumentSigner,
    DocumentVerifier,
    save_signed_document,
    load_signed_document
)


class TestSignedDocument:
    """Tests for SignedDocument serialization."""

    def test_to_dict_from_dict(self):
        """Test document serialization roundtrip."""
        doc = SignedDocument()
        doc.content = b"Test content"
        doc.filename = "test.txt"
        doc.content_hash = "abc123"
        doc.signature = b"signature_bytes"
        doc.timestamp = "2024-01-01T00:00:00Z"

        doc_dict = doc.to_dict()
        restored = SignedDocument.from_dict(doc_dict)

        assert restored.filename == doc.filename
        assert restored.content_hash == doc.content_hash
        assert restored.timestamp == doc.timestamp

    def test_to_json_from_json(self):
        """Test JSON serialization roundtrip."""
        doc = SignedDocument()
        doc.content = b"Test content"
        doc.filename = "test.txt"
        doc.content_hash = "abc123"
        doc.signature = b"signature_bytes"
        doc.timestamp = "2024-01-01T00:00:00Z"

        json_str = doc.to_json()
        restored = SignedDocument.from_json(json_str)

        assert restored.filename == doc.filename


class TestDocumentSigner:
    """Tests for document signing."""

    def test_sign_content(self):
        """Test signing arbitrary content."""
        private_key, _ = AsymmetricEncryption.generate_key_pair()
        signer = DocumentSigner(private_key)

        content = b"Document content to sign"
        signed_doc = signer.sign_content(content, "test.txt")

        assert signed_doc.content == content
        assert signed_doc.filename == "test.txt"
        assert len(signed_doc.signature) > 0
        assert len(signed_doc.content_hash) == 64  # SHA-256 hex

    def test_sign_file(self):
        """Test signing a file."""
        private_key, _ = AsymmetricEncryption.generate_key_pair()
        signer = DocumentSigner(private_key)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Test file content")
            temp_path = f.name

        try:
            signed_doc = signer.sign_document(temp_path)
            assert signed_doc.filename == os.path.basename(temp_path)
            assert b"Test file content" in signed_doc.content
        finally:
            os.unlink(temp_path)

    def test_sign_with_encryption(self):
        """Test signing with recipient encryption."""
        signer_private, _ = AsymmetricEncryption.generate_key_pair()
        _, recipient_public = AsymmetricEncryption.generate_key_pair()

        signer = DocumentSigner(signer_private)
        content = b"Secret document"

        signed_doc = signer.sign_content(content, "secret.txt", encrypt_for=recipient_public)

        assert signed_doc.encrypted is True
        assert signed_doc.encrypted_data is not None


class TestDocumentVerifier:
    """Tests for document verification."""

    def test_verify_valid_signature(self):
        """Test verification of valid signature."""
        private_key, public_key = AsymmetricEncryption.generate_key_pair()

        # Create a simple certificate-like setup
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from datetime import datetime, timedelta, timezone

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test User"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )

        signer = DocumentSigner(private_key, cert)
        content = b"Document to verify"
        signed_doc = signer.sign_content(content, "test.txt")

        verifier = DocumentVerifier()
        result = verifier.verify_document(signed_doc)

        assert result["valid"] is True
        assert result["signature_valid"] is True
        assert result["integrity_valid"] is True

    def test_detect_tampered_content(self):
        """Test detection of modified content."""
        private_key, public_key = AsymmetricEncryption.generate_key_pair()

        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from datetime import datetime, timedelta, timezone

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test User"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )

        signer = DocumentSigner(private_key, cert)
        signed_doc = signer.sign_content(b"Original content", "test.txt")

        # Tamper with content
        signed_doc.content = b"Modified content"

        verifier = DocumentVerifier()
        result = verifier.verify_document(signed_doc)

        assert result["valid"] is False
        assert result["integrity_valid"] is False


class TestFileOperations:
    """Tests for file save/load operations."""

    def test_save_and_load(self):
        """Test saving and loading signed documents."""
        private_key, _ = AsymmetricEncryption.generate_key_pair()

        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from datetime import datetime, timedelta, timezone

        _, public_key = AsymmetricEncryption.generate_key_pair()
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .sign(private_key, hashes.SHA256())
        )

        signer = DocumentSigner(private_key, cert)
        signed_doc = signer.sign_content(b"Test content", "test.txt")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.signed', delete=False) as f:
            temp_path = f.name

        try:
            save_signed_document(signed_doc, temp_path)
            loaded_doc = load_signed_document(temp_path)

            assert loaded_doc.filename == signed_doc.filename
            assert loaded_doc.content_hash == signed_doc.content_hash
            assert loaded_doc.content == signed_doc.content
        finally:
            os.unlink(temp_path)
