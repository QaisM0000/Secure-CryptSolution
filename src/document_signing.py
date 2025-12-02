"""
Document Signing and Verification Module

This module provides the core functionality for signing and verifying
documents with the following security properties:

1. Confidentiality: Documents can be encrypted for specific recipients
2. Integrity: SHA-256 hashes detect any modification to the document
3. Authentication: Certificates verify the signer's identity
4. Non-repudiation: Digital signatures prove the signer created the signature

Signed Document Format:
{
    "document": {
        "content": <base64 encoded content or encrypted data>,
        "filename": <original filename>,
        "mime_type": <content type>,
        "encrypted": <boolean>,
        "hash": <SHA-256 hash of original content>
    },
    "signature": {
        "value": <base64 encoded RSA-PSS signature>,
        "algorithm": "RSA-PSS-SHA256",
        "timestamp": <ISO 8601 timestamp>,
        "signer_certificate": <base64 encoded certificate>
    },
    "metadata": {
        "version": "1.0",
        "created_at": <timestamp>
    }
}
"""

import os
import json
import base64
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .crypto_core import (
    AsymmetricEncryption,
    HashOperations,
    HybridEncryption,
    KeySerializer
)


class SignedDocument:
    """
    Represents a signed document with all cryptographic components.
    """

    VERSION = "1.0"

    def __init__(self):
        self.content: bytes = b""
        self.filename: str = ""
        self.mime_type: str = "application/octet-stream"
        self.content_hash: str = ""
        self.signature: bytes = b""
        self.timestamp: str = ""
        self.signer_certificate: Optional[x509.Certificate] = None
        self.encrypted: bool = False
        self.encrypted_data: Optional[dict] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        doc = {
            "document": {
                "filename": self.filename,
                "mime_type": self.mime_type,
                "hash": self.content_hash,
                "encrypted": self.encrypted
            },
            "signature": {
                "value": base64.b64encode(self.signature).decode('utf-8'),
                "algorithm": "RSA-PSS-SHA256",
                "timestamp": self.timestamp
            },
            "metadata": {
                "version": self.VERSION,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        }

        if self.encrypted and self.encrypted_data:
            doc["document"]["content"] = self.encrypted_data
        else:
            doc["document"]["content"] = base64.b64encode(self.content).decode('utf-8')

        if self.signer_certificate:
            doc["signature"]["signer_certificate"] = base64.b64encode(
                self.signer_certificate.public_bytes(serialization.Encoding.PEM)
            ).decode('utf-8')

        return doc

    @classmethod
    def from_dict(cls, data: dict) -> 'SignedDocument':
        """Create from dictionary."""
        doc = cls()
        doc.filename = data["document"]["filename"]
        doc.mime_type = data["document"]["mime_type"]
        doc.content_hash = data["document"]["hash"]
        doc.encrypted = data["document"].get("encrypted", False)

        if doc.encrypted:
            doc.encrypted_data = data["document"]["content"]
        else:
            doc.content = base64.b64decode(data["document"]["content"])

        doc.signature = base64.b64decode(data["signature"]["value"])
        doc.timestamp = data["signature"]["timestamp"]

        if "signer_certificate" in data["signature"]:
            cert_pem = base64.b64decode(data["signature"]["signer_certificate"])
            doc.signer_certificate = x509.load_pem_x509_certificate(
                cert_pem,
                default_backend()
            )

        return doc

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> 'SignedDocument':
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))


class DocumentSigner:
    """
    Signs documents using RSA-PSS digital signatures.

    The signing process:
    1. Read document content
    2. Compute SHA-256 hash
    3. Optionally encrypt content for a recipient
    4. Sign the hash with signer's private key
    5. Attach certificate for verification
    """

    def __init__(self, private_key, certificate: Optional[x509.Certificate] = None):
        """
        Initialize signer with private key and optional certificate.

        Args:
            private_key: RSA private key for signing
            certificate: X.509 certificate to include in signature
        """
        self.private_key = private_key
        self.certificate = certificate

    def sign_document(
        self,
        document_path: str,
        encrypt_for: Optional[Any] = None
    ) -> SignedDocument:
        """
        Sign a document file.

        Args:
            document_path: Path to the document to sign
            encrypt_for: Optional recipient's public key for encryption

        Returns:
            SignedDocument object containing all components
        """
        path = Path(document_path)
        if not path.exists():
            raise FileNotFoundError(f"Document not found: {document_path}")

        # Read document content
        with open(path, 'rb') as f:
            content = f.read()

        return self.sign_content(
            content=content,
            filename=path.name,
            encrypt_for=encrypt_for
        )

    def sign_content(
        self,
        content: bytes,
        filename: str,
        encrypt_for: Optional[Any] = None
    ) -> SignedDocument:
        """
        Sign arbitrary content.

        Args:
            content: Raw bytes to sign
            filename: Name for the content
            encrypt_for: Optional recipient's public key

        Returns:
            SignedDocument object
        """
        signed_doc = SignedDocument()
        signed_doc.filename = filename
        signed_doc.mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

        # Compute hash of original content
        signed_doc.content_hash = HashOperations.sha256_hex(content)

        # Optionally encrypt content
        if encrypt_for:
            signed_doc.encrypted = True
            signed_doc.encrypted_data = HybridEncryption.encrypt(content, encrypt_for)
        else:
            signed_doc.content = content

        # Create signature over the hash
        hash_bytes = signed_doc.content_hash.encode('utf-8')
        signed_doc.signature = AsymmetricEncryption.sign(hash_bytes, self.private_key)

        # Add timestamp and certificate
        signed_doc.timestamp = datetime.now(timezone.utc).isoformat()
        signed_doc.signer_certificate = self.certificate

        return signed_doc


class DocumentVerifier:
    """
    Verifies document signatures and integrity.

    Verification process:
    1. Extract signature and hash from signed document
    2. Verify signature using signer's public key
    3. If encrypted, decrypt content
    4. Recompute hash and compare
    5. Optionally verify certificate chain
    """

    def __init__(self, ca_certificate: Optional[x509.Certificate] = None):
        """
        Initialize verifier with optional CA certificate.

        Args:
            ca_certificate: CA certificate for validating signer certificates
        """
        self.ca_certificate = ca_certificate

    def verify_document(
        self,
        signed_doc: SignedDocument,
        decryption_key: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Verify a signed document.

        Args:
            signed_doc: The SignedDocument to verify
            decryption_key: Private key for decrypting (if encrypted)

        Returns:
            Dictionary with verification results
        """
        result = {
            "valid": True,
            "signature_valid": False,
            "integrity_valid": False,
            "certificate_valid": None,
            "errors": [],
            "warnings": [],
            "document_info": {
                "filename": signed_doc.filename,
                "mime_type": signed_doc.mime_type,
                "signed_at": signed_doc.timestamp,
                "encrypted": signed_doc.encrypted
            }
        }

        # Get signer's public key
        if signed_doc.signer_certificate:
            signer_public_key = signed_doc.signer_certificate.public_key()
            result["signer"] = signed_doc.signer_certificate.subject.rfc4514_string()
        else:
            result["valid"] = False
            result["errors"].append("No signer certificate found")
            return result

        # Verify signature
        hash_bytes = signed_doc.content_hash.encode('utf-8')
        signature_valid = AsymmetricEncryption.verify(
            hash_bytes,
            signed_doc.signature,
            signer_public_key
        )

        result["signature_valid"] = signature_valid
        if not signature_valid:
            result["valid"] = False
            result["errors"].append("Signature verification failed")

        # Get content for integrity check
        content = None
        if signed_doc.encrypted:
            if decryption_key:
                try:
                    content = HybridEncryption.decrypt(
                        signed_doc.encrypted_data,
                        decryption_key
                    )
                except Exception as e:
                    result["valid"] = False
                    result["errors"].append(f"Decryption failed: {str(e)}")
            else:
                result["warnings"].append("Document is encrypted; cannot verify integrity without decryption key")
        else:
            content = signed_doc.content

        # Verify integrity
        if content:
            computed_hash = HashOperations.sha256_hex(content)
            integrity_valid = computed_hash == signed_doc.content_hash
            result["integrity_valid"] = integrity_valid

            if not integrity_valid:
                result["valid"] = False
                result["errors"].append("Document integrity check failed; content has been modified")

        # Verify certificate if CA is available
        if self.ca_certificate and signed_doc.signer_certificate:
            result["certificate_valid"] = self._verify_certificate(signed_doc.signer_certificate)
            if not result["certificate_valid"]:
                result["warnings"].append("Signer certificate could not be verified against CA")

        return result

    def _verify_certificate(self, certificate: x509.Certificate) -> bool:
        """Verify certificate against CA."""
        try:
            now = datetime.now(timezone.utc)

            # Check validity period
            if certificate.not_valid_before_utc > now:
                return False
            if certificate.not_valid_after_utc < now:
                return False

            # Verify signature
            self.ca_certificate.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                certificate.signature_algorithm_parameters
            )
            return True
        except Exception:
            return False

    def extract_content(
        self,
        signed_doc: SignedDocument,
        decryption_key: Optional[Any] = None
    ) -> bytes:
        """
        Extract the original content from a signed document.

        Args:
            signed_doc: The signed document
            decryption_key: Private key if document is encrypted

        Returns:
            Original document content as bytes
        """
        if signed_doc.encrypted:
            if not decryption_key:
                raise ValueError("Decryption key required for encrypted document")
            return HybridEncryption.decrypt(signed_doc.encrypted_data, decryption_key)
        else:
            return signed_doc.content


def save_signed_document(signed_doc: SignedDocument, output_path: str):
    """Save a signed document to a JSON file."""
    with open(output_path, 'w') as f:
        f.write(signed_doc.to_json())


def load_signed_document(filepath: str) -> SignedDocument:
    """Load a signed document from a JSON file."""
    with open(filepath, 'r') as f:
        return SignedDocument.from_json(f.read())
