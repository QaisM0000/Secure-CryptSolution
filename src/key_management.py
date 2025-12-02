"""
Key Management System

Provides secure key generation, storage, and retrieval operations.
Implements password-based key derivation for protecting private keys
and maintains a key registry for tracking key metadata.

Security considerations:
- Private keys are encrypted with user-provided passwords using PBKDF2
- Key files have restricted permissions (readable only by owner)
- Key metadata is stored separately from key material
"""

import os
import json
import stat
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from .crypto_core import (
    AsymmetricEncryption,
    KeySerializer,
    HashOperations
)


class KeyStore:
    """
    Secure Key Storage and Management

    Manages cryptographic keys with the following features:
    - Password-protected private key storage
    - Key metadata tracking (creation date, key ID, purpose)
    - Secure file permissions
    - Key rotation support
    """

    def __init__(self, keys_directory: str):
        """
        Initialize key store with specified directory.

        Args:
            keys_directory: Path to store key files
        """
        self.keys_dir = Path(keys_directory)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.registry_path = self.keys_dir / "key_registry.json"
        self._load_registry()

    def _load_registry(self):
        """Load key registry from disk."""
        if self.registry_path.exists():
            with open(self.registry_path, 'r') as f:
                self.registry = json.load(f)
        else:
            self.registry = {"keys": {}}

    def _save_registry(self):
        """Save key registry to disk."""
        with open(self.registry_path, 'w') as f:
            json.dump(self.registry, f, indent=2, default=str)

    def _set_secure_permissions(self, filepath: Path):
        """Set file permissions to owner-read-only for sensitive files."""
        os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)

    def generate_key_id(self, public_key_pem: bytes) -> str:
        """
        Generate a unique key identifier based on public key hash.

        The key ID is the first 16 characters of the SHA-256 hash
        of the public key, providing a short but unique identifier.
        """
        return HashOperations.sha256_hex(public_key_pem)[:16]

    def generate_and_store_keypair(
        self,
        user_id: str,
        password: str,
        purpose: str = "signing"
    ) -> Tuple[str, str, str]:
        """
        Generate a new RSA key pair and store it securely.

        Args:
            user_id: Identifier for the key owner
            password: Password to protect the private key
            purpose: Intended use (signing, encryption, both)

        Returns:
            Tuple of (key_id, private_key_path, public_key_path)
        """
        # Generate key pair
        private_key, public_key = AsymmetricEncryption.generate_key_pair()

        # Serialize keys
        private_pem = KeySerializer.serialize_private_key(
            private_key,
            password=password.encode('utf-8')
        )
        public_pem = KeySerializer.serialize_public_key(public_key)

        # Generate key ID
        key_id = self.generate_key_id(public_pem)

        # Create file paths
        private_key_path = self.keys_dir / f"{user_id}_{key_id}_private.pem"
        public_key_path = self.keys_dir / f"{user_id}_{key_id}_public.pem"

        # Write keys to files
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        self._set_secure_permissions(private_key_path)

        with open(public_key_path, 'wb') as f:
            f.write(public_pem)

        # Update registry
        self.registry["keys"][key_id] = {
            "user_id": user_id,
            "purpose": purpose,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "algorithm": "RSA-2048",
            "private_key_path": str(private_key_path),
            "public_key_path": str(public_key_path),
            "status": "active"
        }
        self._save_registry()

        return key_id, str(private_key_path), str(public_key_path)

    def load_private_key(self, key_id: str, password: str):
        """
        Load a private key from storage.

        Args:
            key_id: The key identifier
            password: Password to decrypt the key

        Returns:
            RSA private key object

        Raises:
            KeyError: If key not found
            ValueError: If password is incorrect
        """
        if key_id not in self.registry["keys"]:
            raise KeyError(f"Key {key_id} not found in registry")

        key_info = self.registry["keys"][key_id]
        private_key_path = Path(key_info["private_key_path"])

        with open(private_key_path, 'rb') as f:
            private_pem = f.read()

        return KeySerializer.deserialize_private_key(
            private_pem,
            password=password.encode('utf-8')
        )

    def load_public_key(self, key_id: str):
        """
        Load a public key from storage.

        Args:
            key_id: The key identifier

        Returns:
            RSA public key object
        """
        if key_id not in self.registry["keys"]:
            raise KeyError(f"Key {key_id} not found in registry")

        key_info = self.registry["keys"][key_id]
        public_key_path = Path(key_info["public_key_path"])

        with open(public_key_path, 'rb') as f:
            public_pem = f.read()

        return KeySerializer.deserialize_public_key(public_pem)

    def load_public_key_from_file(self, filepath: str):
        """Load a public key directly from a file path."""
        with open(filepath, 'rb') as f:
            public_pem = f.read()
        return KeySerializer.deserialize_public_key(public_pem)

    def get_key_info(self, key_id: str) -> Dict[str, Any]:
        """Get metadata about a key."""
        if key_id not in self.registry["keys"]:
            raise KeyError(f"Key {key_id} not found")
        return self.registry["keys"][key_id]

    def list_keys(self, user_id: Optional[str] = None) -> Dict[str, Dict]:
        """
        List all keys or keys for a specific user.

        Args:
            user_id: Optional filter by user

        Returns:
            Dictionary of key_id -> key_info
        """
        if user_id:
            return {
                k: v for k, v in self.registry["keys"].items()
                if v["user_id"] == user_id
            }
        return self.registry["keys"]

    def revoke_key(self, key_id: str, reason: str = "unspecified"):
        """
        Revoke a key, marking it as no longer valid for use.

        Args:
            key_id: The key to revoke
            reason: Reason for revocation
        """
        if key_id not in self.registry["keys"]:
            raise KeyError(f"Key {key_id} not found")

        self.registry["keys"][key_id]["status"] = "revoked"
        self.registry["keys"][key_id]["revoked_at"] = datetime.now(timezone.utc).isoformat()
        self.registry["keys"][key_id]["revocation_reason"] = reason
        self._save_registry()

    def is_key_valid(self, key_id: str) -> bool:
        """Check if a key is valid (exists and not revoked)."""
        if key_id not in self.registry["keys"]:
            return False
        return self.registry["keys"][key_id]["status"] == "active"

    def export_public_key(self, key_id: str, output_path: str):
        """Export a public key to a specified location."""
        if key_id not in self.registry["keys"]:
            raise KeyError(f"Key {key_id} not found")

        key_info = self.registry["keys"][key_id]
        source_path = Path(key_info["public_key_path"])

        with open(source_path, 'rb') as src:
            with open(output_path, 'wb') as dst:
                dst.write(src.read())


class PasswordDerivation:
    """
    Password-Based Key Derivation

    Uses PBKDF2-HMAC-SHA256 for deriving cryptographic keys
    from user passwords. This provides protection against
    brute-force attacks through computational hardness.
    """

    ITERATIONS = 480000  # NIST SP 800-132 recommended minimum for PBKDF2
    SALT_LENGTH = 32

    @staticmethod
    def derive_key(password: str, salt: Optional[bytes] = None,
                   key_length: int = 32) -> Tuple[bytes, bytes]:
        """
        Derive a cryptographic key from a password.

        Args:
            password: User password
            salt: Optional salt (generated if not provided)
            key_length: Desired key length in bytes

        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(PasswordDerivation.SALT_LENGTH)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=PasswordDerivation.ITERATIONS,
            backend=default_backend()
        )

        derived_key = kdf.derive(password.encode('utf-8'))
        return derived_key, salt

    @staticmethod
    def verify_password(password: str, salt: bytes, expected_key: bytes) -> bool:
        """Verify a password against a previously derived key."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=len(expected_key),
            salt=salt,
            iterations=PasswordDerivation.ITERATIONS,
            backend=default_backend()
        )

        try:
            kdf.verify(password.encode('utf-8'), expected_key)
            return True
        except Exception:
            return False
