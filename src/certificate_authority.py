"""
Certificate Authority and X.509 Certificate Management

This module implements a simple Certificate Authority (CA) for
issuing and verifying X.509 certificates. Certificates bind
public keys to identities, enabling authentication in the
document signing system.

Certificate Structure:
- Subject: Identity information (name, email, organization)
- Issuer: The CA that signed the certificate
- Validity Period: Start and end dates
- Public Key: The subject's public key
- Signature: CA's signature over the certificate
"""

import os
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from .crypto_core import AsymmetricEncryption, KeySerializer


class CertificateAuthority:
    """
    Simple Certificate Authority for issuing X.509 certificates.

    This CA can:
    - Generate its own root certificate (self-signed)
    - Issue certificates to users
    - Verify certificate signatures and validity
    - Maintain a certificate revocation list (CRL)
    """

    def __init__(self, ca_directory: str):
        """
        Initialize the Certificate Authority.

        Args:
            ca_directory: Directory to store CA files
        """
        self.ca_dir = Path(ca_directory)
        self.ca_dir.mkdir(parents=True, exist_ok=True)

        self.ca_key_path = self.ca_dir / "ca_private.pem"
        self.ca_cert_path = self.ca_dir / "ca_certificate.pem"
        self.crl_path = self.ca_dir / "revoked_certificates.json"

        self._ca_private_key = None
        self._ca_certificate = None
        self._load_crl()

    def _load_crl(self):
        """Load certificate revocation list."""
        if self.crl_path.exists():
            with open(self.crl_path, 'r') as f:
                self.crl = json.load(f)
        else:
            self.crl = {"revoked": []}

    def _save_crl(self):
        """Save certificate revocation list."""
        with open(self.crl_path, 'w') as f:
            json.dump(self.crl, f, indent=2)

    def initialize_ca(
        self,
        common_name: str = "SecureSign Root CA",
        organization: str = "SecureSign",
        country: str = "US",
        validity_years: int = 10,
        password: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Initialize the CA by generating a self-signed root certificate.

        Args:
            common_name: CA's common name
            organization: Organization name
            country: Two-letter country code
            validity_years: Certificate validity in years
            password: Optional password to protect CA private key

        Returns:
            Tuple of (ca_cert_path, ca_key_path)
        """
        # Generate CA key pair
        private_key, public_key = AsymmetricEncryption.generate_key_pair()

        # Build subject and issuer name (same for self-signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # Build certificate
        now = datetime.now(timezone.utc)
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(public_key)
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(now)
        cert_builder = cert_builder.not_valid_after(now + timedelta(days=validity_years * 365))

        # Add CA extensions
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        )
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        # Self-sign the certificate
        certificate = cert_builder.sign(private_key, hashes.SHA256(), default_backend())

        # Save CA private key
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()

        with open(self.ca_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            ))
        os.chmod(self.ca_key_path, 0o600)

        # Save CA certificate
        with open(self.ca_cert_path, 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        self._ca_private_key = private_key
        self._ca_certificate = certificate

        return str(self.ca_cert_path), str(self.ca_key_path)

    def load_ca(self, password: Optional[str] = None):
        """
        Load existing CA key and certificate.

        Args:
            password: Password to decrypt CA private key
        """
        if not self.ca_key_path.exists() or not self.ca_cert_path.exists():
            raise FileNotFoundError("CA not initialized. Run initialize_ca first.")

        # Load private key
        with open(self.ca_key_path, 'rb') as f:
            pwd = password.encode() if password else None
            self._ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=pwd,
                backend=default_backend()
            )

        # Load certificate
        with open(self.ca_cert_path, 'rb') as f:
            self._ca_certificate = x509.load_pem_x509_certificate(
                f.read(),
                default_backend()
            )

    def issue_certificate(
        self,
        subject_name: str,
        subject_email: str,
        subject_public_key: rsa.RSAPublicKey,
        organization: str = "SecureSign User",
        validity_days: int = 365,
        output_path: Optional[str] = None
    ) -> x509.Certificate:
        """
        Issue a certificate to a subject.

        Args:
            subject_name: Subject's common name
            subject_email: Subject's email address
            subject_public_key: Subject's public key
            organization: Subject's organization
            validity_days: Certificate validity in days
            output_path: Optional path to save certificate

        Returns:
            The issued certificate
        """
        if self._ca_private_key is None:
            raise RuntimeError("CA not loaded. Call load_ca first.")

        # Build subject name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject_email),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        ])

        # Build certificate
        now = datetime.now(timezone.utc)
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(self._ca_certificate.subject)
        cert_builder = cert_builder.public_key(subject_public_key)
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(now)
        cert_builder = cert_builder.not_valid_after(now + timedelta(days=validity_days))

        # Add extensions for end-entity certificate
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,  # Non-repudiation
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        # Sign with CA private key
        certificate = cert_builder.sign(
            self._ca_private_key,
            hashes.SHA256(),
            default_backend()
        )

        # Optionally save to file
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))

        return certificate

    def verify_certificate(self, certificate: x509.Certificate) -> Dict[str, Any]:
        """
        Verify a certificate's validity.

        Checks:
        - Certificate is signed by this CA
        - Certificate is within validity period
        - Certificate is not revoked

        Returns:
            Dictionary with verification results
        """
        result = {
            "valid": True,
            "errors": [],
            "subject": None,
            "issuer": None,
            "serial_number": None
        }

        if self._ca_certificate is None:
            raise RuntimeError("CA not loaded")

        # Extract certificate info
        result["subject"] = certificate.subject.rfc4514_string()
        result["issuer"] = certificate.issuer.rfc4514_string()
        result["serial_number"] = hex(certificate.serial_number)

        # Check validity period
        now = datetime.now(timezone.utc)
        if certificate.not_valid_before_utc > now:
            result["valid"] = False
            result["errors"].append("Certificate is not yet valid")

        if certificate.not_valid_after_utc < now:
            result["valid"] = False
            result["errors"].append("Certificate has expired")

        # Check if revoked
        serial_hex = hex(certificate.serial_number)
        if serial_hex in self.crl["revoked"]:
            result["valid"] = False
            result["errors"].append("Certificate has been revoked")

        # Verify signature
        try:
            self._ca_certificate.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                certificate.signature_algorithm_parameters
            )
        except Exception as e:
            result["valid"] = False
            result["errors"].append(f"Signature verification failed: {str(e)}")

        return result

    def revoke_certificate(self, certificate: x509.Certificate, reason: str = "unspecified"):
        """
        Revoke a certificate.

        Args:
            certificate: The certificate to revoke
            reason: Reason for revocation
        """
        serial_hex = hex(certificate.serial_number)
        if serial_hex not in self.crl["revoked"]:
            self.crl["revoked"].append(serial_hex)
            self._save_crl()

    def load_certificate_from_file(self, filepath: str) -> x509.Certificate:
        """Load a certificate from a PEM file."""
        with open(filepath, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    def get_certificate_info(self, certificate: x509.Certificate) -> Dict[str, Any]:
        """Extract readable information from a certificate."""
        def get_name_attribute(name, oid):
            try:
                return name.get_attributes_for_oid(oid)[0].value
            except IndexError:
                return None

        return {
            "subject": {
                "common_name": get_name_attribute(certificate.subject, NameOID.COMMON_NAME),
                "email": get_name_attribute(certificate.subject, NameOID.EMAIL_ADDRESS),
                "organization": get_name_attribute(certificate.subject, NameOID.ORGANIZATION_NAME),
            },
            "issuer": {
                "common_name": get_name_attribute(certificate.issuer, NameOID.COMMON_NAME),
                "organization": get_name_attribute(certificate.issuer, NameOID.ORGANIZATION_NAME),
            },
            "serial_number": hex(certificate.serial_number),
            "not_valid_before": certificate.not_valid_before_utc.isoformat(),
            "not_valid_after": certificate.not_valid_after_utc.isoformat(),
            "signature_algorithm": certificate.signature_algorithm_oid._name,
        }
