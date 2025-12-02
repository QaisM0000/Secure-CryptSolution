"""
SecureSign CLI Application

A command-line interface for the Secure Document Signing and Verification Service.
Provides commands for key management, certificate operations, and document signing.

Usage Examples:
    # Initialize CA
    python -m src.cli ca init --name "My CA" --org "My Organization"

    # Generate user key pair
    python -m src.cli keys generate --user alice --password secret123

    # Issue certificate
    python -m src.cli ca issue --name "Alice Smith" --email alice@example.com --key-id abc123

    # Sign a document
    python -m src.cli sign document.pdf --key-id abc123 --password secret123

    # Verify a document
    python -m src.cli verify document.pdf.signed
"""

import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from .key_management import KeyStore
from .certificate_authority import CertificateAuthority
from .document_signing import (
    DocumentSigner,
    DocumentVerifier,
    SignedDocument,
    save_signed_document,
    load_signed_document
)

# Initialize paths
BASE_DIR = Path(__file__).parent.parent
KEYS_DIR = BASE_DIR / "keys"
CERTS_DIR = BASE_DIR / "certificates"
SIGNED_DIR = BASE_DIR / "signed_documents"

console = Console()


def get_key_store() -> KeyStore:
    """Get or create key store instance."""
    return KeyStore(str(KEYS_DIR))


def get_ca() -> CertificateAuthority:
    """Get or create CA instance."""
    return CertificateAuthority(str(CERTS_DIR))


@click.group()
@click.version_option(version="1.0.0", prog_name="SecureSign")
def cli():
    """
    SecureSign: Secure Document Signing and Verification Service

    A cryptographic solution demonstrating confidentiality, integrity,
    authentication, and non-repudiation through digital signatures.
    """
    pass


# ============================================================================
# Certificate Authority Commands
# ============================================================================

@cli.group()
def ca():
    """Certificate Authority management commands."""
    pass


@ca.command("init")
@click.option("--name", default="SecureSign Root CA", help="CA common name")
@click.option("--org", default="SecureSign", help="Organization name")
@click.option("--country", default="US", help="Country code (2 letters)")
@click.option("--validity", default=10, help="Validity in years")
@click.option("--password", prompt=True, hide_input=True,
              confirmation_prompt=True, help="Password to protect CA key")
def ca_init(name, org, country, validity, password):
    """Initialize the Certificate Authority with a self-signed root certificate."""
    try:
        ca_instance = get_ca()
        cert_path, key_path = ca_instance.initialize_ca(
            common_name=name,
            organization=org,
            country=country,
            validity_years=validity,
            password=password
        )

        console.print(Panel.fit(
            f"[green]Certificate Authority initialized successfully![/green]\n\n"
            f"Certificate: {cert_path}\n"
            f"Private Key: {key_path}\n\n"
            f"[yellow]Keep the private key password safe![/yellow]",
            title="CA Initialization"
        ))
    except Exception as e:
        console.print(f"[red]Error initializing CA: {e}[/red]")
        sys.exit(1)


@ca.command("issue")
@click.option("--name", required=True, help="Subject's full name")
@click.option("--email", required=True, help="Subject's email address")
@click.option("--org", default="SecureSign User", help="Organization")
@click.option("--key-id", required=True, help="Key ID for the certificate")
@click.option("--validity", default=365, help="Validity in days")
@click.option("--ca-password", prompt=True, hide_input=True, help="CA private key password")
def ca_issue(name, email, org, key_id, validity, ca_password):
    """Issue a certificate for a user."""
    try:
        ca_instance = get_ca()
        ca_instance.load_ca(password=ca_password)

        key_store = get_key_store()
        public_key = key_store.load_public_key(key_id)

        cert_path = CERTS_DIR / f"{key_id}_certificate.pem"
        certificate = ca_instance.issue_certificate(
            subject_name=name,
            subject_email=email,
            subject_public_key=public_key,
            organization=org,
            validity_days=validity,
            output_path=str(cert_path)
        )

        cert_info = ca_instance.get_certificate_info(certificate)

        console.print(Panel.fit(
            f"[green]Certificate issued successfully![/green]\n\n"
            f"Subject: {name} <{email}>\n"
            f"Serial: {cert_info['serial_number']}\n"
            f"Valid Until: {cert_info['not_valid_after']}\n"
            f"Saved to: {cert_path}",
            title="Certificate Issued"
        ))
    except FileNotFoundError:
        console.print("[red]CA not initialized. Run 'ca init' first.[/red]")
        sys.exit(1)
    except KeyError:
        console.print(f"[red]Key ID '{key_id}' not found. Generate keys first.[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error issuing certificate: {e}[/red]")
        sys.exit(1)


@ca.command("info")
def ca_info():
    """Display Certificate Authority information."""
    try:
        ca_instance = get_ca()
        ca_instance.load_ca()

        cert_info = ca_instance.get_certificate_info(ca_instance._ca_certificate)

        table = Table(title="Certificate Authority Information")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Common Name", cert_info["subject"]["common_name"])
        table.add_row("Organization", cert_info["subject"]["organization"])
        table.add_row("Serial Number", cert_info["serial_number"])
        table.add_row("Valid From", cert_info["not_valid_before"])
        table.add_row("Valid Until", cert_info["not_valid_after"])
        table.add_row("Algorithm", cert_info["signature_algorithm"])

        console.print(table)
    except FileNotFoundError:
        console.print("[red]CA not initialized. Run 'ca init' first.[/red]")
        sys.exit(1)


# ============================================================================
# Key Management Commands
# ============================================================================

@cli.group()
def keys():
    """Key management commands."""
    pass


@keys.command("generate")
@click.option("--user", required=True, help="User identifier")
@click.option("--purpose", default="signing", help="Key purpose (signing/encryption/both)")
@click.option("--password", prompt=True, hide_input=True,
              confirmation_prompt=True, help="Password to protect private key")
def keys_generate(user, purpose, password):
    """Generate a new RSA key pair for a user."""
    try:
        key_store = get_key_store()
        key_id, priv_path, pub_path = key_store.generate_and_store_keypair(
            user_id=user,
            password=password,
            purpose=purpose
        )

        console.print(Panel.fit(
            f"[green]Key pair generated successfully![/green]\n\n"
            f"Key ID: {key_id}\n"
            f"User: {user}\n"
            f"Purpose: {purpose}\n\n"
            f"Private Key: {priv_path}\n"
            f"Public Key: {pub_path}\n\n"
            f"[yellow]Remember your password! It cannot be recovered.[/yellow]",
            title="Key Generation"
        ))
    except Exception as e:
        console.print(f"[red]Error generating keys: {e}[/red]")
        sys.exit(1)


@keys.command("list")
@click.option("--user", default=None, help="Filter by user ID")
def keys_list(user):
    """List all keys in the key store."""
    try:
        key_store = get_key_store()
        keys_dict = key_store.list_keys(user_id=user)

        if not keys_dict:
            console.print("[yellow]No keys found.[/yellow]")
            return

        table = Table(title="Registered Keys")
        table.add_column("Key ID", style="cyan")
        table.add_column("User", style="green")
        table.add_column("Purpose", style="blue")
        table.add_column("Created", style="magenta")
        table.add_column("Status", style="red")

        for key_id, info in keys_dict.items():
            status_style = "green" if info["status"] == "active" else "red"
            table.add_row(
                key_id,
                info["user_id"],
                info["purpose"],
                info["created_at"][:10],
                f"[{status_style}]{info['status']}[/{status_style}]"
            )

        console.print(table)
    except Exception as e:
        console.print(f"[red]Error listing keys: {e}[/red]")
        sys.exit(1)


@keys.command("info")
@click.argument("key_id")
def keys_info(key_id):
    """Display detailed information about a key."""
    try:
        key_store = get_key_store()
        info = key_store.get_key_info(key_id)

        table = Table(title=f"Key Information: {key_id}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        for key, value in info.items():
            table.add_row(key, str(value))

        console.print(table)
    except KeyError:
        console.print(f"[red]Key '{key_id}' not found.[/red]")
        sys.exit(1)


@keys.command("revoke")
@click.argument("key_id")
@click.option("--reason", default="unspecified", help="Reason for revocation")
def keys_revoke(key_id, reason):
    """Revoke a key, marking it as no longer valid."""
    try:
        key_store = get_key_store()
        key_store.revoke_key(key_id, reason)
        console.print(f"[green]Key '{key_id}' has been revoked.[/green]")
    except KeyError:
        console.print(f"[red]Key '{key_id}' not found.[/red]")
        sys.exit(1)


# ============================================================================
# Document Signing Commands
# ============================================================================

@cli.command("sign")
@click.argument("document", type=click.Path(exists=True))
@click.option("--key-id", required=True, help="Signing key ID")
@click.option("--password", prompt=True, hide_input=True, help="Private key password")
@click.option("--encrypt-for", default=None, help="Recipient's public key file for encryption")
@click.option("--output", "-o", default=None, help="Output file path")
def sign_document(document, key_id, password, encrypt_for, output):
    """Sign a document with digital signature."""
    try:
        key_store = get_key_store()
        ca_instance = get_ca()

        # Load private key
        private_key = key_store.load_private_key(key_id, password)

        # Load certificate if available
        cert_path = CERTS_DIR / f"{key_id}_certificate.pem"
        certificate = None
        if cert_path.exists():
            certificate = ca_instance.load_certificate_from_file(str(cert_path))

        # Load encryption key if specified
        encrypt_public_key = None
        if encrypt_for:
            encrypt_public_key = key_store.load_public_key_from_file(encrypt_for)

        # Sign document
        signer = DocumentSigner(private_key, certificate)
        signed_doc = signer.sign_document(document, encrypt_for=encrypt_public_key)

        # Determine output path
        if output is None:
            output = f"{document}.signed"

        save_signed_document(signed_doc, output)

        console.print(Panel.fit(
            f"[green]Document signed successfully![/green]\n\n"
            f"Original: {document}\n"
            f"Signed: {output}\n"
            f"Hash: {signed_doc.content_hash[:32]}...\n"
            f"Encrypted: {'Yes' if encrypt_for else 'No'}\n"
            f"Timestamp: {signed_doc.timestamp}",
            title="Document Signed"
        ))
    except KeyError:
        console.print(f"[red]Key '{key_id}' not found.[/red]")
        sys.exit(1)
    except ValueError as e:
        console.print(f"[red]Invalid password or key error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error signing document: {e}[/red]")
        sys.exit(1)


@cli.command("verify")
@click.argument("signed_document", type=click.Path(exists=True))
@click.option("--decrypt-key", default=None, help="Key ID for decryption")
@click.option("--decrypt-password", default=None, help="Password for decryption key")
def verify_document(signed_document, decrypt_key, decrypt_password):
    """Verify a signed document's authenticity and integrity."""
    try:
        # Load signed document
        signed_doc = load_signed_document(signed_document)

        # Load CA certificate for verification
        ca_instance = get_ca()
        try:
            ca_instance.load_ca()
            ca_cert = ca_instance._ca_certificate
        except FileNotFoundError:
            ca_cert = None

        # Load decryption key if needed
        decryption_key = None
        if decrypt_key and signed_doc.encrypted:
            if not decrypt_password:
                decrypt_password = click.prompt("Decryption key password", hide_input=True)
            key_store = get_key_store()
            decryption_key = key_store.load_private_key(decrypt_key, decrypt_password)

        # Verify
        verifier = DocumentVerifier(ca_certificate=ca_cert)
        result = verifier.verify_document(signed_doc, decryption_key=decryption_key)

        # Display results
        if result["valid"]:
            status = "[green]VALID[/green]"
        else:
            status = "[red]INVALID[/red]"

        table = Table(title=f"Verification Result: {status}")
        table.add_column("Check", style="cyan")
        table.add_column("Result", style="green")

        table.add_row("Document", result["document_info"]["filename"])
        table.add_row("Signed At", result["document_info"]["signed_at"])
        table.add_row("Signer", result.get("signer", "Unknown"))
        table.add_row(
            "Signature",
            "[green]Valid[/green]" if result["signature_valid"] else "[red]Invalid[/red]"
        )
        table.add_row(
            "Integrity",
            "[green]Valid[/green]" if result["integrity_valid"] else "[red]Invalid[/red]"
        )
        if result["certificate_valid"] is not None:
            table.add_row(
                "Certificate",
                "[green]Valid[/green]" if result["certificate_valid"] else "[yellow]Unverified[/yellow]"
            )

        console.print(table)

        if result["errors"]:
            console.print("\n[red]Errors:[/red]")
            for error in result["errors"]:
                console.print(f"  • {error}")

        if result["warnings"]:
            console.print("\n[yellow]Warnings:[/yellow]")
            for warning in result["warnings"]:
                console.print(f"  • {warning}")

    except Exception as e:
        console.print(f"[red]Error verifying document: {e}[/red]")
        sys.exit(1)


@cli.command("extract")
@click.argument("signed_document", type=click.Path(exists=True))
@click.option("--output", "-o", required=True, help="Output file path")
@click.option("--key-id", default=None, help="Key ID for decryption (if encrypted)")
@click.option("--password", default=None, help="Password for decryption key")
def extract_document(signed_document, output, key_id, password):
    """Extract the original document from a signed document."""
    try:
        signed_doc = load_signed_document(signed_document)

        decryption_key = None
        if signed_doc.encrypted:
            if not key_id:
                console.print("[red]Document is encrypted. Provide --key-id for decryption.[/red]")
                sys.exit(1)
            if not password:
                password = click.prompt("Decryption key password", hide_input=True)
            key_store = get_key_store()
            decryption_key = key_store.load_private_key(key_id, password)

        verifier = DocumentVerifier()
        content = verifier.extract_content(signed_doc, decryption_key)

        with open(output, 'wb') as f:
            f.write(content)

        console.print(f"[green]Document extracted to: {output}[/green]")

    except Exception as e:
        console.print(f"[red]Error extracting document: {e}[/red]")
        sys.exit(1)


# ============================================================================
# Demo Command
# ============================================================================

@cli.command("demo")
def run_demo():
    """Run a complete demonstration of the signing system."""
    console.print(Panel.fit(
        "[bold]SecureSign Demonstration[/bold]\n\n"
        "This demo will walk through the complete document signing workflow:\n"
        "1. Initialize Certificate Authority\n"
        "2. Generate user key pairs\n"
        "3. Issue certificates\n"
        "4. Sign a document\n"
        "5. Verify the signature",
        title="Demo Mode"
    ))

    console.print("\n[cyan]Step 1: Initializing Certificate Authority...[/cyan]")
    ca_instance = get_ca()
    try:
        ca_instance.initialize_ca(password="demo_password_123")
        console.print("[green]✓ CA initialized[/green]")
    except Exception as e:
        console.print(f"[yellow]CA already exists or error: {e}[/yellow]")
        ca_instance.load_ca(password="demo_password_123")

    console.print("\n[cyan]Step 2: Generating key pair for 'alice'...[/cyan]")
    key_store = get_key_store()
    try:
        key_id, _, _ = key_store.generate_and_store_keypair(
            user_id="alice",
            password="alice_password",
            purpose="signing"
        )
        console.print(f"[green]✓ Key pair generated (ID: {key_id})[/green]")
    except Exception as e:
        console.print(f"[yellow]Keys may already exist: {e}[/yellow]")
        keys = key_store.list_keys(user_id="alice")
        if keys:
            key_id = list(keys.keys())[0]
        else:
            raise

    console.print("\n[cyan]Step 3: Issuing certificate for 'alice'...[/cyan]")
    try:
        ca_instance.load_ca(password="demo_password_123")
        public_key = key_store.load_public_key(key_id)
        cert_path = CERTS_DIR / f"{key_id}_certificate.pem"
        ca_instance.issue_certificate(
            subject_name="Alice Demo User",
            subject_email="alice@example.com",
            subject_public_key=public_key,
            output_path=str(cert_path)
        )
        console.print("[green]✓ Certificate issued[/green]")
    except Exception as e:
        console.print(f"[yellow]Certificate may already exist: {e}[/yellow]")

    console.print("\n[cyan]Step 4: Creating and signing a test document...[/cyan]")
    test_doc_path = BASE_DIR / "test_document.txt"
    with open(test_doc_path, 'w') as f:
        f.write("This is a test document for SecureSign demonstration.\n")
        f.write("It contains important information that needs to be signed.\n")
        f.write(f"Created at: {__import__('datetime').datetime.now()}\n")

    private_key = key_store.load_private_key(key_id, "alice_password")
    certificate = ca_instance.load_certificate_from_file(str(cert_path))

    from .document_signing import DocumentSigner, save_signed_document
    signer = DocumentSigner(private_key, certificate)
    signed_doc = signer.sign_document(str(test_doc_path))

    signed_path = SIGNED_DIR / "test_document.txt.signed"
    save_signed_document(signed_doc, str(signed_path))
    console.print(f"[green]✓ Document signed and saved to {signed_path}[/green]")

    console.print("\n[cyan]Step 5: Verifying the signed document...[/cyan]")
    from .document_signing import load_signed_document, DocumentVerifier
    loaded_doc = load_signed_document(str(signed_path))
    verifier = DocumentVerifier(ca_certificate=ca_instance._ca_certificate)
    result = verifier.verify_document(loaded_doc)

    if result["valid"]:
        console.print("[green]✓ Document verification PASSED[/green]")
        console.print(f"  Signature: {'Valid' if result['signature_valid'] else 'Invalid'}")
        console.print(f"  Integrity: {'Valid' if result['integrity_valid'] else 'Invalid'}")
        console.print(f"  Certificate: {'Valid' if result['certificate_valid'] else 'Invalid'}")
    else:
        console.print("[red]✗ Document verification FAILED[/red]")
        for error in result["errors"]:
            console.print(f"  Error: {error}")

    console.print("\n" + "=" * 50)
    console.print("[bold green]Demo completed successfully![/bold green]")
    console.print("\nSecurity properties demonstrated:")
    console.print("  • [cyan]Confidentiality[/cyan]: Optional encryption with hybrid RSA/AES")
    console.print("  • [cyan]Integrity[/cyan]: SHA-256 hash verification")
    console.print("  • [cyan]Authentication[/cyan]: X.509 certificate verification")
    console.print("  • [cyan]Non-repudiation[/cyan]: RSA-PSS digital signature")


def main():
    """Entry point for the CLI application."""
    cli()


if __name__ == "__main__":
    main()
