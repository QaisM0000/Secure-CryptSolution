# SecureSign

A Secure Document Signing and Verification Service demonstrating cryptographic security properties including confidentiality, integrity, authentication, and non-repudiation.

## Overview

SecureSign is a command-line application that implements a complete document signing workflow using established cryptographic primitives. The system enables users to digitally sign documents, verify signatures, and optionally encrypt documents for specific recipients.

## Security Properties

| Property | Implementation |
|----------|---------------|
| **Confidentiality** | AES-256-GCM encryption with RSA key exchange |
| **Integrity** | SHA-256 cryptographic hashing |
| **Authentication** | X.509 certificate verification |
| **Non-repudiation** | RSA-PSS digital signatures |

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

```bash
# Clone the repository
git clone <repository-url>
cd Secure-CryptSolution

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

Run the built-in demonstration:

```bash
python -m src.cli demo
```

This will walk through the complete workflow:
1. Initialize a Certificate Authority
2. Generate user key pairs
3. Issue certificates
4. Sign a test document
5. Verify the signature

## Usage

### Initialize Certificate Authority

```bash
python -m src.cli ca init --name "My CA" --org "My Organization"
```

### Generate User Keys

```bash
python -m src.cli keys generate --user alice --purpose signing
```

### Issue a Certificate

```bash
python -m src.cli ca issue \
    --name "Alice Smith" \
    --email alice@example.com \
    --key-id <key-id>
```

### Sign a Document

```bash
python -m src.cli sign document.pdf --key-id <key-id>
```

### Verify a Signed Document

```bash
python -m src.cli verify document.pdf.signed
```

### Extract Original Document

```bash
python -m src.cli extract document.pdf.signed --output original.pdf
```

### Sign with Encryption

```bash
python -m src.cli sign secret.pdf \
    --key-id <signer-key-id> \
    --encrypt-for recipient_public.pem
```

## Project Structure

```
Secure-CryptSolution/
├── src/
│   ├── __init__.py          # Package initialization
│   ├── __main__.py           # Module entry point
│   ├── cli.py                # Command-line interface
│   ├── crypto_core.py        # Cryptographic primitives
│   ├── key_management.py     # Key storage and lifecycle
│   ├── certificate_authority.py  # X.509 certificate handling
│   └── document_signing.py   # Document signing/verification
├── tests/
│   ├── test_crypto_core.py   # Cryptography tests
│   └── test_document_signing.py  # Signing tests
├── docs/
│   ├── TECHNICAL_REPORT.md   # Full technical documentation
│   └── PRESENTATION_OUTLINE.md   # Presentation materials
├── keys/                     # Key storage directory
├── certificates/             # Certificate storage directory
├── signed_documents/         # Signed document output
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

## Cryptographic Algorithms

### Symmetric Encryption
- **Algorithm**: AES-256-GCM
- **Key Size**: 256 bits
- **Mode**: Galois/Counter Mode (authenticated encryption)

### Asymmetric Encryption
- **Algorithm**: RSA-2048
- **Padding**: OAEP with SHA-256

### Digital Signatures
- **Algorithm**: RSA-PSS
- **Hash**: SHA-256
- **Salt Length**: Maximum

### Key Derivation
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 480,000

## Running Tests

```bash
# Install test dependencies
pip install pytest

# Run all tests
pytest tests/

# Run with verbose output
pytest tests/ -v
```

## Security Considerations

### Best Practices Followed

1. **No custom cryptography**: All algorithms from the established `cryptography` library
2. **Secure random generation**: Uses OS-provided entropy via `os.urandom()`
3. **Password-protected keys**: Private keys encrypted at rest with PBKDF2
4. **Authenticated encryption**: AES-GCM provides integrity alongside confidentiality
5. **Modern padding schemes**: OAEP for encryption, PSS for signatures

### Known Limitations

- Self-signed CA (not integrated with global PKI)
- File-based key storage (production would use HSM)
- No timestamp authority integration
- Single-signer documents only

## Documentation

- **Technical Report**: `docs/TECHNICAL_REPORT.md`
- **Presentation Outline**: `docs/PRESENTATION_OUTLINE.md`

## Dependencies

- `cryptography>=41.0.0`: Core cryptographic operations
- `click>=8.1.0`: Command-line interface framework
- `rich>=13.0.0`: Terminal output formatting
- `python-dateutil>=2.8.0`: Date handling utilities

## License

This project is developed for educational purposes as part of a cryptography course.

## Authors

Cryptography Project Team
