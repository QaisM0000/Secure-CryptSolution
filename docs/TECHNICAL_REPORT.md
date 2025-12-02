# SecureSign: A Secure Document Signing and Verification Service

## Technical Report

---

## 1. Introduction and Problem Statement

Digital documents have become the primary medium for business communications, legal agreements, and official records across virtually every sector of modern society. As organizations transition away from paper-based workflows, the need for robust mechanisms to ensure document authenticity has grown increasingly critical. Traditional physical signatures, once the gold standard for document verification, cannot be directly translated to digital environments without specialized cryptographic solutions.

The fundamental challenge lies in establishing trust within inherently untrusted digital networks. When a document travels across the internet, multiple opportunities exist for malicious actors to intercept, modify, or forge content. Consider a scenario where a company sends a signed contract to a partner organization. Without proper cryptographic protections, an attacker could alter the contract terms before delivery, impersonate the sender, or deny having sent the document altogether. These threats represent failures in four core security properties that any document signing system must address.

This project presents SecureSign, a command-line application that implements a complete document signing and verification workflow using established cryptographic primitives. The system demonstrates how modern cryptography solves real-world document security problems through a practical, functional prototype suitable for educational and small-scale organizational use.

---

## 2. System Architecture and Design

SecureSign follows a modular architecture that separates concerns into distinct, reusable components. The system comprises four primary layers, each responsible for specific functionality.

The **Cryptographic Core Layer** implements fundamental cryptographic operations including symmetric encryption, asymmetric encryption, digital signatures, and hashing. This layer provides abstract interfaces that hide implementation complexity from higher layers while ensuring consistent, secure usage of cryptographic primitives.

The **Key Management Layer** handles the complete lifecycle of cryptographic keys, from generation through storage, retrieval, and eventual revocation. Keys are stored in encrypted form using password-based key derivation, preventing unauthorized access even if an attacker gains access to the file system.

The **Certificate Authority Layer** implements a simplified Public Key Infrastructure that issues and validates X.509 certificates. These certificates bind public keys to identity information, enabling authentication of signers within the system.

The **Application Layer** provides the command-line interface that users interact with directly. This layer orchestrates the lower layers to implement complete workflows such as signing documents, verifying signatures, and managing certificates.

### System Overview Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                     SecureSign Architecture                      │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   Application Layer                      │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────┐ │    │
│  │  │  Sign   │  │ Verify  │  │ Extract │  │ Key/Cert Mgmt│ │    │
│  │  └────┬────┘  └────┬────┘  └────┬────┘  └──────┬──────┘ │    │
│  └───────┼────────────┼───────────┼───────────────┼────────┘    │
│          │            │           │               │              │
│  ┌───────┴────────────┴───────────┴───────────────┴────────┐    │
│  │                 Document Signing Layer                   │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐ │    │
│  │  │   Signer     │  │   Verifier   │  │ SignedDocument │ │    │
│  │  └──────┬───────┘  └──────┬───────┘  └───────┬────────┘ │    │
│  └─────────┼─────────────────┼──────────────────┼──────────┘    │
│            │                 │                  │                │
│  ┌─────────┴─────────────────┴──────────────────┴──────────┐    │
│  │              Certificate Authority Layer                 │    │
│  │  ┌────────────────┐  ┌─────────────┐  ┌───────────────┐ │    │
│  │  │ CA Management  │  │ Certificate │  │  Revocation   │ │    │
│  │  │                │  │   Issuance  │  │     List      │ │    │
│  │  └────────┬───────┘  └──────┬──────┘  └───────┬───────┘ │    │
│  └───────────┼─────────────────┼─────────────────┼─────────┘    │
│              │                 │                 │               │
│  ┌───────────┴─────────────────┴─────────────────┴─────────┐    │
│  │                   Key Management Layer                   │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐ │    │
│  │  │ Key Storage  │  │  Key Derivation│ │  Key Registry │ │    │
│  │  └──────┬───────┘  └──────┬───────┘  └───────┬────────┘ │    │
│  └─────────┼─────────────────┼──────────────────┼──────────┘    │
│            │                 │                  │                │
│  ┌─────────┴─────────────────┴──────────────────┴──────────┐    │
│  │                 Cryptographic Core Layer                 │    │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────┐  ┌──────┐ │    │
│  │  │ AES-256-GCM│  │  RSA-2048  │  │  SHA-256 │  │Hybrid│ │    │
│  │  │ Encryption │  │  RSA-PSS   │  │  Hashing │  │ Enc. │ │    │
│  │  └────────────┘  └────────────┘  └──────────┘  └──────┘ │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │            Python cryptography Library                     │   │
│  └───────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Cryptographic Algorithms Used

### Symmetric Encryption: AES-256-GCM

The system uses AES with a 256-bit key in Galois/Counter Mode for symmetric encryption. GCM provides authenticated encryption, meaning it simultaneously ensures confidentiality through encryption and integrity through an authentication tag. This mode was selected because it represents the current industry standard for symmetric encryption, offering both security and performance. The 256-bit key length provides adequate security margin against brute-force attacks, including potential future quantum computing threats.

### Asymmetric Encryption: RSA-2048 with OAEP

RSA with 2048-bit keys handles asymmetric operations including key exchange and digital signatures. For encryption operations, the system uses Optimal Asymmetric Encryption Padding, which provides semantic security against chosen-ciphertext attacks. While elliptic curve cryptography offers smaller key sizes for equivalent security, RSA remains widely supported and well-understood, making it appropriate for an educational implementation.

### Digital Signatures: RSA-PSS with SHA-256

Digital signatures use the Probabilistic Signature Scheme padding with SHA-256 as the hash function. PSS provides provable security properties that the older PKCS#1 v1.5 padding scheme lacks. The signature is computed over a SHA-256 hash of the document content, ensuring that any modification to the document invalidates the signature.

### Cryptographic Hash: SHA-256

All integrity verification uses SHA-256 from the SHA-2 family. This algorithm produces a 256-bit digest that uniquely identifies document content. The hash is computed before any encryption, ensuring that integrity can be verified after decryption. SHA-256 was chosen over SHA-3 due to its wider deployment and library support while still providing adequate collision resistance.

### Password-Based Key Derivation: PBKDF2-HMAC-SHA256

Private keys are encrypted at rest using keys derived from user passwords through PBKDF2 with 480,000 iterations. This iteration count follows current NIST recommendations and makes brute-force password attacks computationally expensive.

---

## 4. Libraries and Tools

### Python cryptography Library

The project uses the `cryptography` library as its sole cryptographic provider. This library was selected for several important reasons. First, it provides a high-level recipes interface alongside low-level hazmat primitives, allowing developers to choose the appropriate abstraction level. Second, it wraps OpenSSL for performance-critical operations while providing a Pythonic API. Third, the library is actively maintained by the Python Cryptographic Authority and undergoes regular security audits.

Alternative libraries were considered but rejected for specific reasons. PyCryptodome, while capable, lacks some of the certificate handling features required for this project. Directly using OpenSSL through subprocess calls would introduce unnecessary complexity and potential security issues with command-line argument handling. The standard library's hashlib module provides only hashing functionality, which covers only a small portion of the required operations.

### Additional Dependencies

The Click library provides the command-line interface framework, offering automatic help generation and argument parsing. Rich handles terminal output formatting with colored text and tables, improving the user experience during interactive sessions. These libraries were chosen for their simplicity and minimal dependencies, reducing the overall attack surface.

---

## 5. Key Management Strategy

Secure key management represents one of the most critical aspects of any cryptographic system. SecureSign implements several layers of protection for cryptographic keys.

### Key Generation

All keys are generated using cryptographically secure random number generators provided by the operating system through Python's `os.urandom()` function. RSA key pairs use a public exponent of 65537, which balances security against some known attacks while maintaining computational efficiency.

### Key Storage

Private keys are never stored in plaintext. Before writing to disk, each private key is encrypted using a key derived from the user's password through PBKDF2. The encrypted key is stored in PKCS#8 PEM format, which is widely supported and allows for password-protected storage. File permissions are set to owner-read-only mode, preventing other users on the system from accessing key files.

### Key Registry

A JSON-based registry tracks metadata about all keys in the system, including creation timestamps, associated user identifiers, and revocation status. This registry enables key lookup by identifier and supports key lifecycle management without exposing the actual key material.

### Key Revocation

When a key is compromised or no longer needed, it can be marked as revoked in the registry. Subsequent verification operations check the revocation status and warn users when signatures were created with revoked keys. While this implementation uses a simple local registry, production systems would integrate with more robust revocation mechanisms such as Certificate Revocation Lists or Online Certificate Status Protocol responders.

---

## 6. Implementation Details

### Document Signing Workflow

When a user signs a document, the following steps occur. First, the document content is read into memory and a SHA-256 hash is computed. If encryption is requested, the content is encrypted using hybrid encryption before being included in the signed document structure. The hash value is then signed using the signer's private key with RSA-PSS padding. Finally, the signature, hash, optional encrypted content, and signer's certificate are bundled into a JSON document that can be transmitted or stored.

### Verification Workflow

Verification reverses this process while performing multiple security checks. The verifier extracts the signer's certificate and validates it against the Certificate Authority. The signature is verified against the included hash using the public key from the certificate. If the document is encrypted and a decryption key is provided, the content is decrypted. The hash is recomputed from the decrypted content and compared against the signed hash value. Any failure in these checks causes the verification to report which specific property was violated.

### Hybrid Encryption

For confidentiality, the system implements hybrid encryption that combines RSA and AES. A random 256-bit AES key is generated for each encryption operation. The document content is encrypted with this key using AES-GCM. The AES key itself is then encrypted with the recipient's RSA public key using OAEP padding. Both the encrypted key and encrypted content are included in the output. This approach allows encrypting arbitrarily large documents efficiently while maintaining the security properties of asymmetric encryption for key exchange.

---

## 7. Security Analysis

### Threat Model

The system protects against several categories of attackers. External attackers who intercept documents in transit cannot read encrypted content without the recipient's private key. Attackers who modify documents, whether encrypted or not, will be detected through signature verification failures. Attackers who attempt to forge signatures cannot do so without access to the signer's private key. The combination of encryption, hashing, and digital signatures addresses confidentiality, integrity, authentication, and non-repudiation respectively.

### Known Limitations

This implementation has limitations appropriate to its educational scope. The Certificate Authority uses self-signed certificates without integration into the global PKI trust hierarchy. Key storage relies on file system permissions, which may be inadequate in shared hosting environments. The password-based key protection is only as strong as the passwords users choose. Production deployments would require hardware security modules, more robust key backup procedures, and integration with enterprise identity management systems.

### Security Properties Demonstrated

**Confidentiality** is achieved through AES-256-GCM encryption of document content with keys securely exchanged via RSA-OAEP.

**Integrity** is ensured by SHA-256 hashing of the original content, with any modification causing hash verification failure.

**Authentication** is provided by X.509 certificates that bind public keys to identity information, with certificate validation against the Certificate Authority.

**Non-repudiation** results from RSA-PSS digital signatures that can only be created by the holder of the corresponding private key, providing cryptographic proof of origin.

---

## 8. Challenges and Solutions

### Secure Random Number Generation

Early development revealed inconsistencies in random number generation across different platforms. The solution was to exclusively use `os.urandom()`, which the cryptography library also uses internally, ensuring consistent behavior and appropriate entropy sources across operating systems.

### Certificate Handling Complexity

X.509 certificate creation involves numerous fields and extensions that must be correctly configured. Rather than implementing certificate parsing from scratch, the project leverages the cryptography library's comprehensive certificate builder interface, which handles encoding details and validates field values.

### Password-Protected Key Storage

Balancing security with usability required careful consideration. Storing unencrypted keys is unacceptable, but requiring extremely long passwords creates usability problems. The solution uses PBKDF2 with a high iteration count to make password-based attacks expensive while allowing reasonable password lengths.

### Signature Verification Ordering

When verifying encrypted and signed documents, the order of operations matters. The signature must be verified over the hash of the plaintext, not the ciphertext. This required careful design of the signed document structure to include the plaintext hash while optionally encrypting the content itself.

---

## 9. Conclusion and Future Improvements

SecureSign successfully demonstrates how established cryptographic primitives combine to solve real-world document security problems. The implementation provides a complete workflow from key generation through certificate issuance, document signing, and verification. Each of the four core security properties receives concrete implementation through appropriate algorithms and protocols.

Future development could extend the system in several directions. Adding support for multiple signature types would allow documents to require approval from several parties. Implementing timestamp authority integration would provide third-party proof of when signatures were created. Developing a graphical user interface would make the system accessible to non-technical users. Adding support for hardware security modules would enable deployment in high-security environments where keys must never exist in extractable form.

The modular architecture supports these extensions without requiring fundamental redesign. Each cryptographic component is isolated behind clean interfaces, allowing individual algorithms to be upgraded or replaced as cryptographic best practices evolve. This design philosophy, combined with exclusive use of established libraries rather than custom implementations, positions the system for long-term maintainability and security.

---

**Word Count: Approximately 2,450 words**
