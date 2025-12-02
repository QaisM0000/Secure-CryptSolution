# SecureSign: Presentation Outline
## Secure Document Signing and Verification Service

**Duration: 10-12 minutes**

---

## Slide 1: Title Slide (30 seconds)

### SecureSign
**A Secure Document Signing and Verification Service**

- Team Members: [Names]
- Course: Cryptography
- Date: [Presentation Date]

---

## Slide 2: Problem Statement (1 minute)

### The Challenge of Digital Document Trust

**Key Points to Cover:**
- Digital documents are now the primary medium for business and legal communications
- Physical signatures cannot be directly translated to digital environments
- Documents traveling across networks face multiple threats:
  - Interception and unauthorized reading
  - Modification of content in transit
  - Forgery and impersonation
  - Denial of having sent a document

**Visual Suggestion:** Diagram showing document traveling through untrusted network with threat actors

---

## Slide 3: Project Objectives (45 seconds)

### Security Properties We Address

| Property | What It Means | How We Achieve It |
|----------|--------------|-------------------|
| **Confidentiality** | Only intended recipients can read | AES-256-GCM encryption |
| **Integrity** | Detect any modifications | SHA-256 hashing |
| **Authentication** | Verify sender identity | X.509 certificates |
| **Non-repudiation** | Prove document origin | RSA-PSS signatures |

---

## Slide 4: System Architecture (1.5 minutes)

### Layered Design

**Key Points to Cover:**
- Four-layer architecture separating concerns
- Cryptographic Core: Fundamental operations (AES, RSA, SHA-256)
- Key Management: Secure storage and lifecycle
- Certificate Authority: Identity binding and validation
- Application Layer: User-facing CLI interface

**Visual Suggestion:** The architecture diagram from the technical report

**Speaking Notes:**
- Explain why modular design matters for security
- Mention that each layer can be independently tested and updated
- Highlight that this mirrors real-world security architectures

---

## Slide 5: Cryptographic Algorithms (1.5 minutes)

### Our Cryptographic Toolkit

**Symmetric Encryption: AES-256-GCM**
- Industry standard authenticated encryption
- Provides both confidentiality and integrity
- 256-bit keys for quantum resistance margin

**Asymmetric Encryption: RSA-2048 with OAEP**
- Key exchange for hybrid encryption
- Digital signatures with PSS padding
- Widely supported and well-understood

**Hashing: SHA-256**
- 256-bit collision-resistant digests
- Forms basis for integrity verification

**Speaking Notes:**
- Emphasize we use established algorithms, not custom cryptography
- Explain why GCM mode was chosen over CBC
- Mention OAEP and PSS as modern padding schemes

---

## Slide 6: Key Management Strategy (1 minute)

### Protecting the Keys to the Kingdom

**Key Generation**
- Cryptographically secure random generation
- 2048-bit RSA keys with standard public exponent

**Key Storage**
- Never stored in plaintext
- PBKDF2 with 480,000 iterations for password derivation
- Encrypted PKCS#8 PEM format

**Key Lifecycle**
- Registry tracks creation, usage, and revocation
- File permissions restrict access

**Visual Suggestion:** Diagram showing key protection layers

---

## Slide 7: Document Signing Workflow (1 minute)

### How Signing Works

```
Document → SHA-256 Hash → RSA-PSS Sign → Bundle with Certificate
                ↓
        Optional: Encrypt content for recipient
                ↓
        Output: Signed Document (JSON format)
```

**Key Points:**
- Hash computed on original content
- Signature created with signer's private key
- Certificate included for verification
- Optional encryption adds confidentiality

---

## Slide 8: Live Demonstration (2-3 minutes)

### Demo Script

**1. Initialize Certificate Authority**
```bash
python -m src.cli ca init --name "Demo CA" --org "University"
```

**2. Generate User Keys**
```bash
python -m src.cli keys generate --user alice
```

**3. Issue Certificate**
```bash
python -m src.cli ca issue --name "Alice Student" --email alice@edu --key-id [ID]
```

**4. Sign a Document**
```bash
python -m src.cli sign contract.pdf --key-id [ID]
```

**5. Verify the Signature**
```bash
python -m src.cli verify contract.pdf.signed
```

**6. Demonstrate Tampering Detection**
- Modify the signed file
- Show verification failure

**Alternative:** Run the built-in demo command
```bash
python -m src.cli demo
```

---

## Slide 9: Security Analysis (1 minute)

### How We Address Threats

| Threat | Protection |
|--------|-----------|
| Eavesdropping | AES-256-GCM encryption |
| Document modification | SHA-256 hash verification |
| Sender impersonation | Certificate validation |
| Repudiation | RSA-PSS digital signatures |

**Limitations Acknowledged:**
- Self-signed CA, not global PKI
- File-based key storage
- Password strength depends on user

---

## Slide 10: Challenges Encountered (1 minute)

### Technical Hurdles and Solutions

**Challenge 1: Certificate Complexity**
- X.509 has many required fields and extensions
- Solution: Leveraged cryptography library's builder interface

**Challenge 2: Verification Order**
- Must verify signature against plaintext hash, not ciphertext
- Solution: Careful design of signed document structure

**Challenge 3: Secure Key Storage**
- Balance between security and usability
- Solution: High-iteration PBKDF2 allows reasonable passwords

---

## Slide 11: Learning Outcomes (45 seconds)

### What We Learned

**Technical Skills:**
- Practical implementation of cryptographic primitives
- Understanding of PKI and certificate management
- Secure coding practices for handling sensitive data

**Conceptual Understanding:**
- Why custom cryptography is dangerous
- How security properties combine to solve real problems
- Trade-offs between security and usability

**Collaboration:**
- Dividing cryptographic work across team members
- Code review for security-sensitive implementations

---

## Slide 12: Future Improvements (45 seconds)

### Where We Could Go Next

1. **Multi-party Signatures**
   - Documents requiring multiple approvals

2. **Timestamp Authority Integration**
   - Third-party proof of signing time

3. **Graphical Interface**
   - Accessibility for non-technical users

4. **Hardware Security Module Support**
   - Keys that never exist in extractable form

5. **Mobile Application**
   - Sign documents from smartphones

---

## Slide 13: Conclusion (30 seconds)

### Summary

- SecureSign demonstrates practical cryptographic security
- All four security properties implemented with standard algorithms
- Modular architecture enables future extension
- Exclusive use of established libraries ensures security

### Questions?

---

## Appendix: Demo Troubleshooting

**If Demo Fails:**
- Have screenshots ready as backup
- Pre-recorded video as fallback

**Common Issues:**
- Missing dependencies: Run `pip install -r requirements.txt`
- Permission errors: Check key file permissions
- CA not initialized: Run init command first

---

## Appendix: Q&A Preparation

**Likely Questions:**

Q: Why RSA instead of elliptic curves?
A: RSA is more widely understood and supported. ECC would be a valid alternative with smaller keys.

Q: How does this compare to existing solutions like DocuSign?
A: Commercial solutions add workflow management, legal compliance, and cloud infrastructure. Our focus is demonstrating core cryptographic principles.

Q: What happens if the CA private key is compromised?
A: All certificates become untrustworthy. Production systems use offline CAs and hardware security modules.

Q: Why not use blockchain?
A: Blockchain adds complexity without clear benefits for this use case. Traditional PKI is simpler and equally secure for document signing.

Q: How would this scale to many users?
A: Current implementation is file-based. Production would use databases and potentially distributed key management.
