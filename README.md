# SecureKey - SLH-DSA (SPHINCS+) Post-Quantum Cryptography & Key Management CLI

Implementation of NIST FIPS 205 (Stateless Hash-Based Digital Signature Standard / SLH-DSA / SPHINCS+) Post-Quantum Key Management & Digital Signature Suite in Python and Rust.

## 🚀 Features
- **NIST FIPS 205 Standard Compliant**: Stateless Hash-Based Digital Signatures (SLH-DSA).
- **No RSA / ECC Dependency**: Designed specifically for post-quantum security requirements.
- **Multiple Parameter Sets**: Supports `sha2-128f`, `sha2-128s`, `sha2-192f`, `sha2-192s`, `sha2-256f`, `sha2-256s`, and SHAKE parameter variants.
- **Full Key Lifecycle Support**: Key generation, file signing, verification, metadata inspection, PEM export, rotation, and secure zeroization shredding (`destroy`).

## 💻 Usage

### 1. Key Generation
```bash
python securekey.py generate --param-set sha2-128f --name securekey
```

### 2. Sign File
```bash
python securekey.py sign --key securekey_private.key --file SLH-DSA.md --out SLH-DSA.md.sig
```

### 3. Verify Signature
```bash
python securekey.py verify --pubkey securekey_public.pub --file SLH-DSA.md --sig SLH-DSA.md.sig
```

### 4. Export Public Key
```bash
python securekey.py export --pubkey securekey_public.pub --format pem
```

### 5. Secure Key Destruction
```bash
python securekey.py destroy --key securekey_private.key
```
