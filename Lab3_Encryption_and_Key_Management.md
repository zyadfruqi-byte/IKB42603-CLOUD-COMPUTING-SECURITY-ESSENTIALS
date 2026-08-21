# Lab 3 Report: Data Protection — Encryption & Key Management

**Prepared by:** [Your Full Name]
**Course:** IKB42603 Cloud Computing Security Essentials
**Date:** [DD/MM/YYYY]
**Environment:** [e.g. Kali Linux VM / Docker / LocalStack]

---

## 1. Executive Summary

This lab demonstrated the core techniques of data protection in the cloud: symmetric and asymmetric encryption, encryption in transit, key management with a cloud KMS, envelope encryption, per-tenant keys, cryptographic erasure, and integrity verification through hashing. In Session A, AES-256 was used to encrypt and decrypt a sensitive record at rest, RSA key pairs were generated to demonstrate public/private key roles for encryption and digital signatures, and a self-signed TLS certificate was used to protect data in transit. In Session B, a LocalStack KMS was used to create customer master keys, generate and wrap data keys via envelope encryption, provision separate per-tenant keys, and perform cryptographic erasure by disabling/scheduling deletion of a master key so that wrapped data became permanently unrecoverable. Finally, SHA-256 hashing and a simple hash chain were used to demonstrate tamper-evidence.

---

## 2. Environment Setup

[Briefly describe your setup: OS/VM used, Docker version, OpenSSL version, and confirmation that LocalStack (from Lab 1) was running and reachable at `http://localhost:4566`.]

```
docker --version
openssl version
docker ps | grep localstack
```

![Screenshot – environment setup](PASTE_SCREENSHOT_LINK_HERE)

---

## 3. Session A: Encryption Fundamentals

### Task 1: Symmetric Encryption (Data at Rest)

A sample sensitive record was created and encrypted using AES-256 in CBC mode with a passphrase-derived key (PBKDF2). The same key was then used to decrypt the file, and the decrypted output was diffed against the original to confirm successful round-trip encryption.

```
# Create a sample sensitive record
echo 'Patient: Ahmad, Diagnosis: confidential' > record.txt

# Encrypt with AES-256 (prompted for a passphrase = the key)
openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc

# Prove it is unreadable
cat record.enc

# Decrypt back
openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt
diff record.txt record.dec.txt && echo 'MATCH: decryption successful'
```

![Screenshot – AES encrypt/decrypt with MATCH confirmation](PASTE_SCREENSHOT_LINK_HERE)

---

### Task 2: Asymmetric Encryption & Digital Signatures

A 2048-bit RSA key pair was generated. The record was encrypted with the public key and decrypted with the private key, demonstrating confidentiality. The record was then signed with the private key and the signature verified with the public key, demonstrating integrity and origin authentication.

```
# Generate a 2048-bit key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Encrypt with the PUBLIC key, decrypt with the PRIVATE key
openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa
openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt

# Sign with the PRIVATE key; verify with the PUBLIC key
openssl dgst -sha256 -sign private.pem -out record.sig record.txt
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

![Screenshot – RSA signature verify output showing "Verified OK"](PASTE_SCREENSHOT_LINK_HERE)

---

### Task 3: Encryption in Transit (TLS)

A self-signed TLS certificate was generated and used to serve the record over HTTPS on port 8443 via an nginx container. The file was retrieved over the encrypted channel with `curl`, confirming the connection was protected in transit.

```
# Generate a self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
 -days 7 -nodes -subj '/CN=localhost'

# Serve HTTPS on port 8443 using a small container
docker run --rm -d --name tls -p 8443:443 \
 -v $(pwd)/cert.pem:/etc/nginx/cert.pem -v $(pwd)/key.pem:/etc/nginx/key.pem \
 -v $(pwd)/record.txt:/usr/share/nginx/html/record.txt nginx

# Connect over TLS (-k accepts the self-signed cert)
curl -k https://localhost:8443/record.txt
```

![Screenshot – curl output over TLS](PASTE_SCREENSHOT_LINK_HERE)

*End of Session A. The TLS container was stopped (`docker stop tls`). `record.enc`, the RSA keys, and all outputs were retained for the report.*

---

## 4. Session B: Key Management, Envelope Encryption & Erasure

Session B moves from hand-built cryptography to a managed KMS workflow, showing how a cloud KMS controls keys at scale and enables provable deletion.

---

### Task 4: Create and Use a KMS Master Key

A customer master key (CMK) was created in LocalStack's KMS to represent Tenant A's master key. A small secret was then encrypted directly using this key.

```
EP='--endpoint-url=http://localhost:4566'

# Create a customer master key (CMK) and capture its KeyId
aws $EP kms create-key --description 'CCSE tenant-A master key'

# Copy the KeyId from the output into KEY_A
KEY_A=<PASTE_KEYID>

# Encrypt a small secret directly with KMS
aws $EP kms encrypt --key-id $KEY_A --plaintext "$(echo -n 'hello' | base64)" \
 --query CiphertextBlob --output text
```

![Screenshot – KMS KeyId(s) and encrypt output](PASTE_SCREENSHOT_LINK_HERE)

---

### Task 5: Envelope Encryption

Rather than encrypting large data directly with the master key, a data key was generated via KMS, used locally to encrypt the record with AES-256, and then the plaintext copy of the data key was destroyed — leaving only the KMS-wrapped (encrypted) data key on disk.

```
# 5.1 Ask KMS for a data key (returns plaintext + encrypted versions)
aws $EP kms generate-data-key --key-id $KEY_A --key-spec AES_256 \
 --query '[Plaintext,CiphertextBlob]' --output text
# Save column 1 as datakey.b64 (plaintext) and column 2 as datakey.enc (wrapped)

# 5.2 Encrypt the big file locally with the PLAINTEXT data key
base64 -d datakey.b64 > datakey.bin
openssl enc -aes-256-cbc -pbkdf2 -in record.txt -out record.env.enc \
 -pass file:./datakey.bin

# 5.3 Destroy the plaintext data key from disk — keep only the wrapped copy
rm datakey.bin datakey.b64
echo 'Only the KMS-wrapped data key (datakey.enc) remains.'
```

![Screenshot – envelope encryption steps](PASTE_SCREENSHOT_LINK_HERE)

---

### Task 6: Per-Tenant Keys & Cryptographic Erasure

A second, separate master key was created for Tenant B to demonstrate key isolation between tenants. Tenant A's key was then scheduled for deletion and disabled to simulate cryptographic erasure, and an attempt to unwrap Tenant A's data key afterward failed — proving the wrapped data was now permanently unrecoverable.

```
# A separate key for tenant B
aws $EP kms create-key --description 'CCSE tenant-B master key'
KEY_B=<PASTE_KEYID>

# Schedule deletion of tenant A's key (min window)
aws $EP kms schedule-key-deletion --key-id $KEY_A --pending-window-in-days 7

# Disable it immediately to simulate erasure
aws $EP kms disable-key --key-id $KEY_A

# Attempt to unwrap tenant A's data key now — it should FAIL
aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc 2>&1 | head -3
```

![Screenshot – failed kms decrypt after key erasure](PASTE_SCREENSHOT_LINK_HERE)

---

### Task 7: Integrity & Tamper-Evidence

The SHA-256 hash of the original record was computed, then a tampered copy was created and its hash compared to show a mismatch. A simple hash chain was then built, where each log entry's hash incorporates the previous entry's hash, making the log tamper-evident.

```
# Fingerprint the file
sha256sum record.txt

# Tamper with a copy and show the hash changes
cp record.txt tampered.txt; echo 'x' >> tampered.txt
sha256sum record.txt tampered.txt

# Hash chain: each entry includes the previous hash (tamper-evident log)
PREV=0
for line in 'login ok' 'file read' 'export data'; do \
 PREV=$(echo -n "$PREV$line" | sha256sum | cut -d' ' -f1); \
 echo "$line | $PREV"; done
```

![Screenshot – differing SHA-256 hashes and hash chain output](PASTE_SCREENSHOT_LINK_HERE)

---

## 5. Verification Commands Deliverable

The following commands were executed to confirm the final state of the KMS keys and the RSA signature:

```
aws --endpoint-url=http://localhost:4566 kms list-keys
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

![Screenshot – verification command output](PASTE_SCREENSHOT_LINK_HERE)

---

## 6. Short-Answer Questions

### Q1. Compare symmetric and asymmetric encryption: speed, key distribution, and typical use.

Symmetric Encryption: Fast; relies on a single shared key. Key distribution is difficult because the secret must be shared securely beforehand. Used primarily for encrypting large amounts of data at rest (e.g., AES-256).  Asymmetric Encryption: Slower due to complex math; uses a public/private key pair. Key distribution is simple since public keys can be shared freely. Used for key exchanges, digital signatures, and TLS handshakes.

### Q2. Why is key management described as the weakest link, not the algorithm?

Modern algorithms (like AES-256) are mathematically impossible to brute-force with current technology.  Attackers target human error and operational weaknesses—such as hardcoded keys, weak permissions, or unencrypted keys saved on disk—making key handling the primary point of failure.

### Q3. Explain envelope encryption and why only the master key needs hardware-grade protection.

Envelope Encryption: Bulk data is encrypted locally with a temporary Data Key, and that Data Key is then encrypted (wrapped) using a central Master Key in KMS.  Master Key Protection: The plaintext Data Key is deleted immediately after use. Because data cannot be decrypted without unwrapping the Data Key first, securing the Master Key in specialized hardware (HSMs) protects all associated data without needing expensive hardware for every individual file.

### Q4. How does cryptographic erasure achieve provable deletion where overwriting cannot (in the cloud)?

In virtualized cloud storage, data is replicated and spread across drives, making physical overwriting or destruction impossible to perform or verify.  Cryptographic erasure permanently deletes or disables the Master Key that wraps the Data Key. Without the Master Key, the underlying stored data becomes permanent, unrecoverable noise across all storage locations instantly.

### Q5. How does a hash chain make a log tamper-evident (link to tamper-proof logs, Week 6)?

Each log entry's hash is calculated using both its own content and the hash of the entry before it.  If any past log entry is altered, its hash changes, breaking every subsequent link in the chain and immediately flagging tampering during verification.

---

## 7. Deliverables & Checklists Summary

| Session | Task / Verification Objective | Command / Test Executed | Expected Result / Status |
| ------- | ------------------------------ | ------------------------ | ------------------------- |
| **Session A** | Symmetric encryption round-trip | `openssl enc ... && diff record.txt record.dec.txt` | ✅ Pass (MATCH) |
| **Session A** | Asymmetric encrypt/decrypt + signature | `openssl pkeyutl` / `openssl dgst -verify` | ✅ Pass (Verified OK) |
| **Session A** | Encryption in transit | `curl -k https://localhost:8443/record.txt` | ✅ Pass |
| **Session B** | KMS master key creation | `aws kms create-key` | ✅ Pass |
| **Session B** | Envelope encryption | `aws kms generate-data-key` + local `openssl enc` | ✅ Pass |
| **Session B** | Per-tenant key isolation & cryptographic erasure | `aws kms schedule-key-deletion` / `disable-key` / `decrypt` | ✅ Pass (decrypt fails) |
| **Session B** | Integrity / tamper-evidence | `sha256sum` + hash chain loop | ✅ Pass (hash mismatch detected) |

---

### Security Best-Practices Checklist

- [x] **Data encrypted at rest (AES)** and decryption verified.
- [x] **Asymmetric keys used correctly** (encrypt with public, sign with private).
- [x] **Data protected in transit with TLS.**
- [x] **Envelope encryption used**; plaintext data key not left on disk.
- [x] **Per-tenant keys used**; cryptographic erasure demonstrated.
- [x] **Integrity verified** with hashing / hash chain.

---

## 8. Conclusion

During this lab all four stages (key establishment, data security and integrity, destruction/compromising of data) in data life cycles were protected via cryptographic controls. Session A shows the usage in practice: symmetric (AES-256) and asymmetric (RSA) encryption, digital signatures and transport layer protection (TLS). Session B examines management of cloud key material by using local cloud key management by using LocalStack KMS. 

Using envelope encryption for data security both locally, the plain data was encrypted under a disposable data key and the data key protected within a wrap by a KMS master key. 

Per-tenant keys were utilized for securingdata per-client in addition to demonstration of disabling keys showing cryptographic erase thus the storing ciphertext is proveably irretrievable without physical disk access. Through cryptographic hashing (and hash chaining), tamper evidence was proven.