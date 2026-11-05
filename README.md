# ZERO-KNOWLEDGE KYC — Client-Side Document Encryption

A client-side document encryption and cloud storage web application. Sensitive KYC documents (PDF, JPG, PNG, WebP) are encrypted entirely in the client browser with **AES-256-GCM** using a key derived via **PBKDF2-SHA256** (600,000 iterations). Only ciphertext is transmitted to cloud storage. The server never receives original files, passphrases, or encryption keys.

---

## ⚠ Security Limitations

Please read these points before using this application:
- **No Independent Audit**: The application has not undergone an independent security audit. Use at your own risk.
- **Passphrase Responsibility**: Users are solely responsible for protecting their passphrases.
- **No Recovery Mechanism**: **Lost passphrases cannot be recovered**, and encrypted documents will become permanently unreadable.
- **Weak Passphrases**: Weak or short passphrases may be vulnerable to guessing and dictionary attacks, even if they pass the breach database check.
- **Environment Dependency**: Security also depends on the user's device, browser, and operating system integrity.
- **Metadata Visibility**: Cloud storage contains encrypted documents only, but metadata such as file sizes and upload timestamps may still reveal information.
- **Testing Recommendation**: Users should test with dummy, non-sensitive documents until the application has been independently reviewed.

---

## 🔒 Security Architecture

- **Client-Side Symmetric Encryption**: AES-256-GCM with a 256-bit key and 12-byte random IV per encryption. 128-bit authentication tag mathematically guarantees data integrity.
- **Key Derivation (OWASP Compliant)**: PBKDF2 with HMAC-SHA256, 600,000 iterations, and a cryptographically secure 16-byte random salt generated per document.
- **Memory Hygiene**: CryptoKeys are created non-extractable using the Web Crypto API. Key buffers and decrypted plaintext buffers are explicitly zeroed out (`buffer.fill(0)`) upon view changes or clearing.
- **Breach Checking**: Have I Been Pwned API integration using the k-anonymity model (only the first 5 characters of SHA-1 hash are sent).
- **Encrypted Container Format (`.zkkyc`)**:
  - Magic bytes: `ZKKYC1` (6 bytes)
  - Header length: 4-byte big-endian unsigned integer
  - JSON Header: authenticated as AES-GCM Additional Authenticated Data (AAD), storing `docId`, `salt`, `iv`, `iterations`, `alg`, `kdf`, `hash`.
  - Ciphertext Payload: contains original file bytes, MIME type, and filename.
- **Cloud Storage (Supabase)**: Private bucket `encrypted-documents` with strict Row-Level Security (RLS) isolating files under `{user_id}/{document_id}.zkkyc`.

---



## 💻 Running the Application Locally

1. Start a local HTTP server from the project directory:
   ```bash
   python -m http.server 8000
   ```
2. Open your browser and navigate to:
   ```
   http://localhost:8000
   ```

---

## 🧪 Verification & Security Walkthrough

### 1. Verify Cloud Ciphertext (Supabase Console)
1. In the web app, navigate to **Encrypt**, select a document (e.g. an image `id.png`), enter a 12+ character passphrase, and click **Encrypt Document**.
2. Sign in or click **Continue with Anonymous Session** when prompted.
3. Click **Upload to Supabase Storage**.
4. Open your **Supabase Dashboard** -> **Storage** -> `encrypted-documents`.
5. Browse into the folder: `{user_id}/`.
6. Click on the `.zkkyc` file:
   - Trying to preview the file will show that it is **unreadable / corrupted**.
   - Inspecting the raw bytes reveals only binary ciphertext starting with the header magic `ZKKYC1`.
   - Plaintext KYC images, documents, and personal details are completely unreadable on Supabase servers.

### 2. Verify Decryption
1. Go to **My Vault** or **Decrypt** in the web app.
2. Select or retrieve your encrypted container from Supabase.
3. Enter the correct passphrase: the file will decrypt in browser memory and prompt for download of the original file.
4. Try modifying a single character or entering the wrong passphrase: the AES-256-GCM authentication tag check will immediately reject the decryption, ensuring zero corrupted or tampered output.
