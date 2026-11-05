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

## 🚀 Supabase Setup Guide

### 1. Create a Supabase Project
1. Log in to your [Supabase Dashboard](https://supabase.com/dashboard).
2. Click **New Project** and choose a name and database password.

### 2. Configure Storage Bucket and RLS Policies
1. In the Supabase Dashboard, navigate to the **SQL Editor** (terminal icon in sidebar).
2. Click **New Query**.
3. Open [`supabase-setup.sql`](file:///d:/cybertitans/zk-kyc/supabase-setup.sql) in this repository, copy its contents, paste them into the editor, and click **Run**.
4. This script automatically:
   - Creates the private storage bucket: `encrypted-documents`.
   - Adds RLS policies for `INSERT`, `SELECT`, `DELETE`, and `UPDATE` on `storage.objects`.
   - Enforces path isolation so each user can only access their own folder: `{auth.uid}/*`.

### 3. Configure Authentication
1. Go to **Authentication** -> **Providers** -> **Email**:
   - Ensure Email provider is enabled.
   - For rapid local testing without waiting for verification emails, you can toggle off **Confirm email** in **Authentication** -> **URL Configuration / Email Templates** (or under Auth settings).
2. *(Optional)* To allow guest uploads without registering an email:
   - Go to **Authentication** -> **Sign In / Up** -> **Anonymous Sign-ins**.
   - Toggle **Enable Anonymous Sign-ins** to **ON**.

### 4. Connect Your Credentials
1. Go to **Project Settings** -> **API**.
2. Copy your **Project URL** and **anon public** API key.
3. Open [`supabase-config.js`](file:///d:/cybertitans/zk-kyc/supabase-config.js) and paste them:
   ```javascript
   export const supabaseConfig = {
     url: "https://your-project-id.supabase.co",
     anonKey: "YOUR_SUPABASE_ANON_KEY",
     bucketName: "encrypted-documents",
   };
   ```

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
