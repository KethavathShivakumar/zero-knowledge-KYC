/**
 * supabase-storage.js - Supabase Storage & Authentication Module
 *
 * Implements:
 * - Supabase client initialization (reusable singleton).
 * - User authentication (Email/Password, Anonymous Session, Sign Out, Auth State Listener).
 * - Direct authenticated upload to private bucket 'encrypted-documents'.
 * - Accurate byte-level progress reporting (0-100%) and upload cancellation.
 * - Listing authenticated user's encrypted documents under {user_id}/{document_id}.zkkyc.
 * - Downloading and deleting encrypted documents.
 *
 * Security:
 * - NEVER uploads original documents, passphrases, or encryption keys.
 * - Files stored only as AES-256-GCM ciphertext in private bucket.
 * - User folder isolation enforced via Row-Level Security (RLS).
 */

import { supabaseConfig, isSupabaseConfigured } from "../supabase-config.js";

let supabaseClient = null;

/**
 * Initializes and returns the Supabase client instance.
 * Reuses the singleton instance across operations.
 */
export async function getSupabase() {
  if (!isSupabaseConfigured()) {
    throw new Error("Supabase is not configured. Please fill in your project URL and anon key in supabase-config.js.");
  }

  if (supabaseClient) {
    return supabaseClient;
  }

  // Check if Supabase UMD is loaded on window (via js/vendor/supabase.js)
  let createClient = globalThis.supabase?.createClient;

  if (!createClient) {
    throw new Error("Failed to load Supabase SDK. Ensure js/vendor/supabase.js is loaded before this module.");
  }

  supabaseClient = createClient(supabaseConfig.url, supabaseConfig.anonKey, {
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
    },
  });

  return supabaseClient;
}

/* ==================== Authentication ==================== */

/**
 * Retrieves the currently authenticated Supabase user or null.
 * @returns {Promise<any|null>}
 */
export async function getCurrentUser() {
  if (!isSupabaseConfigured()) return null;
  try {
    const client = await getSupabase();
    const { data: { user } } = await client.auth.getUser();
    return user;
  } catch {
    return null;
  }
}

/**
 * Signs in an existing user with email and password.
 * @param {string} email
 * @param {string} password
 * @returns {Promise<any>}
 */
export async function signInWithEmail(email, password) {
  const client = await getSupabase();
  const { data, error } = await client.auth.signInWithPassword({ email, password });
  if (error) throw error;
  return data;
}

/**
 * Signs up a new user with email and password.
 * @param {string} email
 * @param {string} password
 * @returns {Promise<any>}
 */
export async function signUpWithEmail(email, password) {
  const client = await getSupabase();
  const { data, error } = await client.auth.signUp({ email, password });
  if (error) throw error;
  return data;
}

/**
 * Creates or restores an anonymous session for zero-friction testing.
 * @returns {Promise<any>}
 */
export async function signInAnonymously() {
  const client = await getSupabase();
  if (typeof client.auth.signInAnonymously === "function") {
    const { data, error } = await client.auth.signInAnonymously();
    if (error) throw error;
    return data;
  }
  throw new Error("Anonymous sign-in is not enabled in your Supabase Auth settings.");
}

/**
 * Signs out the current user and clears session storage.
 */
export async function signOut() {
  if (!isSupabaseConfigured()) return;
  const client = await getSupabase();
  const { error } = await client.auth.signOut();
  if (error) throw error;
}

/**
 * Subscribes to authentication state changes.
 * @param {function(string, any): void} callback
 */
export async function onAuthStateChange(callback) {
  if (!isSupabaseConfigured()) return;
  try {
    const client = await getSupabase();
    return client.auth.onAuthStateChange(callback);
  } catch {
    // Ignore if not configured yet
  }
}

/* ==================== Multi-Factor Authentication (MFA) ==================== */

/**
 * Retrieves the current user's Authenticator Assurance Level (AAL).
 * @returns {Promise<{currentLevel: 'aal1'|'aal2'|null, nextLevel: 'aal1'|'aal2'|null, currentAuthenticationMethods: string[]}>}
 */
export async function getAssuranceLevel() {
  if (!isSupabaseConfigured()) {
    return { currentLevel: null, nextLevel: null, currentAuthenticationMethods: [] };
  }
  const client = await getSupabase();
  const { data, error } = await client.auth.mfa.getAuthenticatorAssuranceLevel();
  if (error) throw error;
  return data;
}

/**
 * Lists all MFA factors enrolled for the current authenticated user.
 * @returns {Promise<{all: Array<any>, totp: Array<any>}>}
 */
export async function listMFAFactors() {
  const client = await getSupabase();
  const { data, error } = await client.auth.mfa.listFactors();
  if (error) throw error;
  return data || { all: [], totp: [] };
}

/**
 * Starts TOTP factor enrollment with Supabase.
 * Returns factor ID, manual secret, and QR code SVG.
 * @param {string} [friendlyName]
 * @returns {Promise<{id: string, type: 'totp', totp: {qr_code: string, secret: string, uri: string}}>}
 */
export async function enrollTOTPFactor(friendlyName = "Authenticator") {
  const client = await getSupabase();
  const { data, error } = await client.auth.mfa.enroll({
    factorType: "totp",
    issuer: "ZeroKnowledgeKYC",
    friendlyName,
  });
  if (error) throw error;
  return data;
}

/**
 * Creates an MFA challenge for an enrolled factor.
 * @param {string} factorId
 * @returns {Promise<{id: string, type: string}>}
 */
export async function createMFAChallenge(factorId) {
  if (!factorId || typeof factorId !== "string") {
    throw new Error("A valid factor ID is required.");
  }
  const client = await getSupabase();
  const { data, error } = await client.auth.mfa.challenge({ factorId });
  if (error) throw error;
  return data;
}

/**
 * Verifies an MFA challenge using the 6-digit code.
 * Upgrades the current session to AAL2 upon successful verification.
 * @param {string} factorId
 * @param {string} challengeId
 * @param {string} code 6-digit TOTP code
 * @returns {Promise<any>}
 */
export async function verifyMFAChallenge(factorId, challengeId, code) {
  if (!factorId || !challengeId) {
    throw new Error("Factor ID and challenge ID are required.");
  }
  const cleanCode = String(code || "").trim();
  if (!/^\d{6}$/.test(cleanCode)) {
    throw new Error("Verification code must be exactly 6 digits.");
  }

  const client = await getSupabase();
  const { data, error } = await client.auth.mfa.verify({
    factorId,
    challengeId,
    code: cleanCode,
  });
  if (error) throw error;
  return data;
}

/**
 * Challenges and verifies a TOTP code for a factor.
 * Upgrades the current session to AAL2 upon successful verification.
 * @param {string} factorId
 * @param {string} code 6-digit TOTP code
 * @returns {Promise<any>}
 */
export async function challengeAndVerifyMFA(factorId, code) {
  const challenge = await createMFAChallenge(factorId);
  return await verifyMFAChallenge(factorId, challenge.id, code);
}

/**
 * Unenrolls (removes) an MFA factor by factor ID.
 * @param {string} factorId
 * @returns {Promise<any>}
 */
export async function unenrollMFAFactor(factorId) {
  if (!factorId || typeof factorId !== "string") {
    throw new Error("A valid factor ID is required to unenroll.");
  }
  const client = await getSupabase();
  const { data, error } = await client.auth.mfa.unenroll({ factorId });
  if (error) throw error;
  return data;
}

/**
 * Asserts that the current session satisfies AAL requirements.
 * If MFA is enrolled (nextLevel === 'aal2') but not verified (currentLevel !== 'aal2'),
 * throws an Error preventing access to private vault data.
 */
export async function assertAALRequirement() {
  const aal = await getAssuranceLevel();
  if (aal && aal.nextLevel === "aal2" && aal.currentLevel !== "aal2") {
    const err = new Error("MFA verification required (AAL2). Please complete your authenticator verification to access your encrypted vault.");
    err.code = "mfa_required";
    throw err;
  }
}

/* ==================== Storage Operations ==================== */

/**
 * Uploads an encrypted .zkkyc/.enc container Blob to Supabase Storage.
 * Destination path: {user_id}/{document_id}.zkkyc
 *
 * Uses XMLHttpRequest for accurate byte-level progress reporting and cancellation.
 * Upsert is disabled to prevent accidental overwriting of existing encrypted documents.
 * Requires AAL2 verification if the user account has MFA active.
 *
 * @param {Blob} encryptedBlob - Already-encrypted container Blob.
 * @param {object} meta - Metadata containing { docId }.
 * @param {function(number): void} [onProgress] - Progress callback (0-100%).
 * @param {function(any): void} [onTaskCreated] - Callback receiving the abort controller/task.
 * @returns {Promise<{docId: string, path: string}>}
 */
export async function uploadEncryptedDocument(encryptedBlob, meta, onProgress, onTaskCreated) {
  if (!(encryptedBlob instanceof Blob)) {
    throw new Error("A valid encrypted Blob is required for upload.");
  }
  if (!meta || typeof meta.docId !== "string") {
    throw new Error("Valid document metadata is required.");
  }

  await assertAALRequirement();

  const client = await getSupabase();
  let session = (await client.auth.getSession()).data.session;

  // If no user is logged in, try anonymous sign-in or prompt
  if (!session) {
    try {
      const anon = await signInAnonymously();
      session = anon.session;
    } catch {
      throw new Error("Please sign in or register to upload encrypted documents to your cloud vault.");
    }
  }

  const userId = session.user.id;
  const filePath = `${userId}/${meta.docId}.zkkyc`;
  const uploadUrl = `${supabaseConfig.url}/storage/v1/object/${supabaseConfig.bucketName}/${filePath}`;

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();

    if (typeof onTaskCreated === "function") {
      onTaskCreated({
        cancel: () => xhr.abort(),
      });
    }

    xhr.open("POST", uploadUrl, true);
    xhr.setRequestHeader("Authorization", `Bearer ${session.access_token}`);
    xhr.setRequestHeader("apikey", supabaseConfig.anonKey);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    // x-upsert is intentionally omitted (defaults to false) to prevent overwriting existing documents

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable && typeof onProgress === "function") {
        const percent = Math.min(100, Math.max(0, (event.loaded / event.total) * 100));
        onProgress(percent);
      }
    };

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve({
          docId: meta.docId,
          path: filePath,
        });
      } else {
        let errorMsg = `Upload failed (Status ${xhr.status})`;
        try {
          const res = JSON.parse(xhr.responseText);
          if (res.message || res.error) errorMsg = res.message || res.error;
        } catch { /* ignore */ }
        reject(new Error(errorMsg));
      }
    };

    xhr.onerror = () => {
      reject(new Error("Network error connecting to Supabase Storage."));
    };

    xhr.onabort = () => {
      const err = new Error("Upload was cancelled.");
      err.code = "storage/canceled";
      reject(err);
    };

    xhr.send(encryptedBlob);
  });
}

/**
 * Lists the encrypted documents stored in Supabase Storage for the current user.
 * Reads from: {user_id}/
 * @returns {Promise<Array<{docId: string, name: string, size: number, updated: string}>>}
 */
export async function listStoredDocuments() {
  await assertAALRequirement();
  const client = await getSupabase();
  const session = (await client.auth.getSession()).data.session;
  if (!session) return [];

  const userId = session.user.id;
  const folderPath = `${userId}`;

  const { data, error } = await client.storage
    .from(supabaseConfig.bucketName)
    .list(folderPath, {
      limit: 100,
      sortBy: { column: "created_at", order: "desc" },
    });

  if (error) throw error;
  if (!data) return [];

  return data
    .filter((item) => item.name && item.name !== ".emptyFolderPlaceholder")
    .map((item) => {
      const docId = item.name.replace(/\.(enc|zkkyc)$/i, "");
      return {
        docId,
        name: item.name,
        size: item.metadata?.size || item.size || 0,
        updated: item.updated_at || item.created_at || "",
      };
    });
}

/**
 * Downloads an encrypted document from Supabase Storage by document ID.
 * Retrieves: {user_id}/{docId}.zkkyc
 *
 * @param {string} docId - The UUID docId.
 * @returns {Promise<{bytes: Uint8Array, docId: string}>}
 */
export async function downloadStoredDocument(docId) {
  if (!docId || typeof docId !== "string") {
    throw new Error("Invalid document ID.");
  }

  await assertAALRequirement();

  const client = await getSupabase();
  const session = (await client.auth.getSession()).data.session;
  if (!session) {
    throw new Error("You must be signed in to download files.");
  }

  const userId = session.user.id;

  // Try .zkkyc first, fallback to .enc for backward compatibility
  let filePath = `${userId}/${docId}.zkkyc`;
  let { data, error } = await client.storage.from(supabaseConfig.bucketName).download(filePath);

  if (error) {
    filePath = `${userId}/${docId}.enc`;
    const res = await client.storage.from(supabaseConfig.bucketName).download(filePath);
    if (res.error) throw error; // throw original or fallback error
    data = res.data;
  }

  const arrayBuffer = await data.arrayBuffer();
  return {
    bytes: new Uint8Array(arrayBuffer),
    docId,
  };
}

/**
 * Deletes an encrypted document from Supabase Storage.
 * @param {string} docId - The document identifier.
 * @returns {Promise<{docId: string, success: boolean}>}
 */
export async function deleteStoredDocument(docId) {
  if (!docId || typeof docId !== "string") {
    throw new Error("Invalid document ID.");
  }

  await assertAALRequirement();

  const client = await getSupabase();
  const session = (await client.auth.getSession()).data.session;
  if (!session) {
    throw new Error("You must be signed in to delete files.");
  }

  const userId = session.user.id;
  const paths = [
    `${userId}/${docId}.zkkyc`,
    `${userId}/${docId}.enc`,
  ];

  const { error } = await client.storage.from(supabaseConfig.bucketName).remove(paths);
  if (error) throw error;

  return { docId, success: true };
}

/**
 * Formats Supabase and HTTP errors into clear, friendly messages without leaking internals.
 * @param {any} error
 * @returns {string}
 */
export function friendlySupabaseError(error) {
  if (!error) return "An unknown error occurred.";
  const msg = error.message || String(error);

  if (msg.includes("storage/canceled") || error.code === "storage/canceled") {
    return "Upload was cancelled.";
  }
  if (msg.includes("Invalid login credentials")) {
    return "Incorrect email or password. Please try again.";
  }
  if (msg.includes("Invalid TOTP code") || msg.includes("invalid totp") || msg.includes("Invalid code") || msg.includes("invalid_code")) {
    return "Invalid verification code. Please check your authenticator app and try again.";
  }
  if (msg.includes("factor") && (msg.includes("exceed") || msg.includes("maximum") || msg.includes("limit"))) {
    return "Maximum number of enrolled factors reached. Unenroll an existing factor to add a new one.";
  }
  if (msg.includes("mfa_required") || msg.includes("MFA verification required")) {
    return "Two-factor verification (AAL2) required. Please enter your authenticator code to access this feature.";
  }
  if (msg.includes("Email not confirmed")) {
    return "Please confirm your email address before signing in, or disable email confirmation in Supabase Auth settings.";
  }
  if (msg.includes("Bucket not found") || msg.includes("bucket_not_found")) {
    return "The 'encrypted-documents' bucket was not found. Please run 'supabase-setup.sql' in your Supabase SQL Editor to create the bucket.";
  }
  if (msg.includes("row-level security") || msg.includes("RLS") || msg.includes("Access denied") || msg.includes("403")) {
    return "Storage access denied by Supabase RLS policies. Please run 'supabase-setup.sql' in your Supabase SQL Editor to create the bucket and apply RLS policies.";
  }
  if (msg.includes("already exists") || msg.includes("Duplicate") || msg.includes("409")) {
    return "A document with this ID already exists in your vault. Each encrypted document receives a unique ID automatically.";
  }
  if (msg.includes("supabase-config.js")) {
    return msg;
  }
  return msg || "An error occurred while communicating with Supabase.";
}

