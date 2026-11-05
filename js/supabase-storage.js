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

/* ==================== Storage Operations ==================== */

/**
 * Uploads an encrypted .zkkyc/.enc container Blob to Supabase Storage.
 * Destination path: {user_id}/{document_id}.zkkyc
 *
 * Uses XMLHttpRequest for accurate byte-level progress reporting and cancellation.
 * Upsert is disabled to prevent accidental overwriting of existing encrypted documents.
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

