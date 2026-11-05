/**
 * key-derivation.js - Phase 2
 * Derives a non-extractable AES-256-GCM key from a passphrase using
 * PBKDF2 with SHA-256 via the Web Crypto API.
 *
 * Security notes:
 *  - The derived key is created with extractable = false, so JavaScript
 *    cannot read its raw bytes. It only lives in browser memory.
 *  - The passphrase and key are never logged or put in browser storage.
 *  - JavaScript strings are immutable and cannot be reliably wiped from
 *    memory; this is a known limitation of browser-based crypto.
 */

export const KDF_NAME = "PBKDF2";
export const KDF_HASH = "SHA-256";
export const KDF_ITERATIONS = 600000; // OWASP-recommended minimum for PBKDF2-HMAC-SHA256
export const MIN_ITERATIONS = 600000;
export const MAX_ITERATIONS = 10000000; // upper bound so tampered metadata can't freeze the tab
export const SALT_BYTES = 16;
export const KEY_BITS = 256;

/** Throws if Web Crypto is unavailable (e.g. page served over plain http on a non-localhost host). */
function assertCryptoAvailable() {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error("Web Crypto API is unavailable. Use HTTPS or http://localhost.");
  }
}

/** Returns a fresh random 16-byte salt. Use one per document. */
export function generateSalt() {
  assertCryptoAvailable();
  return crypto.getRandomValues(new Uint8Array(SALT_BYTES));
}

/**
 * Derives a non-extractable AES-GCM-256 key.
 * @param {string} passphrase
 * @param {Uint8Array} salt 16 random bytes
 * @param {number} [iterations=KDF_ITERATIONS]
 * @returns {Promise<CryptoKey>}
 */
export async function deriveKey(passphrase, salt, iterations = KDF_ITERATIONS) {
  assertCryptoAvailable();

  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("A passphrase is required.");
  }
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) {
    throw new Error(`Salt must be a Uint8Array of ${SALT_BYTES} bytes.`);
  }
  if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new Error(`Iteration count must be between ${MIN_ITERATIONS} and ${MAX_ITERATIONS}.`);
  }

  // NFKC normalization so the same passphrase typed on different devices
  // or keyboards produces identical bytes.
  const passBytes = new TextEncoder().encode(passphrase.normalize("NFKC"));

  try {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      passBytes,
      { name: KDF_NAME },
      false, // base key is not extractable
      ["deriveKey"]
    );

    return await crypto.subtle.deriveKey(
      { name: KDF_NAME, salt, iterations, hash: KDF_HASH },
      baseKey,
      { name: "AES-GCM", length: KEY_BITS },
      false, // derived key is NON-extractable
      ["encrypt", "decrypt"]
    );
  } finally {
    passBytes.fill(0); // best-effort wipe of our copy of the passphrase bytes
  }
}

/**
 * Self-test you can run from the browser console:
 *   import('/js/key-derivation.js').then(m => m.runSelfTest())
 * Uses a throwaway test passphrase and takes a few seconds (4 derivations).
 */
export async function runSelfTest() {
  const results = [];
  const check = (name, pass) => {
    results.push({ test: name, result: pass ? "PASS" : "FAIL" });
  };

  const pass = "test-passphrase-for-self-test-only";
  const salt = generateSalt();
  const otherSalt = generateSalt();
  const probe = new TextEncoder().encode("probe");
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const keyA = await deriveKey(pass, salt);
  const keyB = await deriveKey(pass, salt);
  const keyWrongSalt = await deriveKey(pass, otherSalt);
  const keyWrongPass = await deriveKey(pass + "x", salt);

  // Key properties
  check("key is non-extractable", keyA.extractable === false);
  check("key is AES-GCM 256", keyA.algorithm.name === "AES-GCM" && keyA.algorithm.length === 256);
  check("key usages are encrypt+decrypt", keyA.usages.includes("encrypt") && keyA.usages.includes("decrypt"));

  let exportBlocked = false;
  try {
    await crypto.subtle.exportKey("raw", keyA);
  } catch {
    exportBlocked = true;
  }
  check("exportKey is blocked", exportBlocked);

  // Determinism: same inputs -> same key (proved by cross-decryption)
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, keyA, probe);
  let sameInputsWork = false;
  try {
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, keyB, cipher);
    sameInputsWork = true;
  } catch { /* stays false */ }
  check("same passphrase + salt gives the same key", sameInputsWork);

  const fails = async (key) => {
    try {
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
      return false;
    } catch {
      return true;
    }
  };
  check("different salt gives a different key", await fails(keyWrongSalt));
  check("different passphrase gives a different key", await fails(keyWrongPass));

  // Input validation
  const rejects = async (fn) => {
    try { await fn(); return false; } catch { return true; }
  };
  check("rejects empty passphrase", await rejects(() => deriveKey("", salt)));
  check("rejects 8-byte salt", await rejects(() => deriveKey(pass, new Uint8Array(8))));
  check("rejects low iteration count", await rejects(() => deriveKey(pass, salt, 1000)));

  console.table(results);
  const allPassed = results.every((r) => r.result === "PASS");
  console.log(allPassed ? "All key-derivation tests passed." : "Some tests FAILED.");
  return allPassed;
}
