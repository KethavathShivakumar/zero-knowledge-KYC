import {
  KDF_NAME,
  KDF_HASH,
  KDF_ITERATIONS,
  MIN_ITERATIONS,
  MAX_ITERATIONS,
  SALT_BYTES,
  generateSalt,
  deriveKey,
} from "./key-derivation.js";

export const MAGIC = new TextEncoder().encode("ZKKYC1");
export const FORMAT_VERSION = 1;
export const ALGORITHM = "AES-256-GCM";
export const IV_BYTES = 12;
export const TAG_BITS = 128;
const TAG_BYTES = TAG_BITS / 8;
const MAX_HEADER_BYTES = 4096;
const MAX_META_BYTES = 4096;

/* ---------- Base64 helpers ---------- */

export function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/* ---------- Encryption ---------- */

/**
 * Encrypts a File/Blob with AES-256-GCM.
 * A fresh random 12-byte IV is generated for every call.
 *
 * @param {Blob} file
 * @param {CryptoKey} key  non-extractable AES-GCM key from deriveKey()
 * @param {Uint8Array} salt the salt that was used to derive `key`
 * @param {number} [iterations] the iteration count used to derive `key`
 * @returns {Promise<{container: Uint8Array, docId: string}>}
 */
export async function encryptFile(file, key, salt, iterations = KDF_ITERATIONS) {
  if (!(file instanceof Blob)) throw new Error("A file is required.");
  if (!(key instanceof CryptoKey)) throw new Error("A valid encryption key is required.");
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) {
    throw new Error(`Salt must be ${SALT_BYTES} bytes.`);
  }
  if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new Error("Invalid iteration count.");
  }

  const enc = new TextEncoder();
  const fileBytes = new Uint8Array(await file.arrayBuffer());
  const meta = enc.encode(
    JSON.stringify({
      name: file.name || "document",
      type: file.type || "application/octet-stream",
      size: fileBytes.length,
    })
  );

  const plaintext = new Uint8Array(4 + meta.length + fileBytes.length);
  new DataView(plaintext.buffer).setUint32(0, meta.length);
  plaintext.set(meta, 4);
  plaintext.set(fileBytes, 4 + meta.length);

  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES)); // unique per encryption
  const docId = crypto.randomUUID();
  const headerBytes = enc.encode(
    JSON.stringify({
      v: FORMAT_VERSION,
      docId,
      alg: ALGORITHM,
      kdf: KDF_NAME,
      hash: KDF_HASH,
      iterations,
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
    })
  );

  try {
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: headerBytes, tagLength: TAG_BITS },
        key,
        plaintext
      )
    );

    const container = new Uint8Array(MAGIC.length + 4 + headerBytes.length + ciphertext.length);
    container.set(MAGIC, 0);
    new DataView(container.buffer).setUint32(MAGIC.length, headerBytes.length);
    container.set(headerBytes, MAGIC.length + 4);
    container.set(ciphertext, MAGIC.length + 4 + headerBytes.length);

    return { container, docId };
  } finally {
    // Best-effort wipe of plaintext copies held by this function.
    plaintext.fill(0);
    fileBytes.fill(0);
  }
}

/* ---------- Container parsing ---------- */

const INVALID_FILE = "This is not a valid encrypted document.";

/**
 * Validates and parses a container. Does not decrypt anything.
 * @param {Uint8Array} bytes
 */
export function parseContainer(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error(INVALID_FILE);
  const prefix = MAGIC.length + 4;
  if (bytes.length < prefix + TAG_BYTES) throw new Error(INVALID_FILE);

  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC[i]) throw new Error(INVALID_FILE);
  }

  const headerLength = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(MAGIC.length);
  if (headerLength === 0 || headerLength > MAX_HEADER_BYTES || prefix + headerLength + TAG_BYTES > bytes.length) {
    throw new Error(INVALID_FILE);
  }

  const headerBytes = bytes.subarray(prefix, prefix + headerLength);
  let header;
  let salt;
  let iv;
  try {
    header = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(headerBytes));
    salt = base64ToBytes(header.salt);
    iv = base64ToBytes(header.iv);
  } catch {
    throw new Error(INVALID_FILE);
  }

  const valid =
    header &&
    header.v === FORMAT_VERSION &&
    header.alg === ALGORITHM &&
    header.kdf === KDF_NAME &&
    header.hash === KDF_HASH &&
    typeof header.docId === "string" &&
    header.docId.length === 36 &&
    Number.isInteger(header.iterations) &&
    header.iterations >= MIN_ITERATIONS &&
    header.iterations <= MAX_ITERATIONS &&
    salt.length === SALT_BYTES &&
    iv.length === IV_BYTES;
  if (!valid) throw new Error(INVALID_FILE);

  return {
    header,
    docId: header.docId,
    salt,
    iv,
    iterations: header.iterations,
    headerBytes,
    headerOffset: prefix,
    ciphertext: bytes.subarray(prefix + headerLength),
  };
}

/* ---------- Decryption (used by the self-test now; wired into the UI in Phase 4) ---------- */

/**
 * Decrypts a container with an already-derived key.
 * @returns {Promise<{name: string, type: string, size: number, data: Uint8Array}>}
 */
export async function decryptContainer(bytes, key) {
  const parsed = parseContainer(bytes);

  let plaintext;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: parsed.iv, additionalData: parsed.headerBytes, tagLength: TAG_BITS },
        key,
        parsed.ciphertext
      )
    );
  } catch {
    throw new Error("Decryption failed: wrong passphrase, or the file was modified.");
  }

  if (plaintext.length < 4) throw new Error(INVALID_FILE);
  const metaLength = new DataView(plaintext.buffer).getUint32(0);
  if (metaLength === 0 || metaLength > MAX_META_BYTES || 4 + metaLength > plaintext.length) {
    throw new Error(INVALID_FILE);
  }

  let meta;
  try {
    meta = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext.subarray(4, 4 + metaLength)));
  } catch {
    throw new Error(INVALID_FILE);
  }

  const data = plaintext.slice(4 + metaLength);
  if (typeof meta.name !== "string" || typeof meta.type !== "string" || meta.size !== data.length) {
    throw new Error(INVALID_FILE);
  }
  plaintext.fill(0);
  return { name: meta.name, type: meta.type, size: meta.size, data };
}

/** Wraps a container in a Blob suitable for download or upload. */
export function containerToBlob(container) {
  return new Blob([container], { type: "application/octet-stream" });
}

/* ---------- Self-test ---------- */

function containsSubarray(haystack, needle) {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

/**
 * Run from the browser console:
 *   import('/js/crypto.js').then(m => m.runSelfTest())
 */
export async function runSelfTest() {
  const results = [];
  const check = (test, pass) => results.push({ test, result: pass ? "PASS" : "FAIL" });
  const rejects = async (fn) => {
    try {
      await fn();
      return false;
    } catch {
      return true;
    }
  };
  const enc = new TextEncoder();

  const marker = enc.encode("PASSPORT-NUMBER-12345");
  const filler = crypto.getRandomValues(new Uint8Array(2000));
  const original = new Uint8Array(marker.length + filler.length);
  original.set(marker, 0);
  original.set(filler, marker.length);
  const file = new File([original], "secret-passport.pdf", { type: "application/pdf" });

  const salt = generateSalt();
  const key = await deriveKey("self-test-passphrase-one", salt);
  const wrongKey = await deriveKey("self-test-passphrase-two", salt);

  const a = await encryptFile(file, key, salt);
  const b = await encryptFile(file, key, salt);
  const pa = parseContainer(a.container);
  const pb = parseContainer(b.container);

  // Round trip
  const out = await decryptContainer(a.container, key);
  check(
    "round trip restores identical bytes",
    out.data.length === original.length && out.data.every((v, i) => v === original[i])
  );
  check("filename, type and size restored", out.name === "secret-passport.pdf" && out.type === "application/pdf" && out.size === original.length);

  // Confidentiality
  check("document content not visible in container", !containsSubarray(a.container, marker));
  check("filename not visible in container", !containsSubarray(a.container, enc.encode("secret-passport")));
  check(
    "header holds only public fields",
    Object.keys(pa.header).sort().join(",") === "alg,docId,hash,iterations,iv,kdf,salt,v"
  );

  // Freshness
  check("IV is 12 bytes", pa.iv.length === 12);
  check("new random IV for each encryption", bytesToBase64(pa.iv) !== bytesToBase64(pb.iv));
  check("ciphertext differs between encryptions", bytesToBase64(pa.ciphertext) !== bytesToBase64(pb.ciphertext));
  check("document IDs are unique", a.docId !== b.docId);

  // Integrity and authentication
  check("wrong key is rejected", await rejects(() => decryptContainer(a.container, wrongKey)));

  const flippedCipher = a.container.slice();
  flippedCipher[flippedCipher.length - 1] ^= 0x01;
  check("modified ciphertext is rejected", await rejects(() => decryptContainer(flippedCipher, key)));

  const flippedHeader = a.container.slice();
  flippedHeader[pa.headerOffset + 16] ^= 0x01; // first character of docId inside the header
  check("modified header is rejected (AAD)", await rejects(() => decryptContainer(flippedHeader, key)));

  const badMagic = a.container.slice();
  badMagic[0] ^= 0xff;
  check("bad magic is rejected", await rejects(() => decryptContainer(badMagic, key)));
  check("truncated file is rejected", await rejects(() => decryptContainer(a.container.slice(0, 20), key)));

  console.table(results);
  const allPassed = results.every((r) => r.result === "PASS");
  console.log(allPassed ? "All crypto tests passed." : "Some tests FAILED.");
  return allPassed;
}

// Re-export so callers can import everything crypto-related from one place.
export { generateSalt, deriveKey, KDF_ITERATIONS };
