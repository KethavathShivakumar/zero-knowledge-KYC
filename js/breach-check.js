/**
 * breach-check.js - Have I Been Pwned Pwned Passwords Range API integration.
 *
 * Uses k-Anonymity model:
 * 1. Hashes passphrase locally with SHA-1.
 * 2. Sends ONLY the first 5 hex characters to api.pwnedpasswords.com.
 * 3. Compares the 35-character suffix locally against the returned list.
 *
 * Confidentiality guarantees:
 * - The full passphrase is NEVER sent over the network.
 * - The remaining 35 characters of the hash are NEVER sent.
 * - The server only sees a 5-character prefix shared by thousands of passwords.
 */

/**
 * Checks if a passphrase appears in known data breaches via HIBP Range API.
 * @param {string} passphrase
 * @returns {Promise<{breached: boolean, count: number, error: string|null}>}
 */
export async function checkPassphraseBreach(passphrase) {
  if (!passphrase || typeof passphrase !== "string") {
    return { breached: false, count: 0, error: null };
  }

  try {
    const enc = new TextEncoder();
    const data = enc.encode(passphrase);
    const hashBuffer = await crypto.subtle.digest("SHA-1", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const fullHash = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();

    const prefix = fullHash.slice(0, 5);
    const suffix = fullHash.slice(5);

    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      method: "GET",
      headers: {
        Accept: "text/plain",
      },
      cache: "no-store",
    });

    if (!response.ok) {
      return { breached: false, count: 0, error: "Breach check service unavailable." };
    }

    const text = await response.text();
    const lines = text.split("\n");

    for (const line of lines) {
      const parts = line.trim().split(":");
      if (parts.length === 2) {
        const itemSuffix = parts[0].trim().toUpperCase();
        const count = parseInt(parts[1].trim(), 10) || 0;
        if (itemSuffix === suffix) {
          return { breached: true, count, error: null };
        }
      }
    }

    return { breached: false, count: 0, error: null };
  } catch (err) {
    return { breached: false, count: 0, error: "Network error during breach check." };
  }
}

