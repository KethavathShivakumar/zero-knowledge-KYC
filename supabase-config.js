/**
 * supabase-config.js - Supabase Client Configuration
 *
 * INSTRUCTIONS:
 * 1. Log in to your Supabase dashboard: https://supabase.com/dashboard
 * 2. Select your project (or create one).
 * 3. Go to Project Settings -> API.
 * 4. Copy the "Project URL" and the "anon public" API key into the fields below.
 * 5. In Supabase Storage, create a private bucket named "encrypted-documents"
 *    (or run the provided RLS SQL script in the SQL Editor).
 *
 * SECURITY:
 * - NEVER put the service_role secret key in frontend code.
 * - Only the anon/publishable key is safe for client applications.
 */

const env = globalThis.__ENV__ || {};

export const supabaseConfig = {
  url: env.SUPABASE_URL || "https://zoclyjcfiugcyhenmyog.supabase.co",
  anonKey: env.SUPABASE_ANON_KEY || "sb_publishable_gvKK9XURFEPlIXglwEjyUA_EwSyUh0q",
  bucketName: "encrypted-documents",
  // hCaptcha Site Key configured in your hCaptcha & Supabase dashboards:
  // If you are testing, you can use the official hCaptcha test key: 10000000-ffff-ffff-ffff-000000000001
  hcaptchaSiteKey: env.HCAPTCHA_SITEKEY || "6ca869b8-8922-4bd0-b126-d7ee8b3873d4",
};

/**
 * Validates whether real Supabase credentials have been configured.
 * @returns {boolean}
 */
export function isSupabaseConfigured() {
  return (
    typeof supabaseConfig.url === "string" &&
    supabaseConfig.url.length > 0 &&
    !supabaseConfig.url.includes("YOUR_PROJECT_REF") &&
    typeof supabaseConfig.anonKey === "string" &&
    supabaseConfig.anonKey.length > 0 &&
    supabaseConfig.anonKey !== "YOUR_SUPABASE_ANON_KEY"
  );
}

