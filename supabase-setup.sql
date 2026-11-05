-- ==============================================================================
-- Zero-Knowledge KYC: Supabase Storage & Row-Level Security (RLS) Setup
-- ==============================================================================
-- INSTRUCTIONS:
-- 1. Open your Supabase Dashboard: https://supabase.com/dashboard
-- 2. Select your project.
-- 3. Click "SQL Editor" in the left sidebar (icon with `_>`).
-- 4. Click "New query", paste this entire script, and click "Run".
-- ==============================================================================

-- 1. Create or configure private storage bucket 'encrypted-documents'
INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES (
  'encrypted-documents',
  'encrypted-documents',
  false,                          -- Strictly private (no public URLs)
  15728640                        -- 15 MB per container limit
)
ON CONFLICT (id) DO UPDATE
SET public = false,
    file_size_limit = 15728640;

-- 2. Allow authenticated users to view the 'encrypted-documents' bucket
DROP POLICY IF EXISTS "Authenticated users can view encrypted-documents bucket" ON storage.buckets;
CREATE POLICY "Authenticated users can view encrypted-documents bucket"
ON storage.buckets
FOR SELECT
TO authenticated
USING (id = 'encrypted-documents');

-- 3. Policy: Authenticated users can upload (INSERT) ONLY into their own folder: {auth.uid}/*
DROP POLICY IF EXISTS "Users can upload their own encrypted documents" ON storage.objects;
CREATE POLICY "Users can upload their own encrypted documents"
ON storage.objects
FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'encrypted-documents'
  AND (
    (storage.foldername(name))[1] = (auth.uid())::text
    OR name LIKE (auth.uid())::text || '/%'
    OR ((storage.foldername(name))[1] = 'users' AND (storage.foldername(name))[2] = (auth.uid())::text)
  )
);

-- 4. Policy: Authenticated users can list and download (SELECT) ONLY their own files
DROP POLICY IF EXISTS "Users can read their own encrypted documents" ON storage.objects;
CREATE POLICY "Users can read their own encrypted documents"
ON storage.objects
FOR SELECT
TO authenticated
USING (
  bucket_id = 'encrypted-documents'
  AND (
    (storage.foldername(name))[1] = (auth.uid())::text
    OR name LIKE (auth.uid())::text || '/%'
    OR ((storage.foldername(name))[1] = 'users' AND (storage.foldername(name))[2] = (auth.uid())::text)
  )
);

-- 5. Policy: Authenticated users can delete (DELETE) ONLY their own files
DROP POLICY IF EXISTS "Users can delete their own encrypted documents" ON storage.objects;
CREATE POLICY "Users can delete their own encrypted documents"
ON storage.objects
FOR DELETE
TO authenticated
USING (
  bucket_id = 'encrypted-documents'
  AND (
    (storage.foldername(name))[1] = (auth.uid())::text
    OR name LIKE (auth.uid())::text || '/%'
    OR ((storage.foldername(name))[1] = 'users' AND (storage.foldername(name))[2] = (auth.uid())::text)
  )
);

-- 6. Policy: Authenticated users can update/upsert (UPDATE) ONLY their own files
DROP POLICY IF EXISTS "Users can update their own encrypted documents" ON storage.objects;
CREATE POLICY "Users can update their own encrypted documents"
ON storage.objects
FOR UPDATE
TO authenticated
USING (
  bucket_id = 'encrypted-documents'
  AND (
    (storage.foldername(name))[1] = (auth.uid())::text
    OR name LIKE (auth.uid())::text || '/%'
    OR ((storage.foldername(name))[1] = 'users' AND (storage.foldername(name))[2] = (auth.uid())::text)
  )
)
WITH CHECK (
  bucket_id = 'encrypted-documents'
  AND (
    (storage.foldername(name))[1] = (auth.uid())::text
    OR name LIKE (auth.uid())::text || '/%'
    OR ((storage.foldername(name))[1] = 'users' AND (storage.foldername(name))[2] = (auth.uid())::text)
  )
);
