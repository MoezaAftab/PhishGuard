-- ==============================================================================
-- PhishGuard - Supabase Database Schema
-- Run this in your Supabase Project -> SQL Editor to initialize the scans table
-- ==============================================================================

CREATE TABLE IF NOT EXISTS public.scans (
    scan_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_preview TEXT NOT NULL,
    overall_score FLOAT NOT NULL,
    verdict TEXT NOT NULL,
    verdict_badge_class TEXT NOT NULL,
    threat_summary TEXT NOT NULL,
    report_json JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for speedy timeline lookups
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON public.scans (verdict);

-- Enable Row Level Security (RLS)
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;

-- Allow read & write access for authenticated or anon key with policy
CREATE POLICY "Allow public read-write for demo" 
ON public.scans
FOR ALL 
TO anon, authenticated
USING (true)
WITH CHECK (true);
