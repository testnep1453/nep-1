-- ============================================================
-- NEP ADMIN AUTH MIGRATION v2
-- Migrates custom admin auth to Supabase Auth + Email OTP 2FA
-- Run this in Supabase SQL Editor with the service role.
-- Order matters — execute top to bottom.
-- ============================================================

-- Enable pgcrypto for bcrypt hashing (required for OTP storage)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- STEP 1: Migrate admin_users → admins
-- Adds email, auth link, role, and legacy hash columns.
-- ============================================================

-- Rename the existing table (idempotent-safe via DO block)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'admin_users' AND table_schema = 'public')
     AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'admins' AND table_schema = 'public')
  THEN
    ALTER TABLE admin_users RENAME TO admins;
  ELSIF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'admins' AND table_schema = 'public') THEN
    CREATE TABLE admins (
      user_id      TEXT PRIMARY KEY,
      is_super_admin BOOLEAN DEFAULT false,
      created_at   TIMESTAMPTZ DEFAULT now()
    );
  END IF;
END;
$$;

-- Add new columns (all idempotent)
ALTER TABLE admins
  ADD COLUMN IF NOT EXISTS auth_user_id  UUID UNIQUE REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS email         TEXT UNIQUE,
  ADD COLUMN IF NOT EXISTS username      TEXT,
  ADD COLUMN IF NOT EXISTS role          TEXT NOT NULL DEFAULT 'admin',
  ADD COLUMN IF NOT EXISTS password_hash TEXT,   -- legacy bcrypt hash, nullable after migration
  ADD COLUMN IF NOT EXISTS updated_at    TIMESTAMPTZ DEFAULT now();

-- Trigger: keep updated_at current
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

DROP TRIGGER IF EXISTS admins_updated_at ON admins;
CREATE TRIGGER admins_updated_at
  BEFORE UPDATE ON admins
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================
-- STEP 2: OTP table
-- Stores one-time codes with bcrypt hash + expiry.
-- ============================================================

CREATE TABLE IF NOT EXISTS admin_otps (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_email TEXT      NOT NULL,
  otp_hash    TEXT      NOT NULL,  -- bcrypt hash of the 6-digit code
  expires_at  TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '5 minutes'),
  used        BOOLEAN   NOT NULL DEFAULT false,
  ip_address  INET,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS admin_otps_email_idx   ON admin_otps(admin_email);
CREATE INDEX IF NOT EXISTS admin_otps_expires_idx ON admin_otps(expires_at);

-- ============================================================
-- STEP 3: Session audit log
-- Records every successful 2FA login for compliance.
-- ============================================================

CREATE TABLE IF NOT EXISTS admin_sessions (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_email      TEXT NOT NULL,
  ip_address       INET,
  user_agent       TEXT,
  otp_verified_at  TIMESTAMPTZ,
  session_start    TIMESTAMPTZ NOT NULL DEFAULT now(),
  session_end      TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- STEP 4: Helper functions (SECURITY DEFINER = bypasses RLS)
-- ============================================================

-- Is the calling user an admin?
CREATE OR REPLACE FUNCTION is_admin()
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER STABLE AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM admins WHERE auth_user_id = auth.uid()
  );
END;
$$;

-- Is the calling user a super-admin?
CREATE OR REPLACE FUNCTION is_super_admin()
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER STABLE AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM admins
    WHERE auth_user_id = auth.uid() AND is_super_admin = true
  );
END;
$$;

-- Store OTP: hashes the plaintext code with bcrypt, invalidates old codes.
-- Called exclusively from the Edge Function via service role.
CREATE OR REPLACE FUNCTION store_admin_otp(
  p_email      TEXT,
  p_otp        TEXT,
  p_expires_at TIMESTAMPTZ,
  p_ip_address INET DEFAULT NULL
)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  -- Invalidate all previous unused codes for this address
  UPDATE admin_otps
  SET used = true
  WHERE admin_email = p_email AND used = false;

  INSERT INTO admin_otps (admin_email, otp_hash, expires_at, ip_address)
  VALUES (p_email, crypt(p_otp, gen_salt('bf', 8)), p_expires_at, p_ip_address);
END;
$$;

-- Verify OTP: compares bcrypt hash, marks used on success, records session.
-- Returns TRUE only once per OTP.
CREATE OR REPLACE FUNCTION verify_admin_otp(p_email TEXT, p_otp TEXT)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_id   UUID;
  v_hash TEXT;
BEGIN
  SELECT id, otp_hash INTO v_id, v_hash
  FROM admin_otps
  WHERE admin_email = p_email
    AND used        = false
    AND expires_at  > now()
  ORDER BY created_at DESC
  LIMIT 1;

  IF v_id IS NULL THEN
    RETURN false;
  END IF;

  IF crypt(p_otp, v_hash) = v_hash THEN
    UPDATE admin_otps SET used = true WHERE id = v_id;

    -- Write audit record
    INSERT INTO admin_sessions (admin_email, otp_verified_at)
    VALUES (p_email, now());

    RETURN true;
  END IF;

  RETURN false;
END;
$$;

-- Cleanup: called periodically to prune stale rows.
CREATE OR REPLACE FUNCTION cleanup_expired_otps()
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  DELETE FROM admin_otps WHERE expires_at < now() - INTERVAL '1 hour';
END;
$$;

-- ============================================================
-- STEP 5: Seed default admin in auth.users + admins
-- Password: SecurePass123!  ← CHANGE THIS IMMEDIATELY
-- ============================================================

DO $$
DECLARE
  v_uid UUID;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM auth.users WHERE email = 'admin@yourapp.com') THEN
    v_uid := gen_random_uuid();

    INSERT INTO auth.users (
      id, instance_id,
      email, encrypted_password,
      email_confirmed_at,
      created_at, updated_at,
      raw_app_meta_data, raw_user_meta_data,
      is_super_admin, role, aud,
      confirmation_token, recovery_token
    ) VALUES (
      v_uid,
      '00000000-0000-0000-0000-000000000000',
      'admin@yourapp.com',
      crypt('SecurePass123!', gen_salt('bf', 12)),
      now(), now(), now(),
      '{"provider":"email","providers":["email"]}'::jsonb,
      '{"role":"super_admin","username":"admin"}'::jsonb,
      false, 'authenticated', 'authenticated',
      '', ''
    );

    INSERT INTO admins (user_id, auth_user_id, email, username, role, is_super_admin)
    VALUES (v_uid::text, v_uid, 'admin@yourapp.com', 'admin', 'super_admin', true)
    ON CONFLICT (user_id) DO UPDATE SET
      auth_user_id   = EXCLUDED.auth_user_id,
      email          = EXCLUDED.email,
      role           = EXCLUDED.role,
      is_super_admin = EXCLUDED.is_super_admin;
  END IF;
END;
$$;

-- ============================================================
-- STEP 6: Row Level Security
-- All tables use is_admin() — no hardcoded IDs.
-- ============================================================

ALTER TABLE admin_otps    ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE admins         ENABLE ROW LEVEL SECURITY;

-- OTP rows: only the matching admin can read their own (insert via service role only)
DROP POLICY IF EXISTS "admin_otps_own"            ON admin_otps;
DROP POLICY IF EXISTS "admin_otps_insert_service" ON admin_otps;

CREATE POLICY "admin_otps_own" ON admin_otps
  FOR SELECT USING (admin_email = auth.email());

-- No INSERT policy — Edge Function uses service role key which bypasses RLS
-- (Do NOT add a public INSERT policy here)

-- Sessions: admins see their own
DROP POLICY IF EXISTS "admin_sessions_own"    ON admin_sessions;
DROP POLICY IF EXISTS "admin_sessions_insert" ON admin_sessions;

CREATE POLICY "admin_sessions_own" ON admin_sessions
  FOR SELECT USING (admin_email = auth.email());

CREATE POLICY "admin_sessions_insert" ON admin_sessions
  FOR INSERT WITH CHECK (true);   -- verify_admin_otp() is SECURITY DEFINER

-- Admins table: own row read + super-admin full access
DROP POLICY IF EXISTS "admins_read_own"       ON admins;
DROP POLICY IF EXISTS "admins_super_admin_all" ON admins;
DROP POLICY IF EXISTS "admin_users_admin_only" ON admins;

CREATE POLICY "admins_read_own" ON admins
  FOR SELECT USING (auth_user_id = auth.uid());

CREATE POLICY "admins_super_admin_all" ON admins
  FOR ALL USING (is_super_admin());

-- Replace all hardcoded '1002' policies on other tables
DROP POLICY IF EXISTS "students_admin_all"      ON students;
DROP POLICY IF EXISTS "attendance_admin"        ON attendance;
DROP POLICY IF EXISTS "feedback_admin_read"     ON feedback;
DROP POLICY IF EXISTS "feedback_admin_delete"   ON feedback;
DROP POLICY IF EXISTS "badges_admin"            ON student_badges;
DROP POLICY IF EXISTS "settings_admin_write"    ON settings;
DROP POLICY IF EXISTS "security_alerts_admin"   ON security_alerts;
DROP POLICY IF EXISTS "system_commands_admin_all" ON system_commands;
DROP POLICY IF EXISTS "device_logs_admin"       ON device_logs;

CREATE POLICY "students_admin_all"        ON students        FOR ALL USING (is_admin());
CREATE POLICY "attendance_admin"          ON attendance      FOR ALL USING (is_admin());
CREATE POLICY "feedback_admin_read"       ON feedback        FOR SELECT USING (is_admin());
CREATE POLICY "feedback_admin_delete"     ON feedback        FOR DELETE USING (is_admin());
CREATE POLICY "badges_admin"              ON student_badges  FOR ALL USING (is_admin());
CREATE POLICY "settings_admin_write"      ON settings        FOR ALL USING (is_admin());
CREATE POLICY "security_alerts_admin"     ON security_alerts FOR ALL USING (is_admin());
CREATE POLICY "system_commands_admin_all" ON system_commands FOR ALL USING (is_admin());
CREATE POLICY "device_logs_admin"         ON device_logs     FOR ALL USING (is_admin());

-- ============================================================
-- STEP 7: Verify
-- ============================================================

SELECT
  u.email,
  a.role,
  a.is_super_admin,
  a.auth_user_id IS NOT NULL AS has_auth_link,
  u.email_confirmed_at IS NOT NULL AS email_confirmed
FROM admins a
JOIN auth.users u ON u.id = a.auth_user_id
WHERE u.email = 'admin@yourapp.com';
