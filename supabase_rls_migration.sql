-- ============================================================
-- NEP GAMING PLATFORM - SUPABASE RLS SECURITY MIGRATION
-- Execute this in Supabase SQL Editor (immediately required!)
-- ============================================================

-- Enable RLS on all tables
ALTER TABLE students ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance ENABLE ROW LEVEL SECURITY;
ALTER TABLE feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE student_badges ENABLE ROW LEVEL SECURITY;
ALTER TABLE fcm_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_commands ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- STUDENTS TABLE POLICIES
-- ============================================================

-- Drop existing policies if any
DROP POLICY IF EXISTS "students_own_data" ON students;
DROP POLICY IF EXISTS "students_admin_all" ON students;
DROP POLICY IF EXISTS "students_insert_own" ON students;

-- Students can only read/update their own data
CREATE POLICY "students_own_data" ON students
  FOR SELECT
  USING (auth.uid()::text = id OR id = '1002');

-- Students can only update their own profile (limited fields)
CREATE POLICY "students_update_own" ON students
  FOR UPDATE
  USING (auth.uid()::text = id)
  WITH CHECK (auth.uid()::text = id);

-- Admin can do everything
CREATE POLICY "students_admin_all" ON students
  FOR ALL
  USING (auth.uid()::text = '1002');

-- Allow insert for seed data (during registration)
CREATE POLICY "students_insert_own" ON students
  FOR INSERT
  WITH CHECK (auth.uid()::text = id OR auth.uid() IS NULL);

-- ============================================================
-- ATTENDANCE TABLE POLICIES
-- ============================================================

DROP POLICY IF EXISTS "attendance_own" ON attendance;
DROP POLICY IF EXISTS "attendance_admin" ON attendance;

-- Students can only see their own attendance
CREATE POLICY "attendance_own" ON attendance
  FOR SELECT
  USING (student_id = auth.uid()::text);

-- Admin can see all attendance
CREATE POLICY "attendance_admin" ON attendance
  FOR ALL
  USING (auth.uid()::text = '1002');

-- Allow insert for own attendance
CREATE POLICY "attendance_insert_own" ON attendance
  FOR INSERT
  WITH CHECK (student_id = auth.uid()::text);

-- ============================================================
-- FEEDBACK TABLE POLICIES
-- ============================================================

DROP POLICY IF EXISTS "feedback_insert" ON feedback;
DROP POLICY IF EXISTS "feedback_admin_read" ON feedback;

-- Anonymous users can insert feedback
CREATE POLICY "feedback_insert" ON feedback
  FOR INSERT
  WITH CHECK (true);

-- Only admin can read feedback
CREATE POLICY "feedback_admin_read" ON feedback
  FOR SELECT
  USING (auth.uid()::text = '1002');

-- Only admin can delete feedback
CREATE POLICY "feedback_admin_delete" ON feedback
  FOR DELETE
  USING (auth.uid()::text = '1002');

-- ============================================================
-- STUDENT_BADGES TABLE POLICIES
-- ============================================================

DROP POLICY IF EXISTS "badges_own" ON student_badges;
DROP POLICY IF EXISTS "badges_admin" ON student_badges;

-- Students can see their own badges
CREATE POLICY "badges_own" ON student_badges
  FOR SELECT
  USING (student_id = auth.uid()::text);

-- Admin can manage all badges
CREATE POLICY "badges_admin" ON student_badges
  FOR ALL
  USING (auth.uid()::text = '1002');

-- ============================================================
-- SETTINGS TABLE POLICIES
-- ============================================================

DROP POLICY IF EXISTS "settings_read_all" ON settings;
DROP POLICY IF EXISTS "settings_admin_write" ON settings;

-- Anyone can read settings (public config)
CREATE POLICY "settings_read_all" ON settings
  FOR SELECT
  USING (true);

-- Only admin can modify settings
CREATE POLICY "settings_admin_write" ON settings
  FOR ALL
  USING (auth.uid()::text = '1002');

-- ============================================================
-- SECURITY_ALERTS TABLE POLICIES
-- ============================================================

DROP POLICY IF EXISTS "security_alerts_insert" ON security_alerts;
DROP POLICY IF EXISTS "security_alerts_admin" ON security_alerts;

-- Authenticated users can create alerts
CREATE POLICY "security_alerts_insert" ON security_alerts
  FOR INSERT
  WITH CHECK (auth.uid() IS NOT NULL);

-- Only admin can read/delete alerts
CREATE POLICY "security_alerts_admin" ON security_alerts
  FOR ALL
  USING (auth.uid()::text = '1002');

-- ============================================================
-- SYSTEM_COMMANDS TABLE POLICIES
-- ============================================================

DROP POLICY IF EXISTS "system_commands_user_select" ON system_commands;
DROP POLICY IF EXISTS "system_commands_admin_all" ON system_commands;

-- Users can only see commands targeting them or global
CREATE POLICY "system_commands_user_select" ON system_commands
  FOR SELECT
  USING (target_id = auth.uid()::text OR target_id = 'all');

-- Only admin can create/update/delete commands
CREATE POLICY "system_commands_admin_all" ON system_commands
  FOR ALL
  USING (auth.uid()::text = '1002');

-- ============================================================
-- DEVICE_LOGS TABLE POLICIES
-- ============================================================

DROP POLICY IF EXISTS "device_logs_insert_own" ON device_logs;
DROP POLICY IF EXISTS "device_logs_admin" ON device_logs;

-- Users can create their own device logs
CREATE POLICY "device_logs_insert_own" ON device_logs
  FOR INSERT
  WITH CHECK (student_id = auth.uid()::text);

-- Only admin can read all logs
CREATE POLICY "device_logs_admin" ON device_logs
  FOR ALL
  USING (auth.uid()::text = '1002');

-- ============================================================
-- ADMIN_USERS TABLE POLICIES
-- ============================================================

DROP POLICY IF EXISTS "admin_users_self" ON admin_users;

-- Only admins can see admin table
CREATE POLICY "admin_users_admin_only" ON admin_users
  FOR ALL
  USING (auth.uid()::text = '1002');

-- ============================================================
-- CREATE ADMIN USERS TABLE (if not exists)
-- ============================================================

CREATE TABLE IF NOT EXISTS admin_users (
  user_id TEXT PRIMARY KEY,
  is_super_admin BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Insert admin (replace with actual Supabase Auth UID)
-- INSERT INTO admin_users (user_id, is_super_admin) 
-- VALUES ('actual-supabase-auth-uid-here', true);

-- ============================================================
-- VERIFY RLS IS ENABLED
-- ============================================================

SELECT 
  schemaname,
  tablename,
  rowsecurity
FROM pg_tables 
WHERE tablename IN (
  'students', 'attendance', 'feedback', 'student_badges', 
  'settings', 'security_alerts', 'system_commands', 'admin_users'
);
