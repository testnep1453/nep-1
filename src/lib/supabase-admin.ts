/**
 * supabase-admin.ts
 *
 * Supabase client and auth utilities for the admin panel.
 *
 * Required env vars (Vite):
 *   VITE_SUPABASE_URL
 *   VITE_SUPABASE_ANON_KEY
 */

import { createClient, Session, User } from "@supabase/supabase-js";

// ── Client ───────────────────────────────────────────────────────────────────

const SUPABASE_URL     = import.meta.env.VITE_SUPABASE_URL as string;
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY as string;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  throw new Error("Missing VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY");
}

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    autoRefreshToken: true,
    persistSession:   true,
    detectSessionInUrl: true,
    // sessionStorage keeps the session tab-isolated; logout in one tab
    // does not carry over to another tab's active session.
    storage: window.sessionStorage,
  },
});

// ── Types ────────────────────────────────────────────────────────────────────

export interface AdminRecord {
  user_id:       string;
  auth_user_id:  string;
  email:         string;
  username:      string;
  role:          "admin" | "super_admin";
  is_super_admin: boolean;
  created_at:    string;
}

export interface AuthResult<T = void> {
  data:  T | null;
  error: string | null;
}

// ── Session timeout (30-min inactivity) ─────────────────────────────────────

const INACTIVITY_MS    = 30 * 60 * 1000;
const ACTIVITY_EVENTS  = ["mousedown", "keydown", "touchstart", "scroll"] as const;
let   inactivityTimer: ReturnType<typeof setTimeout> | null = null;

function onActivity() {
  if (!inactivityTimer) return; // monitoring not active
  clearTimeout(inactivityTimer);
  scheduleTimeout();
}

function scheduleTimeout() {
  inactivityTimer = setTimeout(async () => {
    await signOutAdmin();
    window.dispatchEvent(new CustomEvent("nep:admin:session-timeout"));
  }, INACTIVITY_MS);
}

export function startSessionMonitoring(): void {
  scheduleTimeout();
  ACTIVITY_EVENTS.forEach(evt =>
    window.addEventListener(evt, onActivity, { passive: true }),
  );
}

export function stopSessionMonitoring(): void {
  if (inactivityTimer) {
    clearTimeout(inactivityTimer);
    inactivityTimer = null;
  }
  ACTIVITY_EVENTS.forEach(evt =>
    window.removeEventListener(evt, onActivity),
  );
}

// ── OTP verification state ───────────────────────────────────────────────────
// Stored in sessionStorage so refreshing the page requires re-auth, and
// closing the tab always clears it.

const OTP_KEY = "nep_admin_otp_ok";

export function markOtpVerified():  void    { sessionStorage.setItem(OTP_KEY, "1"); }
export function clearOtpVerified(): void    { sessionStorage.removeItem(OTP_KEY); }
export function isOtpVerified():    boolean { return sessionStorage.getItem(OTP_KEY) === "1"; }

// ── Auth operations ──────────────────────────────────────────────────────────

/**
 * Step 1 of 2FA: validate email + password and confirm the account is an admin.
 * Does NOT grant full access — OTP verification (step 2) is still required.
 */
export async function signInAdmin(
  email: string,
  password: string,
): Promise<AuthResult<User>> {
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });

  if (error || !data.user) {
    return { data: null, error: "Invalid email or password." };
  }

  // Verify the account exists in the admins table before proceeding.
  const { error: adminErr } = await supabase
    .from("admins")
    .select("role")
    .eq("auth_user_id", data.user.id)
    .single();

  if (adminErr) {
    // Sign out immediately — authenticated but not an admin.
    await supabase.auth.signOut();
    return { data: null, error: "Access denied. Not an admin account." };
  }

  return { data: data.user, error: null };
}

/**
 * Step 2a: request a fresh OTP be sent to the admin's email.
 * Calls the send-otp Edge Function using the current session JWT.
 */
export async function requestOtp(): Promise<AuthResult> {
  const { error } = await supabase.functions.invoke("send-otp", {
    method: "POST",
    body:   {},
  });

  if (error) {
    return { data: null, error: error.message ?? "Failed to send verification code." };
  }

  return { data: null, error: null };
}

/**
 * Step 2b: verify the OTP entered by the admin.
 * Uses the verify_admin_otp() SECURITY DEFINER RPC — the DB handles bcrypt comparison.
 */
export async function verifyOtp(
  email: string,
  otp: string,
): Promise<AuthResult> {
  const { data, error } = await supabase.rpc("verify_admin_otp", {
    p_email: email,
    p_otp:   otp.trim(),
  });

  if (error) {
    return { data: null, error: "Verification failed. Please try again." };
  }

  if (!data) {
    return { data: null, error: "Invalid or expired code." };
  }

  markOtpVerified();
  startSessionMonitoring();
  return { data: null, error: null };
}

/** Full sign-out: clears OTP state, stops inactivity timer, ends Supabase session. */
export async function signOutAdmin(): Promise<void> {
  clearOtpVerified();
  stopSessionMonitoring();
  await supabase.auth.signOut();
}

/**
 * Sends a Supabase password-reset email.
 * Always returns success to prevent email enumeration.
 */
export async function sendPasswordResetEmail(email: string): Promise<AuthResult> {
  await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: `${window.location.origin}/admin/reset-password`,
  });
  // Intentionally silent — never reveal whether the email exists.
  return { data: null, error: null };
}

/**
 * Called from the reset-password page after the user clicks the magic link.
 * Updates the password in auth.users.
 */
export async function updateAdminPassword(
  newPassword: string,
): Promise<AuthResult> {
  const { error } = await supabase.auth.updateUser({ password: newPassword });

  if (error) {
    return { data: null, error: error.message };
  }

  return { data: null, error: null };
}

/** Returns the full admin record for the currently authenticated user. */
export async function getAdminRecord(): Promise<AdminRecord | null> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;

  const { data, error } = await supabase
    .from("admins")
    .select("*")
    .eq("auth_user_id", user.id)
    .single();

  return error ? null : (data as AdminRecord);
}

/** Returns the current Supabase session, or null if not authenticated. */
export async function getCurrentSession(): Promise<Session | null> {
  const { data: { session } } = await supabase.auth.getSession();
  return session;
}

/**
 * Returns true only when:
 *  1. There is a valid Supabase session, AND
 *  2. The OTP verification flag is set for this browser tab.
 *
 * Use this as the guard in protected admin routes.
 */
export async function isFullyAuthenticated(): Promise<boolean> {
  if (!isOtpVerified()) return false;
  const session = await getCurrentSession();
  return session !== null;
}
