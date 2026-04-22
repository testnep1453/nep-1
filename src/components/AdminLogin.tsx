/**
 * AdminLogin.tsx
 *
 * Two-step admin login:
 *   Step 1 – Email + password  (Supabase Auth)
 *   Step 2 – 6-digit OTP       (sent to admin email, verified via DB RPC)
 *
 * On completion, calls onSuccess() so the parent can redirect to the dashboard.
 */

import { useState, useEffect, useRef, useCallback, forwardRef, FormEvent } from "react";
import {
  Shield, Mail, Lock, Eye, EyeOff, ChevronRight,
  RefreshCw, AlertCircle, CheckCircle, Clock,
} from "lucide-react";
import {
  signInAdmin, requestOtp, verifyOtp, signOutAdmin,
} from "../lib/supabase-admin";

// ── Constants ────────────────────────────────────────────────────────────────

const OTP_TTL_SEC      = 5 * 60;   // must match migration.sql / Edge Function
const MAX_OTP_ATTEMPTS = 5;

// ── Sub-components ───────────────────────────────────────────────────────────

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label:    string;
  id:       string;
  error?:   string;
  icon?:    React.ReactNode;
  trailing?: React.ReactNode;
}

const Field = forwardRef<HTMLInputElement, InputProps>(
  function Field({ label, id, error, icon, trailing, ...rest }, ref) {
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm font-medium text-slate-300">
        {label}
      </label>
      <div className="relative">
        {icon && (
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none">
            {icon}
          </span>
        )}
        <input
          ref={ref}
          id={id}
          className={[
            "w-full rounded-lg border bg-slate-900 px-4 py-2.5 text-sm text-slate-100",
            "placeholder-slate-600 outline-none transition",
            "focus:border-red-500 focus:ring-2 focus:ring-red-500/20",
            icon    ? "pl-10" : "",
            trailing ? "pr-10" : "",
            error
              ? "border-red-500/70"
              : "border-slate-700 hover:border-slate-600",
          ].join(" ")}
          {...rest}
        />
        {trailing && (
          <span className="absolute right-3 top-1/2 -translate-y-1/2">
            {trailing}
          </span>
        )}
      </div>
      {error && (
        <p className="flex items-center gap-1 text-xs text-red-400">
          <AlertCircle size={12} /> {error}
        </p>
      )}
    </div>
  );
});

// ── Types ────────────────────────────────────────────────────────────────────

type Step = "credentials" | "otp";

interface Props {
  onSuccess: () => void;
}

// ── Component ────────────────────────────────────────────────────────────────

export default function AdminLogin({ onSuccess }: Props) {
  // ── Shared state
  const [step,      setStep]      = useState<Step>("credentials");
  const [loading,   setLoading]   = useState(false);
  const [globalErr, setGlobalErr] = useState("");

  // ── Step 1 state
  const [email,        setEmail]        = useState("");
  const [password,     setPassword]     = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [fieldErrors,  setFieldErrors]  = useState<{ email?: string; password?: string }>({});

  // ── Step 2 state
  const [otp,         setOtp]         = useState("");
  const [otpErr,      setOtpErr]      = useState("");
  const [countdown,   setCountdown]   = useState(OTP_TTL_SEC);
  const [otpAttempts, setOtpAttempts] = useState(0);
  const [resendCooldown, setResendCooldown] = useState(0);
  const timerRef    = useRef<ReturnType<typeof setInterval> | null>(null);
  const resendRef   = useRef<ReturnType<typeof setInterval> | null>(null);
  const otpInputRef = useRef<HTMLInputElement>(null);

  // ── Countdown timer (step 2)
  const startCountdown = useCallback(() => {
    if (timerRef.current) clearInterval(timerRef.current);
    setCountdown(OTP_TTL_SEC);
    timerRef.current = setInterval(() => {
      setCountdown(n => {
        if (n <= 1) {
          clearInterval(timerRef.current!);
          return 0;
        }
        return n - 1;
      });
    }, 1000);
  }, []);

  // Cleanup on unmount
  useEffect(() => () => {
    if (timerRef.current)  clearInterval(timerRef.current);
    if (resendRef.current) clearInterval(resendRef.current);
  }, []);

  // Auto-focus OTP input when step changes
  useEffect(() => {
    if (step === "otp") {
      setTimeout(() => otpInputRef.current?.focus(), 100);
    }
  }, [step]);

  // ── Resend cooldown helper
  function startResendCooldown(seconds = 60) {
    setResendCooldown(seconds);
    resendRef.current = setInterval(() => {
      setResendCooldown(n => {
        if (n <= 1) {
          clearInterval(resendRef.current!);
          return 0;
        }
        return n - 1;
      });
    }, 1000);
  }

  // ── Validation (step 1)
  function validateCredentials(): boolean {
    const errs: typeof fieldErrors = {};
    if (!email.trim())     errs.email    = "Email is required.";
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errs.email = "Enter a valid email.";
    if (!password.trim())  errs.password = "Password is required.";
    setFieldErrors(errs);
    return Object.keys(errs).length === 0;
  }

  // ── Step 1 submit
  async function handleCredentials(e: FormEvent) {
    e.preventDefault();
    setGlobalErr("");
    if (!validateCredentials()) return;

    setLoading(true);
    try {
      const { error } = await signInAdmin(email.trim().toLowerCase(), password);
      if (error) {
        setGlobalErr(error);
        return;
      }

      // Password OK → send OTP
      const { error: otpErr } = await requestOtp();
      if (otpErr) {
        // Sign out so we don't leave a half-authenticated session
        await signOutAdmin();
        setGlobalErr(otpErr);
        return;
      }

      setStep("otp");
      startCountdown();
      startResendCooldown();
    } finally {
      setLoading(false);
    }
  }

  // ── Step 2: resend OTP
  async function handleResend() {
    if (resendCooldown > 0) return;
    setOtpErr("");
    setGlobalErr("");
    setLoading(true);
    try {
      const { error } = await requestOtp();
      if (error) { setGlobalErr(error); return; }
      setOtp("");
      setOtpAttempts(0);
      startCountdown();
      startResendCooldown();
    } finally {
      setLoading(false);
    }
  }

  // ── Step 2 submit
  async function handleOtp(e: FormEvent) {
    e.preventDefault();
    setOtpErr("");
    setGlobalErr("");

    const code = otp.replace(/\s/g, "");
    if (!/^\d{6}$/.test(code)) {
      setOtpErr("Enter the 6-digit code from your email.");
      return;
    }

    if (countdown === 0) {
      setOtpErr("Code expired. Request a new one.");
      return;
    }

    if (otpAttempts >= MAX_OTP_ATTEMPTS) {
      setOtpErr("Too many failed attempts. Please log in again.");
      await signOutAdmin();
      setStep("credentials");
      setOtp("");
      setPassword("");
      return;
    }

    setLoading(true);
    try {
      const { error } = await verifyOtp(email.trim().toLowerCase(), code);
      if (error) {
        setOtpAttempts(a => a + 1);
        setOtpErr(error);
        setOtp("");
        otpInputRef.current?.focus();
        return;
      }
      onSuccess();
    } finally {
      setLoading(false);
    }
  }

  // ── Back to credentials
  async function handleBack() {
    await signOutAdmin();
    setStep("credentials");
    setOtp("");
    setOtpErr("");
    setGlobalErr("");
    setOtpAttempts(0);
    if (timerRef.current) clearInterval(timerRef.current);
  }

  // ── Helpers
  const mm = String(Math.floor(countdown / 60)).padStart(2, "0");
  const ss = String(countdown % 60).padStart(2, "0");

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-[#0f0f1a] flex items-center justify-center p-4">
      <div className="w-full max-w-md">

        {/* Header */}
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center
                          rounded-2xl bg-gradient-to-br from-red-600 to-red-800 shadow-lg shadow-red-900/40">
            <Shield size={28} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-wide text-white">NEP Admin</h1>
          <p className="mt-1 text-sm text-slate-500">
            {step === "credentials"
              ? "Sign in to the admin panel"
              : "Check your email for the verification code"}
          </p>
        </div>

        {/* Card */}
        <div className="rounded-2xl border border-slate-800 bg-[#1a1a2e] p-8 shadow-xl">

          {/* Global error */}
          {globalErr && (
            <div className="mb-5 flex items-start gap-2 rounded-lg border border-red-500/30
                            bg-red-500/10 px-4 py-3 text-sm text-red-400">
              <AlertCircle size={16} className="mt-0.5 shrink-0" />
              <span>{globalErr}</span>
            </div>
          )}

          {/* ── STEP 1: Credentials ── */}
          {step === "credentials" && (
            <form onSubmit={handleCredentials} noValidate className="space-y-5">
              <Field
                label="Email address"
                id="admin-email"
                type="email"
                autoComplete="email"
                autoFocus
                value={email}
                onChange={e => { setEmail(e.target.value); setFieldErrors(f => ({ ...f, email: undefined })); }}
                placeholder="admin@yourapp.com"
                icon={<Mail size={16} />}
                error={fieldErrors.email}
                disabled={loading}
              />

              <Field
                label="Password"
                id="admin-password"
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                value={password}
                onChange={e => { setPassword(e.target.value); setFieldErrors(f => ({ ...f, password: undefined })); }}
                placeholder="••••••••••••"
                icon={<Lock size={16} />}
                error={fieldErrors.password}
                disabled={loading}
                trailing={
                  <button
                    type="button"
                    onClick={() => setShowPassword(v => !v)}
                    className="text-slate-500 hover:text-slate-300 transition"
                    tabIndex={-1}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                }
              />

              <div className="flex justify-end">
                <a
                  href="/admin/forgot-password"
                  className="text-xs text-slate-500 hover:text-red-400 transition"
                >
                  Forgot password?
                </a>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="mt-2 flex w-full items-center justify-center gap-2 rounded-lg
                           bg-gradient-to-r from-red-600 to-red-700 px-4 py-2.5
                           text-sm font-semibold text-white shadow-md shadow-red-900/30
                           transition hover:from-red-500 hover:to-red-600 active:scale-[0.98]
                           disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <RefreshCw size={16} className="animate-spin" />
                ) : (
                  <>Continue <ChevronRight size={16} /></>
                )}
              </button>
            </form>
          )}

          {/* ── STEP 2: OTP ── */}
          {step === "otp" && (
            <form onSubmit={handleOtp} noValidate className="space-y-5">
              {/* Email chip */}
              <div className="flex items-center justify-center gap-2 rounded-lg
                              border border-slate-700 bg-slate-900/60 px-4 py-2.5">
                <CheckCircle size={14} className="text-green-500 shrink-0" />
                <span className="text-sm text-slate-300 truncate">{email}</span>
              </div>

              {/* Countdown */}
              <div className={[
                "flex items-center justify-center gap-2 text-sm font-mono",
                countdown === 0 ? "text-red-400" : "text-slate-400",
              ].join(" ")}>
                <Clock size={14} />
                <span>{countdown > 0 ? `Expires in ${mm}:${ss}` : "Code expired"}</span>
              </div>

              {/* OTP input */}
              <Field
                label="Verification code"
                id="admin-otp"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                value={otp}
                ref={otpInputRef}
                onChange={e => {
                  const v = e.target.value.replace(/\D/g, "").slice(0, 6);
                  setOtp(v);
                  setOtpErr("");
                }}
                placeholder="000000"
                error={otpErr}
                disabled={loading}
                className="text-center text-xl tracking-[0.5em] font-mono"
              />

              {otpAttempts > 0 && otpAttempts < MAX_OTP_ATTEMPTS && (
                <p className="text-center text-xs text-yellow-500">
                  {MAX_OTP_ATTEMPTS - otpAttempts} attempt{MAX_OTP_ATTEMPTS - otpAttempts !== 1 ? "s" : ""} remaining
                </p>
              )}

              <button
                type="submit"
                disabled={loading || otp.length < 6 || countdown === 0}
                className="flex w-full items-center justify-center gap-2 rounded-lg
                           bg-gradient-to-r from-red-600 to-red-700 px-4 py-2.5
                           text-sm font-semibold text-white shadow-md shadow-red-900/30
                           transition hover:from-red-500 hover:to-red-600 active:scale-[0.98]
                           disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <RefreshCw size={16} className="animate-spin" />
                ) : (
                  <>Verify &amp; Sign In <ChevronRight size={16} /></>
                )}
              </button>

              <div className="flex items-center justify-between text-xs">
                <button
                  type="button"
                  onClick={handleBack}
                  className="text-slate-500 hover:text-slate-300 transition"
                  disabled={loading}
                >
                  ← Back
                </button>
                <button
                  type="button"
                  onClick={handleResend}
                  disabled={loading || resendCooldown > 0}
                  className="text-slate-500 hover:text-red-400 transition
                             disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {resendCooldown > 0
                    ? `Resend in ${resendCooldown}s`
                    : "Resend code"}
                </button>
              </div>
            </form>
          )}
        </div>

        {/* Footer */}
        <p className="mt-6 text-center text-xs text-slate-700">
          NEP Gaming Platform &mdash; Admin Panel
        </p>
      </div>
    </div>
  );
}
