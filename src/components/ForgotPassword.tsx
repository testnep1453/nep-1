/**
 * ForgotPassword.tsx
 *
 * Two-screen flow:
 *  Screen A – Email input → sends Supabase reset link
 *  Screen B – Success confirmation (email always shows success to prevent enumeration)
 *
 * The redirect URL lands the admin on /admin/reset-password where they
 * call updateAdminPassword() from supabase-admin.ts.
 *
 * Usage: render at /admin/forgot-password
 */

import { useState, FormEvent } from "react";
import { Shield, Mail, ArrowLeft, RefreshCw, CheckCircle, AlertCircle } from "lucide-react";
import { sendPasswordResetEmail } from "../lib/supabase-admin";

// ── Types ────────────────────────────────────────────────────────────────────

type Screen = "form" | "sent";

// ── Component ────────────────────────────────────────────────────────────────

interface Props {
  /** Override the "Back to login" href if your router uses a different path. */
  loginHref?: string;
}

export default function ForgotPassword({ loginHref = "/admin/login" }: Props) {
  const [screen,  setScreen]  = useState<Screen>("form");
  const [email,   setEmail]   = useState("");
  const [emailErr, setEmailErr] = useState("");
  const [loading, setLoading] = useState(false);
  const [globalErr, setGlobalErr] = useState("");

  function validate(): boolean {
    if (!email.trim()) {
      setEmailErr("Email is required.");
      return false;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setEmailErr("Enter a valid email address.");
      return false;
    }
    return true;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setEmailErr("");
    setGlobalErr("");
    if (!validate()) return;

    setLoading(true);
    try {
      // sendPasswordResetEmail always returns { error: null } to prevent
      // email enumeration — the Supabase error is swallowed intentionally.
      const { error } = await sendPasswordResetEmail(email.trim().toLowerCase());

      // Treat any unexpected error as non-fatal; still show the success screen.
      if (error) {
        console.error("Password reset error:", error);
      }

      setScreen("sent");
    } catch (err) {
      console.error("Unexpected error:", err);
      setGlobalErr("An unexpected error occurred. Please try again.");
    } finally {
      setLoading(false);
    }
  }

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
            {screen === "form" ? "Reset your password" : "Check your inbox"}
          </p>
        </div>

        {/* Card */}
        <div className="rounded-2xl border border-slate-800 bg-[#1a1a2e] p-8 shadow-xl">

          {/* ── Screen A: form ── */}
          {screen === "form" && (
            <>
              {globalErr && (
                <div className="mb-5 flex items-start gap-2 rounded-lg border border-red-500/30
                                bg-red-500/10 px-4 py-3 text-sm text-red-400">
                  <AlertCircle size={16} className="mt-0.5 shrink-0" />
                  <span>{globalErr}</span>
                </div>
              )}

              <p className="mb-6 text-sm text-slate-400 leading-relaxed">
                Enter the email address for your admin account. If it matches a registered
                admin, you will receive a password-reset link within a few minutes.
              </p>

              <form onSubmit={handleSubmit} noValidate className="space-y-5">
                <div className="space-y-1.5">
                  <label
                    htmlFor="reset-email"
                    className="block text-sm font-medium text-slate-300"
                  >
                    Email address
                  </label>
                  <div className="relative">
                    <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none">
                      <Mail size={16} />
                    </span>
                    <input
                      id="reset-email"
                      type="email"
                      autoComplete="email"
                      autoFocus
                      value={email}
                      onChange={e => {
                        setEmail(e.target.value);
                        setEmailErr("");
                      }}
                      placeholder="admin@yourapp.com"
                      disabled={loading}
                      className={[
                        "w-full rounded-lg border bg-slate-900 pl-10 pr-4 py-2.5",
                        "text-sm text-slate-100 placeholder-slate-600 outline-none transition",
                        "focus:border-red-500 focus:ring-2 focus:ring-red-500/20",
                        emailErr
                          ? "border-red-500/70"
                          : "border-slate-700 hover:border-slate-600",
                      ].join(" ")}
                    />
                  </div>
                  {emailErr && (
                    <p className="flex items-center gap-1 text-xs text-red-400">
                      <AlertCircle size={12} /> {emailErr}
                    </p>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="flex w-full items-center justify-center gap-2 rounded-lg
                             bg-gradient-to-r from-red-600 to-red-700 px-4 py-2.5
                             text-sm font-semibold text-white shadow-md shadow-red-900/30
                             transition hover:from-red-500 hover:to-red-600 active:scale-[0.98]
                             disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? (
                    <RefreshCw size={16} className="animate-spin" />
                  ) : (
                    "Send reset link"
                  )}
                </button>
              </form>
            </>
          )}

          {/* ── Screen B: success ── */}
          {screen === "sent" && (
            <div className="text-center space-y-5">
              <div className="mx-auto flex h-16 w-16 items-center justify-center
                              rounded-full bg-green-500/10 border border-green-500/30">
                <CheckCircle size={32} className="text-green-400" />
              </div>

              <div className="space-y-2">
                <h2 className="text-lg font-semibold text-white">Link sent</h2>
                <p className="text-sm text-slate-400 leading-relaxed">
                  If <span className="font-medium text-slate-200">{email}</span> is
                  registered as an admin, you will receive a password reset link shortly.
                </p>
              </div>

              <div className="rounded-lg border border-slate-700 bg-slate-900/60 px-4 py-3 text-left">
                <p className="text-xs text-slate-500 leading-relaxed">
                  <strong className="text-slate-400">Didn't receive it?</strong>
                  {" "}Check your spam folder. The link expires in 1 hour.
                  You can{" "}
                  <button
                    type="button"
                    onClick={() => setScreen("form")}
                    className="text-red-400 hover:underline"
                  >
                    try again
                  </button>
                  {" "}with a different address.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Back to login */}
        <div className="mt-6 text-center">
          <a
            href={loginHref}
            className="inline-flex items-center gap-1.5 text-sm text-slate-500
                       hover:text-slate-300 transition"
          >
            <ArrowLeft size={14} /> Back to login
          </a>
        </div>
      </div>
    </div>
  );
}
