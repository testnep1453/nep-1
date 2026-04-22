/**
 * Supabase Edge Function: send-otp
 *
 * Generates a 6-digit OTP for an authenticated admin, stores a bcrypt hash
 * via the store_admin_otp() RPC, and emails the plaintext code via Resend.
 *
 * Required env vars (set in Supabase Dashboard → Edge Functions → Secrets):
 *   RESEND_API_KEY        – Resend API key (https://resend.com)
 *   OTP_FROM_EMAIL        – Verified sender address, e.g. noreply@yourapp.com
 *   SUPABASE_URL          – Auto-injected by Supabase
 *   SUPABASE_SERVICE_ROLE_KEY – Auto-injected by Supabase
 *
 * Deploy:
 *   supabase functions deploy send-otp --no-verify-jwt
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.102.1";

const RESEND_API_KEY         = Deno.env.get("RESEND_API_KEY")!;
const OTP_FROM_EMAIL         = Deno.env.get("OTP_FROM_EMAIL") ?? "noreply@yourapp.com";
const SUPABASE_URL           = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE  = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const OTP_TTL_MS      = 5 * 60 * 1000;   // 5 minutes
const RATE_LIMIT_MAX  = 3;                // max OTPs per window
const RATE_LIMIT_MS   = 10 * 60 * 1000;  // 10-minute window

const CORS_HEADERS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

/** Cryptographically random 6-digit string. */
function generateOtp(): string {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return String(100000 + (arr[0] % 900000));
}

Deno.serve(async (req: Request) => {
  // ── Preflight ──────────────────────────────────────────────────────────────
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: CORS_HEADERS });
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed." }, 405);
  }

  try {
    // ── Authenticate caller ────────────────────────────────────────────────
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return json({ error: "Unauthorized." }, 401);
    }

    // Verify the JWT and resolve the calling user
    const userClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
      global: { headers: { Authorization: authHeader } },
      auth:   { persistSession: false },
    });

    const { data: { user }, error: userErr } = await userClient.auth.getUser();
    if (userErr || !user) {
      return json({ error: "Unauthorized." }, 401);
    }

    // ── Authorise: caller must be a registered admin ───────────────────────
    const svc = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
      auth: { persistSession: false },
    });

    const { data: adminRow, error: adminErr } = await svc
      .from("admins")
      .select("email, role, is_super_admin")
      .eq("auth_user_id", user.id)
      .single();

    if (adminErr || !adminRow) {
      return json({ error: "Forbidden." }, 403);
    }

    const adminEmail = adminRow.email as string;

    // ── Rate limiting ──────────────────────────────────────────────────────
    const windowStart = new Date(Date.now() - RATE_LIMIT_MS).toISOString();

    const { count, error: countErr } = await svc
      .from("admin_otps")
      .select("id", { count: "exact", head: true })
      .eq("admin_email", adminEmail)
      .gte("created_at", windowStart);

    if (countErr) {
      console.error("Rate-limit check failed:", countErr);
      return json({ error: "Internal error." }, 500);
    }

    if ((count ?? 0) >= RATE_LIMIT_MAX) {
      return json(
        { error: "Too many requests. Wait 10 minutes before requesting a new code." },
        429,
      );
    }

    // ── Generate & store OTP ───────────────────────────────────────────────
    const otp       = generateOtp();
    const expiresAt = new Date(Date.now() + OTP_TTL_MS).toISOString();
    const clientIp  = (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim() || null;

    const { error: storeErr } = await svc.rpc("store_admin_otp", {
      p_email:      adminEmail,
      p_otp:        otp,
      p_expires_at: expiresAt,
      p_ip_address: clientIp,
    });

    if (storeErr) {
      console.error("store_admin_otp failed:", storeErr);
      return json({ error: "Failed to create OTP." }, 500);
    }

    // ── Send email via Resend ─────────────────────────────────────────────
    const emailPayload = {
      from:    `NEP Admin <${OTP_FROM_EMAIL}>`,
      to:      [adminEmail],
      subject: `[NEP] Admin verification code: ${otp}`,
      html: `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0f0f1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:40px 16px;">
      <table width="480" cellpadding="0" cellspacing="0"
             style="background:#1a1a2e;border-radius:12px;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,.4);">
        <tr>
          <td style="background:linear-gradient(135deg,#16213e,#0f3460);padding:32px;text-align:center;">
            <p style="margin:0;font-size:24px;font-weight:700;color:#e94560;letter-spacing:2px;">NEP ADMIN</p>
            <p style="margin:8px 0 0;font-size:13px;color:#aaa;">Verification Required</p>
          </td>
        </tr>
        <tr>
          <td style="padding:40px 32px;text-align:center;">
            <p style="margin:0 0 8px;font-size:14px;color:#888;">Your one-time verification code</p>
            <div style="display:inline-block;margin:16px 0;padding:20px 40px;background:#0f0f1a;
                        border-radius:8px;border:1px solid #e9456040;">
              <span style="font-size:40px;font-weight:800;letter-spacing:12px;color:#e94560;
                           font-variant-numeric:tabular-nums;">${otp}</span>
            </div>
            <p style="margin:0;font-size:13px;color:#666;">
              Expires in <strong style="color:#aaa;">5 minutes</strong> &mdash; single use only.
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:0 32px 32px;text-align:center;">
            <p style="margin:0;font-size:11px;color:#444;line-height:1.6;">
              If you did not request this code, your account credentials may be compromised.<br>
              Contact your system administrator immediately.
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
    };

    const resendRes = await fetch("https://api.resend.com/emails", {
      method:  "POST",
      headers: {
        Authorization:  `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(emailPayload),
    });

    if (!resendRes.ok) {
      const resendError = await resendRes.json().catch(() => ({}));
      console.error("Resend error:", resendError);
      return json({ error: "Failed to send verification email." }, 500);
    }

    return json({ success: true, message: "Verification code sent to your email." });
  } catch (err) {
    console.error("Unexpected error in send-otp:", err);
    return json({ error: "Internal server error." }, 500);
  }
});
