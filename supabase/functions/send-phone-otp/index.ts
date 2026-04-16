// supabase/functions/send-phone-otp/index.ts
//
// Deploy with:
//   supabase functions deploy send-phone-otp
//
// Required secrets (Supabase Dashboard → Edge Functions → Secrets):
//   BREVO_API_KEY       — your Brevo API key (https://app.brevo.com/settings/keys/api)
//   BREVO_SMS_SENDER    — sender name shown on the SMS (e.g. "YouthLink"), max 11 chars, no spaces
//   SUPABASE_URL        — auto-injected by Supabase
//   SUPABASE_SERVICE_ROLE_KEY — auto-injected by Supabase
//
// POST body: { phone: "+639XXXXXXXXX", action: "send" | "verify", code?: string }
// The function stores hashed OTPs in the `phone_otps` table (see migration below).
// ─────────────────────────────────────────────────────────────────────────────
//
// Required DB migration (run once in Supabase SQL editor):
// ─────────────────────────────────────────────────────────────────────────────
// create table if not exists public.phone_otps (
//   id          uuid primary key default gen_random_uuid(),
//   phone       text not null,
//   code_hash   text not null,
//   expires_at  timestamptz not null,
//   used        boolean not null default false,
//   created_at  timestamptz not null default now()
// );
// create index on public.phone_otps (phone, expires_at);
// -- Auto-clean expired rows older than 10 minutes
// -- (optional: add a pg_cron job or just let the function clean up)
// ─────────────────────────────────────────────────────────────────────────────

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

const OTP_TTL_MINUTES = 5
const OTP_LENGTH      = 6
const MAX_ATTEMPTS    = 5  // per phone per TTL window

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Generate a random numeric OTP of the given length. */
function generateOtp(length = OTP_LENGTH): string {
  const digits = new Uint8Array(length)
  crypto.getRandomValues(digits)
  return Array.from(digits).map(d => d % 10).join('')
}

/** SHA-256 hash of the OTP (we never store the plaintext). */
async function hashOtp(code: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code))
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
}

/** Normalise Philippine phone numbers to E.164 (+63…). */
function normalisePhone(raw: string): string | null {
  const digits = raw.replace(/\D/g, '')
  // 09XXXXXXXXX → +639XXXXXXXXX
  if (/^09\d{9}$/.test(digits)) return `+63${digits.slice(1)}`
  // 639XXXXXXXXX or +639XXXXXXXXX
  if (/^639\d{9}$/.test(digits)) return `+${digits}`
  if (/^\+639\d{9}$/.test(raw.trim())) return raw.trim()
  return null
}

/** Send an SMS via Brevo Transactional SMS API. */
async function sendBrevoSms(opts: {
  apiKey: string
  sender: string
  to: string      // E.164
  content: string // SMS body (≤ 160 chars for 1 part)
}): Promise<void> {
  const res = await fetch('https://api.brevo.com/v3/transactionalSMS/sms', {
    method: 'POST',
    headers: {
      'accept':       'application/json',
      'api-key':      opts.apiKey,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      sender:    opts.sender,
      recipient: opts.to,
      content:   opts.content,
      type:      'transactional',
    }),
  })

  if (!res.ok) {
    const body = await res.text()
    throw new Error(`Brevo SMS error ${res.status}: ${body}`)
  }
}

// ── Main handler ─────────────────────────────────────────────────────────────

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })

  try {
    const { phone: rawPhone, action, code } = await req.json() as {
      phone: string
      action: 'send' | 'verify'
      code?: string
    }

    if (!rawPhone || !action) {
      return json({ error: 'Missing phone or action' }, 400)
    }

    const phone = normalisePhone(rawPhone)
    if (!phone) {
      return json({ error: 'Invalid Philippine phone number. Use format: 09XXXXXXXXX' }, 400)
    }

    const BREVO_API_KEY    = Deno.env.get('BREVO_API_KEY')
    const BREVO_SMS_SENDER = Deno.env.get('BREVO_SMS_SENDER') || 'YouthLink'

    if (!BREVO_API_KEY) throw new Error('BREVO_API_KEY secret is not set')

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    )

    // ── SEND ──────────────────────────────────────────────────────────────────
    if (action === 'send') {
      // Rate-limit: max MAX_ATTEMPTS active (unused, non-expired) OTPs per phone
      const { count } = await supabase
        .from('phone_otps')
        .select('*', { count: 'exact', head: true })
        .eq('phone', phone)
        .eq('used', false)
        .gt('expires_at', new Date().toISOString())

      if ((count ?? 0) >= MAX_ATTEMPTS) {
        return json({ error: 'Too many OTP requests. Please wait a few minutes.' }, 429)
      }

      // Invalidate any previous unused OTPs for this phone
      await supabase
        .from('phone_otps')
        .update({ used: true })
        .eq('phone', phone)
        .eq('used', false)

      // Generate + store OTP
      const otp       = generateOtp()
      const codeHash  = await hashOtp(otp)
      const expiresAt = new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000).toISOString()

      const { error: insertErr } = await supabase
        .from('phone_otps')
        .insert({ phone, code_hash: codeHash, expires_at: expiresAt })

      if (insertErr) throw insertErr

      // Send via Brevo
      await sendBrevoSms({
        apiKey:  BREVO_API_KEY,
        sender:  BREVO_SMS_SENDER,
        to:      phone,
        content: `Your YouthLink verification code is: ${otp}\nValid for ${OTP_TTL_MINUTES} minutes. Do not share this with anyone.`,
      })

      return json({ sent: true, expiresInMinutes: OTP_TTL_MINUTES })
    }

    // ── VERIFY ────────────────────────────────────────────────────────────────
    if (action === 'verify') {
      if (!code || !/^\d{6}$/.test(code)) {
        return json({ error: 'Invalid OTP format. Enter the 6-digit code.' }, 400)
      }

      const codeHash = await hashOtp(code)

      const { data: otpRow, error: fetchErr } = await supabase
        .from('phone_otps')
        .select('id, expires_at, used')
        .eq('phone', phone)
        .eq('code_hash', codeHash)
        .eq('used', false)
        .gt('expires_at', new Date().toISOString())
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle()

      if (fetchErr) throw fetchErr

      if (!otpRow) {
        return json({ verified: false, error: 'Incorrect or expired OTP. Please try again.' }, 400)
      }

      // Mark OTP as used
      await supabase
        .from('phone_otps')
        .update({ used: true })
        .eq('id', otpRow.id)

      // Update the profile's phone_verified flag
      await supabase
        .from('profiles')
        .update({ phone_verified: true, contact_number: phone })
        .eq('contact_number', phone)

      return json({ verified: true })
    }

    return json({ error: `Unknown action: ${action}` }, 400)

  } catch (err) {
    console.error('[send-phone-otp]', err)
    return json({ error: (err as Error).message }, 500)
  }
})

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  })
}
