import { supabase } from './supabase'

/**
 * Request a 6-digit OTP to be sent to the given Philippine phone number via Brevo SMS.
 *
 * @param {string} phone  — e.g. "09171234567" or "+639171234567"
 * @returns {Promise<{ sent: boolean, expiresInMinutes: number }>}
 */
export async function requestPhoneOtp(phone) {
  const { data, error } = await supabase.functions.invoke('send-phone-otp', {
    body: { phone, action: 'send' },
  })
  if (error) throw new Error(error.message || 'Failed to send OTP')
  if (data?.error) throw new Error(data.error)
  return data
}

/**
 * Verify the OTP the user entered.
 *
 * @param {string} phone  — same number used in requestPhoneOtp()
 * @param {string} code   — 6-digit code entered by user
 * @returns {Promise<{ verified: boolean }>}
 */
export async function verifyPhoneOtp(phone, code) {
  const { data, error } = await supabase.functions.invoke('send-phone-otp', {
    body: { phone, action: 'verify', code },
  })
  if (error) throw new Error(error.message || 'Verification failed')
  if (data?.error) throw new Error(data.error)
  return data
}
