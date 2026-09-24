import { createClient } from '@supabase/supabase-js';
const url = import.meta.env.VITE_SUPABASE_URL;
const key = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
export const supabase = url && key ? createClient(url, key, {
  auth: { flowType: 'pkce', persistSession: true, autoRefreshToken: true, detectSessionInUrl: true },
}) : null;
export async function accessToken() {
  if (!supabase) throw new Error('Account service is not configured yet.');
  const { data, error } = await supabase.auth.getSession();
  if (error || !data.session) {
    const expired = new Error('Please sign in to investigate and view your private history.');
    expired.status = 401;
    throw expired;
  }
  return data.session.access_token;
}
