import { useState } from 'react';
import { supabase } from '../services/auth';

export default function AuthPanel({ user, recovery, onClose }) {
  const [mode, setMode] = useState(recovery ? 'update' : 'login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event) {
    event.preventDefault(); setBusy(true); setMessage('');
    try {
      if (!supabase) throw new Error('Account setup is pending. Please try again after the service is configured.');
      let response;
      if (mode === 'login') response = await supabase.auth.signInWithPassword({ email, password });
      if (mode === 'signup') response = await supabase.auth.signUp({ email, password, options: { emailRedirectTo: window.location.origin + '/' } });
      if (mode === 'reset') response = await supabase.auth.resetPasswordForEmail(email, { redirectTo: window.location.origin + '/' });
      if (mode === 'update') {
        response = await supabase.auth.updateUser({ password });
        if (!response.error) {
          const { error } = await supabase.auth.signOut({ scope: 'global' });
          if (error) throw new Error('Password changed. Sign out of other sessions from your account and try again.');
          setMode('login'); setMessage('Password updated. Sign in again.'); setPassword(''); return;
        }
      }
      // Match messages for existing and unknown addresses; do not expose provider details.
      if (mode === 'signup' || mode === 'reset') {
        setMessage('If this address is eligible, an email will arrive with the next steps. Check your spam folder too.');
      } else if (response?.error) {
        setMessage(mode === 'login' ? 'Unable to sign in. Check your details and email confirmation, or reset your password.' : 'Unable to update the password. Request a fresh recovery link and try again.');
      } else if (mode === 'login') onClose();
      setPassword('');
    } catch (error) { setMessage(error.message || 'Account service is temporarily unavailable.'); }
    finally { setBusy(false); }
  }
  return <section className="panel account-panel" id="account" aria-labelledby="account-title">
    <div className="panel-heading-row"><h2 id="account-title">{user && !['update', 'reset'].includes(mode) ? 'Your account' : { login: 'Sign in', signup: 'Create an account', reset: 'Reset your password', update: 'Choose a new password' }[mode]}</h2><button className="ghost-button" onClick={onClose}>Close</button></div>
    {user && !['update', 'reset'].includes(mode) ? <><p>Signed in as {user.email}</p><p>Your investigation history belongs to your account.</p><button className="secondary-button" disabled={busy} onClick={async () => { setBusy(true); const { error } = await supabase.auth.signOut({ scope: 'global' }); setBusy(false); if (error) setMessage('Could not sign out. Try again.'); else onClose(); }}>Sign out of all devices</button><button className="ghost-button" onClick={() => { setEmail(user.email); setMode('reset'); }}>Reset password</button></> : <form onSubmit={submit}>
      <p>Sign in to investigate suspicious content, save private cases, and revisit findings.</p>
      {!supabase && <p role="status">Account service is awaiting configuration.</p>}
      {mode !== 'update' && <label>Email address<input type="email" required autoComplete="email" value={email} onChange={e => setEmail(e.target.value)} maxLength={254} /></label>}
      {mode !== 'reset' && <label>Password<input type="password" required minLength={mode === 'login' ? 1 : 12} maxLength={128} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} value={password} onChange={e => setPassword(e.target.value)} /></label>}
      {(mode === 'signup' || mode === 'update') && <p>Use a unique passphrase of at least 12 characters.</p>}
      {mode === 'signup' && <label className="consent"><input type="checkbox" required /> <span>I am at least 18, agree to the <a href="/terms.html">terms</a> and have read the <a href="/privacy.html">privacy notice</a>.</span></label>}
      <button className="primary-button" disabled={busy || !supabase}>{busy ? 'Please wait…' : {login:'Sign in',signup:'Create account',reset:'Send recovery email',update:'Update password'}[mode]}</button>
      <div className="account-links">{mode !== 'login' && <button type="button" className="ghost-button" onClick={() => {setMode('login');setMessage('');}}>Back to sign in</button>}{mode === 'login' && <><button type="button" className="ghost-button" onClick={() => setMode('signup')}>Create an account</button><button type="button" className="ghost-button" onClick={() => setMode('reset')}>Forgot password?</button></>}</div>
    </form>}
    {message && <p role="status" aria-live="polite">{message}</p>}
  </section>;
}
