import { useEffect, useState } from 'react';
import { send } from '../api';
import { Icon, SecurityPipeline } from './CyberVisuals';

export default function Auth({ onLogin }) {
  const [register, setRegister] = useState(false);
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [sentAt, setSentAt] = useState(0);
  const [remaining, setRemaining] = useState(0);
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    if (!verifying) return undefined;
    const update = () => setRemaining(Math.max(0, 60 - Math.floor((Date.now() - sentAt) / 1000)));
    update();
    const timer = window.setInterval(update, 1000);
    return () => window.clearInterval(timer);
  }, [sentAt, verifying]);
  async function requestCode() {
    await send('/auth/register', { username, email, password });
    setSentAt(Date.now());
    setVerifying(true);
    setCode('');
  }
  async function submit(event) {
    event.preventDefault();
    setBusy(true); setError('');
    try {
      if (register && verifying) onLogin(await send('/auth/register/verify', { username, email, code }));
      else if (register) await requestCode();
      else onLogin(await send('/auth/login', { username, password }));
    }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  async function resend() {
    setBusy(true); setError('');
    try { await requestCode(); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  return <main className="auth-layout">
    <section className="auth-intro">
      <div className="brand"><span className="brand-symbol"><Icon name="shield" size={22} /></span> PhishGuard<span className="brand-tag">ML</span></div>
      <div className="eyebrow">COMPUTER NETWORKS / SECURITY PROJECT</div>
      <h1>Clarity before<br />every <span>click.</span></h1>
      <p className="lead">Phishing Attack Detection and Prevention Using Machine Learning</p>
      <p>Inspect suspicious URLs and emails. Understand the warning signs. Keep sensitive information out of the wrong hands.</p>
      <div className="intro-features"><span>01 / URL intelligence</span><span>02 / Email analysis</span><span>03 / Security reports</span></div>
      <SecurityPipeline compact />
      <div className="scope-note">Server-side analysis by default. Target lookups only when you enable them.</div>
    </section>
    <section className="auth-card">
      <div className="auth-card-symbol"><Icon name="shield" size={27} /></div><div className="eyebrow">YOUR SECURITY WORKSPACE</div>
      <h2>{register ? verifying ? 'Verify your email' : 'Create an account' : 'Welcome back'}</h2>
      <p>{register ? verifying ? `Enter the six-digit code sent to ${email}. It expires in 10 minutes.` : 'Verify your email to save scans and protection settings.' : 'Sign in to inspect your next suspicious message.'}</p>
      <form onSubmit={submit}>
        {verifying ? <><label htmlFor="verification-code">Verification code</label><input id="verification-code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" minLength={6} maxLength={6} required value={code} onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="6-digit code" /></> : <>
          <label htmlFor="username">Username</label><input id="username" autoComplete="username" pattern="[a-zA-Z0-9_.-]{3,40}" minLength={3} maxLength={40} required value={username} onChange={e => setUsername(e.target.value)} placeholder="Your username" />
          {register && <><label htmlFor="email">Email address</label><input id="email" type="email" autoComplete="email" maxLength={254} required value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com" /></>}
          <label htmlFor="password">Password</label><div className="password-wrapper"><input id="password" type={visible ? 'text' : 'password'} autoComplete={register ? 'new-password' : 'current-password'} minLength={8} maxLength={128} required value={password} onChange={e => setPassword(e.target.value)} placeholder="At least 8 characters" /><button type="button" className="password-toggle" onClick={() => setVisible(!visible)} aria-label={visible ? 'Hide password' : 'Show password'}>{visible ? 'Hide' : 'Show'}</button></div>
        </>}
        {error && <div className="notice error" role="alert">{error}</div>}
        <button className="primary-btn full" disabled={busy}>{busy ? 'Connecting…' : register ? verifying ? 'Verify & create account →' : 'Send verification code →' : 'Enter workspace →'}</button>
      </form>
      {verifying && <><button className="text-btn" type="button" disabled={busy || remaining > 0} onClick={resend}>{remaining ? `Resend code in ${remaining}s` : 'Resend code'}</button><button className="text-btn" type="button" onClick={() => { setVerifying(false); setError(''); }}>Edit account details</button></>}
      <button className="text-btn" onClick={() => { setRegister(!register); setVerifying(false); setError(''); }}>{register ? 'Already registered? Sign in' : 'New here? Create an account'}</button>
      <p className="small">Accounts from the previous browser-only version need to be registered again.</p>
    </section>
  </main>;
}
