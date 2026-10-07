import { useState } from 'react';
import { send } from '../api';
import { Icon, SecurityPipeline } from './CyberVisuals';

export default function Auth({ onLogin }) {
  const [register, setRegister] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function submit(event) {
    event.preventDefault();
    setBusy(true); setError('');
    try { onLogin(await send(`/auth/${register ? 'register' : 'login'}`, { username, password })); }
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
      <div className="scope-note">Local inference by default. External checks only when you enable them.</div>
    </section>
    <section className="auth-card">
      <div className="auth-card-symbol"><Icon name="shield" size={27} /></div><div className="eyebrow">YOUR SECURITY WORKSPACE</div>
      <h2>{register ? 'Create an account' : 'Welcome back'}</h2>
      <p>{register ? 'Save your scans and personal protection settings.' : 'Sign in to inspect your next suspicious message.'}</p>
      <form onSubmit={submit}>
        <label htmlFor="username">Username</label><input id="username" autoComplete="username" pattern="[a-zA-Z0-9_.-]{3,40}" minLength={3} maxLength={40} required value={username} onChange={e => setUsername(e.target.value)} placeholder="Your username" />
        <label htmlFor="password">Password</label><div className="password-wrapper"><input id="password" type={visible ? 'text' : 'password'} autoComplete={register ? 'new-password' : 'current-password'} minLength={8} maxLength={128} required value={password} onChange={e => setPassword(e.target.value)} placeholder="At least 8 characters" /><button type="button" className="password-toggle" onClick={() => setVisible(!visible)} aria-label={visible ? 'Hide password' : 'Show password'}>{visible ? 'Hide' : 'Show'}</button></div>
        {error && <div className="notice error" role="alert">{error}</div>}
        <button className="primary-btn full" disabled={busy}>{busy ? 'Connecting…' : register ? 'Create account →' : 'Enter workspace →'}</button>
      </form>
      <button className="text-btn" onClick={() => { setRegister(!register); setError(''); }}>{register ? 'Already registered? Sign in' : 'New here? Create an account'}</button>
      <p className="small">Accounts from the previous browser-only version need to be registered again.</p>
    </section>
  </main>;
}
