import { useEffect, useState } from 'react';
import { api } from './api';
import Auth from './components/Auth';
import Scanner from './components/Scanner';
import Reports from './pages/Reports';
import ModelLab from './pages/ModelLab';
import Protection from './pages/Protection';
import Academy from './pages/Academy';
import Settings from './pages/Settings';
import AdminPanel from './pages/AdminPanel';
import { AmbientField, Icon } from './components/CyberVisuals';
import CommandPalette from './components/CommandPalette';
import { useMediaQuery } from './hooks';

const navigation = [
  ['dashboard', 'scan', 'Detection center'], ['reports', 'reports', 'Scan reports'],
  ['protection', 'shield', 'Protection'], ['models', 'models', 'Model lab'], ['academy', 'learn', 'Learn'], ['settings', 'settings', 'Settings'],
];

export default function App() {
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(true);
  const [page, setPage] = useState('dashboard');
  const [menu, setMenu] = useState(false);
  const [error, setError] = useState('');
  const [command, setCommand] = useState(false);
  const [motion, setMotion] = useState(() => localStorage.getItem('phishguard-motion') !== 'off');
  const mobile = useMediaQuery('(max-width: 700px)');
  useEffect(() => {
    document.documentElement.dataset.motion = motion ? 'on' : 'off';
    localStorage.setItem('phishguard-motion', motion ? 'on' : 'off');
  }, [motion]);
  useEffect(() => {
    function shortcut(event) {
      if (!user) return;
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault(); setCommand(value => !value);
      }
    }
    window.addEventListener('keydown', shortcut);
    return () => window.removeEventListener('keydown', shortcut);
  }, [user]);
  useEffect(() => {
    api('/auth/me').then(setUser).catch(err => { if (err.status !== 401) setError(err.message); }).finally(() => setChecking(false));
  }, []);
  async function logout() {
    try { await api('/auth/logout', { method: 'POST' }); setUser(null); setPage('dashboard'); }
    catch (err) { setError(err.message); }
  }
  if (checking) return <div className="boot-screen"><div className="boot-emblem"><Icon name="shield" size={32} /></div><span>Connecting to PhishGuard…</span></div>;
  if (!user) return <><AmbientField paused={!motion} /><Auth onLogin={setUser} />{error && <div className="connection-banner" role="alert">{error}</div>}</>;
  const items = user.role === 'admin' ? [...navigation, ['admin', 'activity', 'Activity logs']] : navigation;
  function navigate(target) { setPage(target); setMenu(false); setCommand(false); }
  return <div className="layout">
    <a className="skip-link" href="#main-content">Skip to content</a>
    <AmbientField paused={!motion} />
    {menu && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setMenu(false)} />}
    <aside className={`sidebar ${menu ? 'open' : ''}`} id="workspace-navigation" inert={mobile && !menu} onKeyDown={event => { if (event.key === 'Escape') setMenu(false); }}>
      <div className="brand"><span className="brand-symbol"><Icon name="shield" size={22} /></span> PhishGuard<span className="brand-tag">ML</span></div>
      <p className="nav-heading">SECURITY WORKSPACE</p>
      <nav aria-label="Main navigation">{items.map(([target, icon, label]) => <button key={target} className={`nav-item ${page === target ? 'active' : ''}`} aria-current={page === target ? 'page' : undefined} onClick={() => navigate(target)}><Icon name={icon} />{label}{page === target && <i className="nav-active-dot" />}</button>)}</nav>
      <div className="sidebar-intel"><div className="sidebar-intel-icon"><Icon name="shield" size={22} /><span /></div><strong>Your instinct. Upgraded.</strong><p>A closer look at every suspicious link and message.</p><span className="intel-footnote">LOCAL WORKSPACE / V2.0</span></div>
      <div className="sidebar-bottom"><div className="user-avatar">{user.username[0].toUpperCase()}</div><div><strong>{user.username}</strong><span>{user.role === 'admin' ? 'Administrator' : 'Personal workspace'}</span></div><button onClick={logout} className="icon-btn" aria-label="Sign out" title="Sign out"><Icon name="logout" size={17} /></button></div>
    </aside>
    <main className="main-content" id="main-content" tabIndex={-1}>
      <header className="topbar"><div className="breadcrumb"><span className="breadcrumb-mark"><Icon name="shield" size={14} /></span> WORKSPACE <span>/</span> {items.find(item => item[0] === page)?.[2]}</div><div className="topbar-right"><button className="command-trigger" onClick={() => setCommand(true)} aria-label="Search workspace"><Icon name="search" size={15} /><span>Jump to…</span><kbd>Ctrl K</kbd></button><button className="motion-toggle icon-btn" onClick={() => setMotion(!motion)} aria-label={motion ? 'Pause animations' : 'Enable animations'} title={motion ? 'Pause animations' : 'Enable animations'} aria-pressed={!motion}><Icon name={motion ? 'pause' : 'play'} size={14} /></button><span className="local-badge"><i /> Local analysis</span><button className="menu-button" onClick={() => setMenu(!menu)} aria-expanded={menu} aria-controls="workspace-navigation"><Icon name={menu ? 'close' : 'menu'} size={16} /><span>Menu</span></button></div></header>
      {error && <div className="notice error" role="alert">{error}<button className="text-btn" onClick={() => setError('')}>Dismiss</button></div>}
      <div className="page-transition" key={page}>
      {page === 'dashboard' && <Scanner />}
      {page === 'reports' && <Reports />}
      {page === 'protection' && <Protection />}
      {page === 'models' && <ModelLab />}
      {page === 'academy' && <Academy />}
      {page === 'settings' && <Settings />}
      {page === 'admin' && user.role === 'admin' && <AdminPanel />}
      </div>
      <footer>PHISHGUARD / Computer Networks Project <span>ML estimates support decisions; they cannot guarantee safety.</span></footer>
    </main>
    {command && <CommandPalette items={items} onNavigate={navigate} onClose={() => setCommand(false)} />}
  </div>;
}
