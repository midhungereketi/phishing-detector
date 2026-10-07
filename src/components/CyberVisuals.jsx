import { useEffect, useRef, useState } from 'react';

export function Icon({ name = 'shield', size = 20, ...props }) {
  const paths = {
    shield: <><path d="M12 3 4.5 6v6c0 4.3 7.5 9 7.5 9s7.5-4.7 7.5-9V6L12 3Z" /><path d="m8.5 12 2.5 2.5 4.5-5" /></>,
    scan: <><path d="M8 3H4v4m12-4h4v4M4 17v4h4m12-4v4h-4M3 12h18" /><circle cx="12" cy="12" r="4" /></>,
    reports: <><path d="M6 3h9l3 3v15H6zM14 3v5h4M9 12h6m-6 4h6" /></>,
    models: <><circle cx="12" cy="12" r="3" /><circle cx="5" cy="5" r="2" /><circle cx="19" cy="5" r="2" /><circle cx="5" cy="19" r="2" /><circle cx="19" cy="19" r="2" /><path d="m6.5 6.5 3.4 3.4m4.2 4.2 3.4 3.4m0-11-3.4 3.4m-4.2 4.2-3.4 3.4" /></>,
    learn: <><path d="m2 8 10-5 10 5-10 5-10-5Zm4 2v7l6 3 6-3v-7m4-2v9" /></>,
    settings: <><path d="m9 3-1 3-3 1-2 3 2 2-1 3 3 2 1 3h4l1-3 3-1 2-3-2-2 1-3-3-2-1-3H9Z" /><circle cx="10.5" cy="11.5" r="3" /></>,
    arrow: <path d="M5 12h14m-6-6 6 6-6 6" />,
    search: <><circle cx="10" cy="10" r="6" /><path d="m15 15 5 5" /></>,
    mail: <><rect x="3" y="5" width="18" height="14" rx="3" /><path d="m3 7 9 6 9-6" /></>,
    link: <><path d="m10 13 4-4m-6 6-1 1a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0m2 2 1-1a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0" /></>,
    activity: <path d="M2 12h5l3-8 4 16 3-8h5" />,
    menu: <path d="M4 6h16M4 12h16M4 18h16" />,
    close: <path d="m6 6 12 12M18 6 6 18" />,
    logout: <><path d="M9 4H4v16h5m4-12 4 4-4 4m-6-4h13" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    warning: <><path d="m12 3 10 18H2L12 3Z" /><path d="M12 9v5m0 3v.1" /></>,
    pause: <><path d="M8 5v14M16 5v14" /></>,
    play: <path d="m8 5 11 7-11 7V5Z" />,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>{paths[name] || paths.shield}</svg>;
}

// Code-native vector artwork remains sharp at every viewport size.
export function SecurityPipeline({ compact = false }) {
  return <div className={`security-pipeline ${compact ? 'compact' : ''}`} aria-hidden="true">
    <svg viewBox="0 0 480 210" className="pipeline-svg">
      <g fill="none" stroke="currentColor" strokeWidth="1" className="pipeline-grid">{[30,70,110,150,190].map(y => <path key={y} d={`M0 ${y}h480`}/>)}{[20,60,100,140,180,220,260,300,340,380,420,460].map(x => <path key={x} d={`M${x} 0v210`}/>)}</g>
      <g fill="none" stroke="#5977a3" strokeWidth="1.5"><path d="M95 58h65q15 0 15 15v32h32M95 152h65q15 0 15-15v-32M273 105h39q15 0 15-15V58h53M327 105v32q0 15 15 15h38"/></g>
      <g className="pipeline-flow" fill="none" stroke="#4d91ff" strokeWidth="2" strokeDasharray="7 115"><path d="M95 58h65q15 0 15 15v32h32M273 105h39q15 0 15-15V58h53M327 105v32q0 15 15 15h38"/></g>
      <g className="pipeline-node"><rect x="24" y="35" width="84" height="46" rx="9"/><rect x="24" y="129" width="84" height="46" rx="9"/><rect x="374" y="35" width="88" height="46" rx="9"/><rect x="374" y="129" width="88" height="46" rx="9"/></g>
      <rect x="203" y="68" width="74" height="74" rx="18" fill="#2563eb" stroke="#80aaff"/>
      <path d="m240 84-18 7v14c0 13 18 23 18 23s18-10 18-23V91l-18-7Z" fill="none" stroke="white" strokeWidth="2"/><path d="m231 105 6 6 12-14" fill="none" stroke="white" strokeWidth="2" strokeLinecap="round"/>
      <g fontFamily="system-ui, sans-serif" fontSize="12" fontWeight="600" textAnchor="middle" className="pipeline-label"><text x="66" y="63">URL</text><text x="66" y="157">EMAIL</text><text x="418" y="63">EVIDENCE</text><text x="418" y="157">VERDICT</text></g>
      <text x="240" y="166" textAnchor="middle" fontFamily="system-ui, sans-serif" fontSize="10" letterSpacing="1.5" fill="#9baecc">ML ENGINE</text>
    </svg>
  </div>;
}

export function AnimatedNumber({ value, pad = true }) {
  const [display, setDisplay] = useState(value);
  const previous = useRef(value);
  useEffect(() => {
    const start = previous.current;
    const target = value;
    previous.current = target;
    if (start === target) return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches || document.documentElement.dataset.motion === 'off';
    let id;
    const began = performance.now();
    function update(time) {
      const progress = reduced ? 1 : Math.min((time - began) / 650, 1);
      setDisplay(Math.round(start + (target - start) * (1 - Math.pow(1 - progress, 3))));
      if (progress < 1) id = requestAnimationFrame(update);
    }
    id = requestAnimationFrame(update);
    return () => cancelAnimationFrame(id);
  }, [value]);
  return <span>{pad ? String(display).padStart(2, '0') : display}</span>;
}

export function ScanActivity() {
  return <div className="scan-activity" role="status" aria-live="polite"><div className="scan-beam" /><span className="scan-activity-icon"><Icon name="scan" size={22} /></span><div><strong>Inspecting your target</strong><p>Extracting features and running the trained classifier…</p></div><div className="processing-bars" aria-hidden="true">{[0, 1, 2, 3, 4].map(i => <i key={i} style={{ '--bar': i }} />)}</div></div>;
}
