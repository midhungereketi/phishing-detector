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

export function AmbientField({ paused = false }) {
  const canvas = useRef(null);
  useEffect(() => {
    const element = canvas.current;
    const context = element.getContext('2d');
    if (!context) return;
    const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
    let frame = 0;
    let previous = 0;
    let width = 0;
    let height = 0;
    let active = !document.hidden;
    const particles = Array.from({ length: 35 }, (_, index) => ({
      x: ((index * 137.508) % 1000) / 1000,
      y: ((index * 293.771 + 170) % 1000) / 1000,
      velocity: .000006 + (index % 4) * .000002,
    }));
    function resize() {
      const ratio = Math.min(window.devicePixelRatio || 1, 1.5);
      width = window.innerWidth; height = window.innerHeight;
      element.width = width * ratio; element.height = height * ratio;
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      draw(0);
    }
    function draw(delta) {
      context.clearRect(0, 0, width, height);
      for (const particle of particles) {
        if (!paused && !preference.matches) particle.y = (particle.y - particle.velocity * delta + 1) % 1;
        context.beginPath();
        context.arc(particle.x * width, particle.y * height, 1, 0, Math.PI * 2);
        context.fillStyle = 'rgba(172, 139, 255, 0.35)'; context.fill();
      }
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const a = particles[i], b = particles[j];
          const distance = Math.hypot((a.x - b.x) * width, (a.y - b.y) * height);
          if (distance < 150) {
            context.beginPath(); context.moveTo(a.x * width, a.y * height); context.lineTo(b.x * width, b.y * height);
            context.strokeStyle = `rgba(172,139,255,${.06 * (1 - distance / 150)})`; context.stroke();
          }
        }
      }
    }
    function tick(time) {
      if (!active || paused || preference.matches) return;
      if (time - previous >= 40) { draw(Math.min(time - previous, 80)); previous = time; }
      frame = requestAnimationFrame(tick);
    }
    function update() {
      cancelAnimationFrame(frame); active = !document.hidden;
      previous = performance.now(); draw(0);
      if (active && !paused && !preference.matches) frame = requestAnimationFrame(tick);
    }
    resize(); update();
    window.addEventListener('resize', resize);
    document.addEventListener('visibilitychange', update);
    preference.addEventListener('change', update);
    return () => { cancelAnimationFrame(frame); window.removeEventListener('resize', resize); document.removeEventListener('visibilitychange', update); preference.removeEventListener('change', update); };
  }, [paused]);
  return <canvas className="ambient-field" ref={canvas} aria-hidden="true" />;
}

export function SecurityOrb({ compact = false }) {
  return <div className={`security-orb ${compact ? 'compact' : ''}`} aria-hidden="true">
    <div className="orb-aura" />
    <svg viewBox="0 0 400 330" className="orb-svg">
      <defs><radialGradient id="orb-fill"><stop stopColor="#a78bfa" stopOpacity=".12" /><stop offset="1" stopColor="#a78bfa" stopOpacity="0" /></radialGradient><linearGradient id="shield-fill" x2="1" y2="1"><stop stopColor="#e2d8ff" /><stop offset="1" stopColor="#9870ed" /></linearGradient></defs>
      <g className="orb-grid" fill="none" stroke="#a58bc9" strokeOpacity=".16" strokeWidth=".7">
        <ellipse cx="200" cy="165" rx="121" ry="121" fill="url(#orb-fill)" />
        {[28, 65, 100].map(r => <ellipse key={r} cx="200" cy="165" rx={r} ry="121" />)}
        {[45, 83, 113].map(r => <ellipse key={r} cx="200" cy="165" rx="121" ry={r} />)}
        <path d="M79 165h242M200 44v242" />
      </g>
      <g className="orb-orbit" fill="none" stroke="#b295ee" strokeWidth=".8"><ellipse cx="200" cy="165" rx="167" ry="60" transform="rotate(-28 200 165)" strokeOpacity=".45" /><ellipse cx="200" cy="165" rx="157" ry="50" transform="rotate(34 200 165)" strokeOpacity=".22" /></g>
      <ellipse className="orb-tracer" cx="200" cy="165" rx="167" ry="60" transform="rotate(-28 200 165)" fill="none" stroke="#d2f79a" strokeWidth="2" strokeDasharray="8 720" strokeLinecap="round" />
      <g className="orb-nodes"><circle cx="94" cy="209" r="4" fill="#d2f79a" /><circle cx="317" cy="112" r="3" fill="#c2a2ff" /><circle cx="240" cy="51" r="2" fill="#bca7e6" /><circle cx="125" cy="76" r="3" fill="#7ecdfa" /><circle cx="285" cy="252" r="3" fill="#a993ff" /></g>
      <g className="orb-shield"><path d="m200 112 41 17v34c0 28-41 52-41 52s-41-24-41-52v-34l41-17Z" fill="#141225" stroke="url(#shield-fill)" strokeWidth="1.6" /><path d="m200 122 32 13v28c0 21-32 42-32 42s-32-21-32-42v-28l32-13Z" fill="#ac8bff" fillOpacity=".05" stroke="#ac8bff" strokeOpacity=".25" /><path d="m185 160 10 10 22-24" fill="none" stroke="#d2f79a" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></g>
      <g fontFamily="monospace" fontSize="7" fill="#9d8ab8" letterSpacing="1.2"><text x="49" y="272">ENCRYPT YOUR INSTINCTS.</text><text x="258" y="65">PHISHGUARD / ML</text></g>
      <path d="M31 49h14m-7-7v14M351 283h14m-7-7v14" stroke="#5e4d79" strokeWidth="1" />
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
