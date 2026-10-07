import { useEffect, useRef, useState } from 'react';
import { Icon } from './CyberVisuals';

export default function CommandPalette({ items, onNavigate, onClose }) {
  const dialog = useRef(null);
  const [query, setQuery] = useState('');
  const matches = items.filter(item => item[2].toLowerCase().includes(query.toLowerCase()));
  useEffect(() => {
    const element = dialog.current;
    element.showModal();
    return () => element.close();
  }, []);
  return <dialog ref={dialog} className="command-palette" onCancel={onClose} onClick={event => { if (event.target === dialog.current) onClose(); }} aria-labelledby="command-title">
    <div className="command-search"><Icon name="search" /><input autoFocus aria-label="Search workspace pages" placeholder="Where do you want to go?" value={query} onChange={event => setQuery(event.target.value)} onKeyDown={event => { if (event.key === 'Enter' && matches[0]) onNavigate(matches[0][0]); }} /><button className="keycap" onClick={onClose}>ESC</button></div>
    <div className="command-body"><h2 id="command-title">JUMP TO A PAGE</h2>{matches.length ? matches.map(([target, icon, label]) => <button className="command-result" key={target} onClick={() => onNavigate(target)}><Icon name={icon} /><span>{label}</span><Icon name="arrow" size={16} /></button>) : <p>No matching pages.</p>}</div>
    <div className="command-footer"><span>↑ Tab to navigate</span><span>↵ Enter to select</span></div>
  </dialog>;
}
