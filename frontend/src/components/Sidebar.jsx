import { useRef, useState } from 'react';
import { ArrowRight, BookOpen, History, Home, Menu, ShieldCheck, X } from 'lucide-react';
import { categories } from '../config/categories';

export default function Sidebar({ route, category }) {
  const [expanded, setExpanded] = useState(false);
  const menu = useRef(null);
  function closeMenu() { setExpanded(false); }
  return <aside className={'sidebar' + (expanded ? ' sidebar-expanded' : '')}>
    <div className="sidebar-heading">
      <a className="brand" href="#home" aria-label="Evidence home" onClick={closeMenu}><span className="brand-mark"><ShieldCheck size={24} /></span><span>EVIDENCE<small>Clarity before action.</small></span></a>
      <button ref={menu} className="mobile-menu" aria-expanded={expanded} aria-controls="workspace-navigation" onClick={() => setExpanded(value => !value)}>{expanded ? <X size={21} /> : <Menu size={21} />}<span>{expanded ? 'Close menu' : 'Menu'}</span></button>
    </div>
    <nav id="workspace-navigation" aria-label="Workspace" onKeyDown={event => { if (event.key === 'Escape') { closeMenu(); menu.current?.focus(); } }}>
      <span className="nav-label">WORKSPACE</span>
      <a className={route === 'home' ? 'active' : ''} href="#home" aria-current={route === 'home' ? 'page' : undefined} onClick={closeMenu}><Home size={19} /> Overview</a>
      <a className={route === 'history' ? 'active' : ''} href="#history" aria-current={route === 'history' ? 'page' : undefined} onClick={closeMenu}><History size={19} /> My investigations</a>
      <span className="nav-label nav-gap">INVESTIGATE</span>
      {categories.map(({ id, name, icon: Icon }) => <a key={id} className={category?.id === id ? 'active' : ''} aria-current={category?.id === id ? 'page' : undefined} href={'#investigate/' + id} onClick={closeMenu}><Icon size={19} />{name}</a>)}
      <a className={'mobile-recovery ' + (route === 'help' ? 'active' : '')} href="#help" onClick={closeMenu} aria-current={route === 'help' ? 'page' : undefined}><ShieldCheck size={19} /> Already affected?</a>
    </nav>
    <div className="sidebar-bottom"><div className="help-card"><ShieldCheck size={22} /><strong>Already affected?</strong><p>Find practical steps to contain the damage.</p><a href="#help">Get recovery guidance <ArrowRight size={15} /></a></div><a className="guide-link" href="/guide.html"><BookOpen size={18} /> How to use EVIDENCE</a><span className="beta-label">BETA · Verify critical findings</span></div>
  </aside>;
}
