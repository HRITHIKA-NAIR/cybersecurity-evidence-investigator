import { useReducedMotion } from 'motion/react';
import * as m from 'motion/react-m';
import { ArrowRight, CircleHelp, Link2, Mail, ShieldCheck } from 'lucide-react';
import { categories } from '../config/categories';

export default function Overview() {
  const reducedMotion = useReducedMotion();
  return <>
            <m.section className="hero-card" initial={reducedMotion ? false : { opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .4 }}>
              <div className="hero-copy"><span className="hero-tag"><span /> EVIDENCE BEFORE VERDICT</span><h2>Suspicious doesn’t have<br className="wide-break" /> to mean uncertain.</h2><p>Bring a link, message or file. We connect the warning signs to the evidence behind them, with clear next steps.</p><a href="#investigate/link" className="primary-button">Check something suspicious <ArrowRight size={18} /></a><span className="hero-footnote">Static file inspection · Private account history</span></div>
              <div className="shield-art" aria-hidden="true"><div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="shield-glow" /><ShieldCheck className="hero-shield" strokeWidth={1.2} /><span className="floating-symbol symbol-mail"><Mail size={23} /></span><span className="floating-symbol symbol-link"><Link2 size={23} /></span><span className="art-label"><span /> Find the signal.</span></div>
            </m.section>
            <section className="category-section" aria-labelledby="category-title"><div className="section-title"><div><span className="eyebrow">START AN INVESTIGATION</span><h2 id="category-title">What would you like to check?</h2></div><span className="muted">One piece of evidence at a time.</span></div>
              <div className="category-grid">{categories.map(({ id, name, icon: Icon, detail }, index) => <m.a key={id} href={'#investigate/' + id} className="category-card" whileHover={reducedMotion ? undefined : { y: -4 }} transition={{ type: 'spring', stiffness: 300, damping: 24 }}><span className={'category-icon tone-' + index}><Icon size={23} /></span><h3>{name}</h3><p>{detail}</p><span className="card-link">Start checking <ArrowRight size={17} /></span></m.a>)}</div>
            </section>
            <section className="steps-strip" aria-label="How an investigation works">{[['01', 'Bring the evidence', 'Paste content or choose a supported file.'], ['02', 'Understand the signals', 'Review findings, sources and uncertainty.'], ['03', 'Choose your next step', 'Use recovery guidance or request a re-review.']].map(([n, name, desc]) => <div key={n}><span>{n}</span><div><h3>{name}</h3><p>{desc}</p></div></div>)}</section>
            <div className="honesty-note"><CircleHelp size={19} /><p>EVIDENCE supports your judgment. A low score cannot guarantee safety, and this website cannot remove malware or recover an account.</p><a href="#help">Need help now? <ArrowRight size={16} /></a></div>
          </>;
}
