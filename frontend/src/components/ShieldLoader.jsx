export default function ShieldLoader({ label = 'Examining the evidence…' }) {
  return <div className="shield-loading" role="status" aria-live="polite">
    <div className="shield-stage"><svg className="spinning-shield" viewBox="0 0 64 72" aria-hidden="true"><path d="M32 3 57 13v20c0 16-11 28-25 35C18 61 7 49 7 33V13Z" fill="none" stroke="currentColor" strokeWidth="4"/><path d="m20 35 8 8 17-19" fill="none" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round"/></svg></div>
    <div><strong>{label}</strong><p>Some checks take a little longer. Results will appear here when ready.</p></div>
  </div>;
}
