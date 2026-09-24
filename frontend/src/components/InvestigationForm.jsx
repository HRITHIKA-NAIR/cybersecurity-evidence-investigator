import { useState } from 'react';
import { ArrowRight, LockKeyhole, UploadCloud, X } from 'lucide-react';
export default function InvestigationForm({ category, busy, online, signedIn, onSubmit }) {
  const [content, setContent] = useState('');
  const [file, setFile] = useState(null);
  const [consent, setConsent] = useState(false);
  const [validation, setValidation] = useState('');
  const [dragging, setDragging] = useState(false);
  function chooseFile(selected) {
    if (busy) return;
    if (!selected) return;
    const ext = '.' + selected.name.split('.').pop().toLowerCase();
    if (!category.accept.split(',').includes(ext)) { setValidation('Choose one of the supported file types listed below.'); return; }
    if (!selected.size || selected.size > 10 * 1024 * 1024) { setValidation('Choose a non-empty file no larger than 10 MiB.'); return; }
    setFile(selected); setValidation('');
  }
  function submit(event) {
    event.preventDefault();
    if (!file && !content.trim()) { setValidation(category.id === 'file' ? 'Choose a file to inspect.' : 'Enter the content you want to investigate.'); return; }
    if (category.id === 'link') {
      try { const url = new URL(content.trim()); if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error(); }
      catch { setValidation('Enter a complete http:// or https:// URL without a username or password.'); return; }
    }
    if (!consent) { setValidation('Read and accept the processing notice before submitting.'); return; }
    setValidation(''); onSubmit({ content: content.trim(), file });
  }
  return <div className="investigation-layout"><form className="panel investigation-form" onSubmit={submit} noValidate>
    <span className="eyebrow">NEW INVESTIGATION</span><h2>Start with the evidence</h2><p className="muted">{category.note}</p>
    {category.accept && <div className={'upload-zone' + (dragging ? ' upload-dragging' : '')} onDragOver={event => { event.preventDefault(); if (!busy) setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={event => { event.preventDefault(); setDragging(false); if (event.dataTransfer.files.length !== 1) { setValidation('Choose one file at a time.'); return; } chooseFile(event.dataTransfer.files[0]); }}><UploadCloud size={28} aria-hidden="true" /><strong>{file ? file.name : category.id === 'email' ? 'Choose an original email (.eml)' : 'Choose a file to inspect'}</strong><span>{file ? (file.size / 1024).toFixed(1) + ' KiB selected' : 'Drop one file here or browse · up to 10 MiB'}</span><label className="secondary-button file-picker">Browse files<input type="file" accept={category.accept} onChange={event => { chooseFile(event.target.files?.[0]); event.target.value = ''; }} disabled={busy} aria-describedby="form-validation" /></label>{file && <button type="button" className="ghost-button" disabled={busy} onClick={() => setFile(null)}><X size={16} /> Remove file</button>}</div>}
    {category.id !== 'file' && <label className="field-label" htmlFor="evidence-content">{category.id === 'email' ? 'Or paste the email text' : category.hint}{category.id === 'link' ? <input id="evidence-content" type="url" autoComplete="off" spellCheck="false" value={content} onChange={e => setContent(e.target.value)} placeholder={category.placeholder} maxLength={100000} disabled={busy || Boolean(file)} aria-invalid={Boolean(validation)} aria-describedby="form-validation" /> : <textarea id="evidence-content" rows={7} value={content} onChange={e => setContent(e.target.value)} placeholder={category.placeholder} maxLength={100000} disabled={busy || Boolean(file)} aria-invalid={Boolean(validation)} aria-describedby="form-validation" />}</label>}
    {category.id === 'file' && <details className="supported-types"><summary>Supported file types</summary><p>{category.accept.replaceAll(',', ', ')}</p></details>}
    <label className="consent"><input type="checkbox" checked={consent} disabled={busy} onChange={e => setConsent(e.target.checked)} /><span>I’m authorized to submit this evidence. I understand configured AI and reputation providers may receive extracted content and URLs, and public URLs may be contacted. <a href="/privacy.html" target="_blank" rel="noreferrer">Read the privacy notice</a>.</span></label>
    <p id="form-validation" className="validation-message" role={validation ? 'alert' : undefined}>{validation}</p>
    <button className="primary-button" disabled={busy || !online}>{busy ? 'Investigation in progress…' : !online ? 'Reconnect to investigate' : signedIn ? 'Investigate evidence' : 'Sign in to investigate'}<ArrowRight size={18} /></button>
  </form><aside className="input-guidance"><div className="guidance-icon"><LockKeyhole size={23} /></div><h2>A useful check starts with context.</h2><p>Submit only what’s needed to understand the suspicious content.</p><ul><li>Remove passwords, one-time codes and unrelated personal details.</li><li>Use only evidence you own or have permission to inspect.</li><li>Keep the original safely if you need to report an incident.</li></ul><div className="guidance-bottom"><strong>Already clicked or shared something?</strong><p>You don’t have to wait for a result to take action.</p><a className="text-link" href="#help">Open recovery guidance <ArrowRight size={16} /></a></div></aside></div>;
}
