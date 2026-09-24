import { useRef, useState } from 'react';
import { ArrowRight, FolderSearch, RefreshCw, Search, Trash2 } from 'lucide-react';
import { deleteInvestigation } from '../services/api';
import StateMessage from './StateMessage';

export default function HistoryPage({ items, loading, failed, busy, signedIn, onRefresh, onSignIn, onSelect, onError }) {
  const [query, setQuery] = useState('');
  const [pending, setPending] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [deleted, setDeleted] = useState([]);
  const [notice, setNotice] = useState('');
  const dialog = useRef(null);
  const trigger = useRef(null);
  const visible = items.filter(item => !deleted.includes(item.id));
  const matches = visible.filter(item => [item.content_preview, item.verdict, item.id, item.input_type].join(' ').toLowerCase().includes(query.trim().toLowerCase()));
  function closeDialog() {
    dialog.current.close();
    setPending(null);
    trigger.current?.focus();
  }
  async function confirmDelete() {
    if (deleting) return;
    setDeleting(true);
    try {
      await deleteInvestigation(pending);
      setDeleted(old => [...old, pending]);
      setNotice('Investigation permanently deleted from active storage.');
      closeDialog();
    } catch (error) {
      closeDialog();
      onError(error);
    } finally { setDeleting(false); }
  }
  if (!signedIn) return <section className="panel empty-panel"><FolderSearch size={36} /><h2>Your investigations stay with you.</h2><p>Sign in to open your private history.</p><button className="primary-button" onClick={onSignIn}>Sign in</button></section>;
  return <section className="panel history-page" aria-label="Saved investigations" aria-busy={loading}>
    <div className="history-toolbar">
      <label className="search-field"><Search size={18} /><span className="sr-only">Search your loaded investigations</span><input type="search" value={query} onChange={e => setQuery(e.target.value)} placeholder="Search your case previews…" /></label>
      <button className="secondary-button" onClick={onRefresh} disabled={loading}><RefreshCw size={16} />{loading ? 'Loading…' : 'Refresh'}</button>
    </div>
    <p className="history-scope">Search checks the preview, case number, type and verdict of your latest 100 cases. Open a case for its full evidence.</p>
    {notice && <StateMessage title="Deleted" message={notice} />}
    {loading ? <StateMessage title="Loading your investigations" message="Your cases will appear here when the service responds." />
      : failed && !visible.length ? <StateMessage kind="error" title="History could not be loaded" message="Your saved cases may still be available. Check the connection or sign in again, then use Refresh." />
      : !matches.length ? <div className="empty-panel"><FolderSearch size={38} /><h2>{query ? 'No matching investigations' : 'A fresh start.'}</h2><p>{query ? 'Try another term. Search covers the previews of your latest 100 cases.' : 'Your saved investigations will appear here after your first check.'}</p>{query ? <button className="secondary-button" onClick={() => setQuery('')}>Clear search</button> : <a className="primary-button" href="#investigate/link">Start an investigation <ArrowRight size={16} /></a>}</div>
      : <ul className="case-list">{matches.map(item => <li key={item.id}>
        <button className="case-open" disabled={busy} onClick={() => onSelect(item)}><span className="case-number">CASE #{item.id} · {item.input_type || 'content'}</span><strong>{item.content_preview || 'File investigation'}</strong><span className="muted">{item.verdict} · Score {item.threat_score}/100 · {item.created_at ? new Date(item.created_at).toLocaleDateString() : 'Saved case'}</span></button>
        <button className="icon-button delete-button" disabled={busy} aria-label={'Delete investigation ' + item.id} onClick={event => { trigger.current = event.currentTarget; setPending(item.id); dialog.current.showModal(); }}><Trash2 size={18} /></button>
      </li>)}</ul>}
    <dialog ref={dialog} className="delete-dialog" aria-labelledby="delete-title" onCancel={event => { if (deleting) event.preventDefault(); else setPending(null); }}>
      <h2 id="delete-title">Delete this investigation?</h2><p>The case and its related evidence will be removed from active storage. This cannot be undone. Provider retention and backup limits are explained in the privacy notice.</p>
      <div className="dialog-actions"><button className="secondary-button" autoFocus disabled={deleting} onClick={closeDialog}>Keep investigation</button><button className="danger-button" disabled={deleting} onClick={confirmDelete}>{deleting ? 'Deleting…' : 'Delete permanently'}</button></div>
    </dialog>
  </section>;
}
