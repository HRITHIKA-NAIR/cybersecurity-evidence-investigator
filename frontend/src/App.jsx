import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react';
import { LazyMotion, domAnimation, MotionConfig } from 'motion/react';
import { ArrowRight, Moon, ShieldCheck, Sun, UserRound, WifiOff } from 'lucide-react';
import AuthPanel from './components/AuthPanel';
import InvestigationForm from './components/InvestigationForm';
import HistoryPage from './components/HistoryPage';
import RecoveryGuide from './components/RecoveryGuide';
import ShieldLoader from './components/ShieldLoader';
import StateMessage from './components/StateMessage';
import { supabase } from './services/auth';
import { challengeInvestigation, getInvestigation, getInvestigations, investigateFile, investigateText } from './services/api';
import { categories, readRoute } from './config/categories';
import Overview from './components/Overview';
import Sidebar from './components/Sidebar';
import './App.css';

const CaseResults = lazy(() => import('./components/CaseResults'));
function App() {
  const [route, setRoute] = useState(readRoute);
  const [user, setUser] = useState(null);
  const [accountOpen, setAccountOpen] = useState(false);
  const [recovery, setRecovery] = useState(false);
  const [theme, setTheme] = useState(() => { try { return localStorage.getItem('evidence-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'); } catch { return 'light'; } });
  const [online, setOnline] = useState(navigator.onLine);
  const [result, setResult] = useState(null);
  const [resultContext, setResultContext] = useState('');
  const [challenge, setChallenge] = useState(null);
  const [busy, setBusy] = useState('');
  const [slow, setSlow] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyFailed, setHistoryFailed] = useState(false);
  const [sessionEpoch, setSessionEpoch] = useState(0);
  const identity = useRef(null);
  const generation = useRef(0);
  const activeRequest = useRef(null);
  const historyRequest = useRef(null);
  const detailRequest = useRef(null);
  const heading = useRef(null);
  const category = categories.find(c => route === 'investigate/' + c.id);
  const title = category?.name || ({ home: 'Overview', history: 'My investigations', help: 'Recovery guidance', case: 'Investigation results' }[route]);
  useEffect(() => {
    const changed = () => { setRoute(readRoute()); setError(null); };
    const connectivity = () => setOnline(navigator.onLine);
    window.addEventListener('hashchange', changed);
    window.addEventListener('online', connectivity); window.addEventListener('offline', connectivity);
    return () => { window.removeEventListener('hashchange', changed); window.removeEventListener('online', connectivity); window.removeEventListener('offline', connectivity); };
  }, []);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('evidence-theme', theme); } catch { /* Optional preference storage. */ }
  }, [theme]);
  useEffect(() => {
    document.title = route === 'home' ? 'Phishing & Suspicious Content Checker | EVIDENCE' : title + ' · EVIDENCE';
    heading.current?.focus({ preventScroll: true });
  }, [title, route]);
  useEffect(() => {
    if (!supabase) return;
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      const nextUser = session?.user || null;
      if (identity.current !== nextUser?.id) {
        identity.current = nextUser?.id;
        generation.current += 1;
        activeRequest.current?.abort();
        historyRequest.current?.abort();
        detailRequest.current?.abort();
        activeRequest.current = null;
        setSessionEpoch(generation.current);
        setResult(null); setHistory([]); setChallenge(null); setBusy(''); setHistoryLoading(false); setHistoryFailed(false);
      }
      setUser(nextUser);
      if (event === 'PASSWORD_RECOVERY') { setRecovery(true); setAccountOpen(true); }
      if (event === 'SIGNED_OUT') setRecovery(false);
    });
    return () => { subscription.unsubscribe(); activeRequest.current?.abort(); historyRequest.current?.abort(); detailRequest.current?.abort(); };
  }, []);
  useEffect(() => {
    if (!busy) return;
    const timer = setTimeout(() => setSlow(true), 15000);
    return () => clearTimeout(timer);
  }, [busy]);
  const report = useCallback((err) => {
    setError({ message: err.message || 'The service could not be reached. Try again.', status: err.status });
    if (err.status === 401) {
      generation.current += 1;
      identity.current = null;
      activeRequest.current?.abort(); historyRequest.current?.abort(); detailRequest.current?.abort();
      activeRequest.current = null;
      setSessionEpoch(generation.current); setUser(null); setResult(null); setChallenge(null); setHistory([]);
      setBusy(''); setHistoryLoading(false); setRecovery(false); setAccountOpen(true);
    }
  }, []);
  const refreshHistory = useCallback(async () => {
    if (!user) { setAccountOpen(true); return; }
    historyRequest.current?.abort();
    const controller = new AbortController();
    historyRequest.current = controller;
    const current = generation.current;
    setHistoryLoading(true); setHistoryFailed(false); setError(null);
    const isCurrent = () => current === generation.current && !controller.signal.aborted;
    try { const data = await getInvestigations(controller.signal); if (isCurrent()) setHistory(data); }
    catch (err) { if (isCurrent()) { setHistoryFailed(true); report(err); } }
    finally { if (isCurrent()) setHistoryLoading(false); }
  }, [user, report]);
  useEffect(() => {
    // Defer the fetch until navigation settles; cancel obsolete route work.
    const task = route === 'history' && user ? setTimeout(refreshHistory, 0) : null;
    return () => { clearTimeout(task); historyRequest.current?.abort(); };
  }, [route, user, refreshHistory]);
  async function investigate({ content, file }) {
    if (!user) { setAccountOpen(true); return; }
    if (activeRequest.current) return;
    const current = generation.current;
    activeRequest.current = new AbortController();
    setBusy('analysis'); setSlow(false); setError(null); setResult(null); setChallenge(null); setResultContext(category.id);
    try {
      const data = file ? await investigateFile(file, activeRequest.current.signal) : await investigateText(content, activeRequest.current.signal);
      if (current === generation.current) { setResult(data); location.hash = 'case'; }
    } catch (err) { if (current === generation.current && err.name !== 'AbortError') report(err); }
    finally { if (current === generation.current) { setBusy(''); activeRequest.current = null; } }
  }
  async function reviewConclusion() {
    if (!result?.investigation_id) return;
    if (activeRequest.current) return;
    const current = generation.current;
    activeRequest.current = new AbortController();
    setBusy('review'); setSlow(false); setError(null);
    try { const data = await challengeInvestigation(result.investigation_id, activeRequest.current.signal); if (current === generation.current) setChallenge(data); }
    catch (err) { if (current === generation.current && err.name !== 'AbortError') report(err); }
    finally { if (current === generation.current) { setBusy(''); activeRequest.current = null; } }
  }
  async function openCase(item) {
    if (busy) return;
    detailRequest.current?.abort();
    const controller = new AbortController();
    detailRequest.current = controller;
    const current = generation.current;
    setBusy('case'); setSlow(false); setError(null); setResult(null); location.hash = 'case';
    try {
      const data = await getInvestigation(item.id, controller.signal);
      if (current === generation.current && !controller.signal.aborted) { setResult(data); setChallenge(data.challenge_result || null); }
    } catch (err) { if (current === generation.current && !controller.signal.aborted) report(err); }
    finally { if (current === generation.current && !controller.signal.aborted) setBusy(''); }
  }
  const showResult = result && (route === 'case' || category?.id === resultContext);
  return <LazyMotion features={domAnimation}><MotionConfig reducedMotion="user">
    <a className="skip-link" href="#main" onClick={e => { e.preventDefault(); document.getElementById('main').focus(); }}>Skip to main content</a>
    <div className="workspace">
      <Sidebar route={route} category={category} />
      <div className="workspace-body">
        <header className="topbar"><div className="breadcrumb">Workspace <span>/</span> <strong>{title}</strong></div><div className="topbar-actions">
          <button className="theme-switch" type="button" role="switch" aria-checked={theme === 'dark'} aria-label="Dark mode" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}><Sun size={16} /><span className="switch-track"><span /></span><Moon size={16} /></button>
          <button className="account-button" onClick={() => setAccountOpen(true)}><UserRound size={17} /><span>{user ? 'My account' : 'Sign in'}</span></button>
        </div></header>
        <main id="main" tabIndex={-1} className="main-content">
          {!online && <StateMessage icon={WifiOff} title="You’re offline" message="Recovery guidance still works on this page. Reconnect to sign in, investigate or load your history." />}
          <div className="page-heading"><div><span className="eyebrow">{route === 'home' ? 'YOUR SECURITY WORKSPACE' : 'EVIDENCE INVESTIGATOR'}</span><h1 ref={heading} tabIndex={-1}>{route === 'home' ? 'A little clarity. A safer next step.' : title}</h1><p>{category ? category.detail : route === 'home' ? 'Understand suspicious content, see the evidence, and know what to do next.' : route === 'history' ? 'Revisit your latest 100 investigations, or permanently delete a case.' : route === 'help' ? 'Start with what happened. Take one practical step at a time.' : 'Review the reasoning and its limits before making a decision.'}</p></div>{route === 'home' && <a className="text-link desktop-guide" href="/guide.html">How it works <ArrowRight size={16} /></a>}</div>
          {error && <StateMessage kind="error" title={error.status === 401 ? 'Your session needs attention' : error.status === 403 ? 'Permission denied' : error.status === 429 ? 'Request limit reached' : 'We couldn’t complete that request'} message={error.message} />}
          {busy && <><ShieldLoader label={busy === 'case' ? 'Opening your investigation…' : busy === 'review' ? 'Reviewing the conclusion…' : 'Examining the evidence…'} />{slow && <StateMessage title="This is taking a little longer" message="The free service may be waking up, or a provider may be slow. Keep this page open; you don’t need to submit again." />}</>}
          {route === 'home' && <Overview />}
          {category && <InvestigationForm key={category.id + sessionEpoch} category={category} busy={Boolean(busy)} online={online} signedIn={Boolean(user)} onSubmit={investigate} />}
          {route === 'history' && <HistoryPage key={sessionEpoch} items={history} loading={historyLoading} failed={historyFailed} busy={Boolean(busy)} signedIn={Boolean(user)} onRefresh={refreshHistory} onSignIn={() => setAccountOpen(true)} onSelect={openCase} onError={report} />}
          {route === 'help' && <RecoveryGuide />}
          {showResult && <Suspense fallback={<ShieldLoader label="Opening your results…" />}><CaseResults key={result.investigation_id || 'unsaved'} result={result} challenge={challenge} onReview={reviewConclusion} busy={Boolean(busy)} /></Suspense>}
          {route === 'case' && !result && !busy && <StateMessage title="Choose an investigation" message="Open a saved case from My investigations, or start a new check from the sidebar." />}
          <footer className="site-footer"><span><ShieldCheck size={15} /> EVIDENCE · Clarity before action.</span><nav aria-label="Policies"><a href="/privacy.html">Privacy</a><a href="/terms.html">Terms</a><a href="/data-deletion.html">Data deletion</a><a href="/acceptable-use.html">Acceptable use</a><a href="/copyright.html">Copyright</a></nav></footer>
        </main>
      </div>
    </div>
    {accountOpen && <AccountDialog onClose={() => setAccountOpen(false)}><AuthPanel key={recovery ? 'recovery' : 'account'} user={user} recovery={recovery} onClose={() => setAccountOpen(false)} /></AccountDialog>}
  </MotionConfig></LazyMotion>;
}
function AccountDialog({ children, onClose }) {
  const ref = useRef(null);
  useEffect(() => { const dialog = ref.current; const previous = document.activeElement; dialog.showModal(); return () => { dialog.close(); previous?.focus(); }; }, []);
  return <dialog ref={ref} className="account-dialog" aria-labelledby="account-title" onCancel={onClose}>{children}</dialog>;
}
export default App;
