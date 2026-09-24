import { AlertCircle, Info } from 'lucide-react';
export default function StateMessage({ kind = 'info', icon, title, message }) {
  const Icon = icon || (kind === 'error' ? AlertCircle : Info);
  return <div className={'state-message state-' + kind} role={kind === 'error' ? 'alert' : 'status'}><Icon size={22} aria-hidden="true" /><div><strong>{title}</strong><p>{message}</p></div></div>;
}
