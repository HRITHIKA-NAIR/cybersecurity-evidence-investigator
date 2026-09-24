import { useState } from 'react';
const GUIDES = {
  credentials: { title: 'Phishing or a stolen account', steps: ['From a trusted device, open the service through its official app or a saved address. Do not use the suspicious link.', 'If you entered a password, change it and any reused passwords. Secure your main email account first.', 'Revoke unfamiliar sessions and connected apps, check recovery details and email forwarding rules, then enable multi-factor authentication.', 'If you shared a one-time code, approve no further prompts. Use the provider’s official compromised-account recovery process if access is lost.'] },
  malware: { title: 'A suspicious file was opened or installed', steps: ['If you ran the file or see signs of compromise, disconnect the affected device from Wi-Fi and Ethernet. Stop entering passwords on it.', 'Preserve the message, filename, time and screenshots without opening the file again. On a work device, contact your IT/security team immediately.', 'Use a trusted device to secure important accounts. Run your platform’s trusted security tools or seek professional recovery support.', 'If files are encrypted, preserve evidence and seek incident-response help before wiping or restoring. Restore only from a verified clean backup after containment.'] },
  payment: { title: 'Money or payment details were shared', steps: ['Contact your bank or payment provider immediately using the number on your card or its official app. Ask about freezing the card/account and stopping or recalling the transaction.', 'Save transaction references, messages and receipts. Report the incident through the provider’s fraud process and the appropriate local authority.', 'Secure associated email and payment accounts from a trusted device. Monitor transactions and reject anyone promising guaranteed recovery for a fee.'] },
  website: { title: 'Your own website may be compromised', steps: ['Contact your hosting provider or security team and preserve application, access and authentication logs. Avoid publishing logs containing secrets.', 'Contain the affected service and revoke exposed credentials from a clean device. Review administrator accounts, deployments and unexpected changes.', 'Find and fix the cause, apply supported updates, and restore a verified clean backup if needed. Validate access controls and monitor for recurrence before reopening.'] },
};
export default function RecoveryGuide({ findings = [] }) {
  const [selected, setSelected] = useState('');
  const text = findings.map(f => `${f.attack_type} ${f.category}`).join(' ').toLowerCase();
  const suggested = /ransom|malware|macro|script|executable/.test(text) ? 'malware' : /sql|xss|injection/.test(text) ? 'website' : 'credentials';
  const key = selected || suggested;
  return <section className="panel recovery-panel" id="recovery" aria-labelledby="recovery-title">
    <span className="eyebrow">What to do next</span><h2 id="recovery-title">Already clicked, shared something, or been hacked?</h2>
    <p>You can use these steps without signing in. Choose what actually happened; a finding alone does not prove your device or account was compromised.</p>
    {findings.length > 0 && <p>Suggested starting point based on detected indicators: <strong>{GUIDES[suggested].title}</strong>. Confirm your situation below.</p>}
    <label>Your situation<select value={key} onChange={e => setSelected(e.target.value)}>{Object.entries(GUIDES).map(([id,g]) => <option value={id} key={id}>{g.title}</option>)}</select></label>
    <ol>{GUIDES[key].steps.map(s => <li key={s}>{s}</li>)}</ol>
    <p className="limitation-note">This website explains evidence and recovery steps. It cannot clean your device, restore an account, reverse a payment, or guarantee that a threat is gone.</p>
    <a href="https://www.cisa.gov/secure-our-world/recognize-and-report-phishing" target="_blank" rel="noopener noreferrer">Official phishing guidance</a> · <a href="https://www.ncsc.gov.uk/guidance/recovering-a-hacked-account" target="_blank" rel="noopener noreferrer">Account recovery guidance</a>
  </section>;
}
