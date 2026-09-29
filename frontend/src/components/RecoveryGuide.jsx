import { useState } from 'react';

const GUIDES = {
  low_risk: {
    title: 'Nothing confirmed yet - stay cautious',
    steps: [
      'No clear danger was found this time, but that is not a guarantee. Do not enter a password, one-time code or card number unless you opened the site yourself, not through the link you checked.',
      'Reach the organisation only through its official app or a web address you typed yourself or saved earlier, never through the link or number in the message.',
      'If anything about the sender or timing still feels wrong - unexpected urgency, a request for money, a link that does not match who it claims to be from - treat it as suspicious regardless of this result.',
      'Keep the message until you are sure. If you interacted with it further, choose the situation below that matches what happened.',
    ],
  },
  credentials: { title: 'Phishing or a stolen account', steps: ['From a trusted device, open the service through its official app or a saved address. Do not use the suspicious link.', 'If you entered a password, change it and any reused passwords. Secure your main email account first.', 'Revoke unfamiliar sessions and connected apps, check recovery details and email forwarding rules, then enable multi-factor authentication.', 'If you shared a one-time code, approve no further prompts. Use the provider’s official compromised-account recovery process if access is lost.'] },
  malware: { title: 'A suspicious file was opened or installed', steps: ['If you ran the file or see signs of compromise, disconnect the affected device from Wi-Fi and Ethernet. Stop entering passwords on it.', 'Preserve the message, filename, time and screenshots without opening the file again. On a work device, contact your IT/security team immediately.', 'Use a trusted device to secure important accounts. Run your platform’s trusted security tools or seek professional recovery support.', 'If files are encrypted, preserve evidence and seek incident-response help before wiping or restoring. Restore only from a verified clean backup after containment.'] },
  payment: { title: 'Money or payment details were shared', steps: ['Contact your bank or payment provider immediately using the number on your card or its official app. Ask about freezing the card/account and stopping or recalling the transaction.', 'Save transaction references, messages and receipts.', 'In the UAE, report to Dubai Police eCrime (or your emirate\u2019s equivalent) and, for card fraud, your bank\u2019s fraud line. Do not pay anyone who promises guaranteed recovery for a fee - that itself is a common follow-up scam.', 'Secure associated email and payment accounts from a trusted device and monitor transactions closely for the following weeks.'] },
  website: { title: 'Your own website may be compromised', steps: ['Contact your hosting provider or security team and preserve application, access and authentication logs. Avoid publishing logs containing secrets.', 'Contain the affected service and revoke exposed credentials from a clean device. Review administrator accounts, deployments and unexpected changes.', 'Find and fix the cause, apply supported updates, and restore a verified clean backup if needed. Validate access controls and monitor for recurrence before reopening.'] },
};

const UAE_LINKS = [
  { href: 'https://ecrime.ae', label: 'Dubai Police eCrime (report online)' },
  { href: 'https://mysafesociety.ae', label: 'My Safe Society - UAE Public Prosecution' },
  { href: 'https://tdra.gov.ae', label: 'TDRA - report phishing/spam, or forward SMS to 7726' },
  { href: 'tel:999', label: 'Emergency: 999' },
  { href: 'tel:901', label: 'Non-emergency police (Dubai/Sharjah/Ajman): 901' },
];

const INTL_LINKS = [
  { href: 'https://www.cisa.gov/secure-our-world/recognize-and-report-phishing', label: 'CISA: recognize and report phishing' },
  { href: 'https://www.ncsc.gov.uk/guidance/recovering-a-hacked-account', label: 'NCSC: recovering a hacked account' },
];

function suggestKey(findings, verdict) {
  const text = findings.map(f => `${f.attack_type} ${f.category}`).join(' ').toLowerCase();
  if (/ransom|malware|macro|script|executable/.test(text)) return 'malware';
  if (/sql|xss|injection/.test(text)) return 'website';
  if (findings.length > 0) return 'credentials';
  if (verdict === 'Low Risk' || verdict === 'Inconclusive') return 'low_risk';
  return 'credentials';
}

export default function RecoveryGuide({ findings = [], verdict }) {
  const [selected, setSelected] = useState('');
  const suggested = suggestKey(findings, verdict);
  const key = selected || suggested;

  return (
    <section className="panel recovery-panel" id="recovery" aria-labelledby="recovery-title">
      <span className="eyebrow">What to do next</span>
      <h2 id="recovery-title">Already clicked, shared something, or been hacked?</h2>
      <p>You can use these steps without signing in. Choose what actually happened; a finding alone does not prove your device or account was compromised.</p>
      <p>Suggested starting point for this result: <strong>{GUIDES[suggested].title}</strong>. Confirm your situation below.</p>

      <label>Your situation
        <select value={key} onChange={e => setSelected(e.target.value)}>
          {Object.entries(GUIDES).map(([id, g]) => <option value={id} key={id}>{g.title}</option>)}
        </select>
      </label>

      <ol>{GUIDES[key].steps.map(s => <li key={s}>{s}</li>)}</ol>

      <p className="limitation-note">This website explains evidence and recovery steps. It cannot clean your device, restore an account, reverse a payment, or guarantee that a threat is gone.</p>

      <p><strong>Report it in the UAE:</strong>{' '}
        {UAE_LINKS.map((l, i) => (
          <span key={l.href}>
            <a href={l.href} target={l.href.startsWith('tel:') ? undefined : '_blank'} rel="noopener noreferrer">{l.label}</a>
            {i < UAE_LINKS.length - 1 ? ' \u00b7 ' : ''}
          </span>
        ))}
      </p>
      <p className="muted">International guidance: {INTL_LINKS.map((l, i) => (
        <span key={l.href}>
          <a href={l.href} target="_blank" rel="noopener noreferrer">{l.label}</a>
          {i < INTL_LINKS.length - 1 ? ' \u00b7 ' : ''}
        </span>
      ))}</p>
    </section>
  );
}
