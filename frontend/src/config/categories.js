import { FileSearch, Link2, Mail, MessageSquare } from 'lucide-react';

// Organise by what a person has, rather than a diagnosis they do not yet know.
export const categories = [
  { id: 'link', name: 'Links & websites', icon: Link2, detail: 'Check a suspicious URL before you trust it.', hint: 'Website address', placeholder: 'https://example.com/suspicious-page', note: 'We inspect public URLs and redirects. Visiting a URL may notify its operator.', examples: 'Unexpected login pages, delivery links, unfamiliar shops' },
  { id: 'email', name: 'Emails', icon: Mail, detail: 'Look beyond a sender’s name and urgent request.', hint: 'Email content', placeholder: 'Paste the email text here…', accept: '.eml', note: 'An original .eml file includes headers that pasted text cannot provide.', examples: 'Unusual senders, payment requests, password resets' },
  { id: 'file', name: 'Files & QR codes', icon: FileSearch, detail: 'Inspect attachments, documents and QR images.', hint: 'File to inspect', accept: '.txt,.md,.csv,.json,.eml,.pdf,.docx,.docm,.pptx,.pptm,.xlsx,.xlsm,.html,.htm,.svg,.js,.ps1,.vbs,.bat,.cmd,.lnk,.iso,.zip,.7z,.png,.jpg,.jpeg,.gif,.bmp,.webp', note: 'Static inspection only. Uploaded files are not executed. Unsupported or encrypted content may remain inconclusive.', examples: 'Email attachments, downloaded documents, QR screenshots' },
  { id: 'message', name: 'Texts & messages', icon: MessageSquare, detail: 'Make sense of unexpected messages and requests.', hint: 'Message content', placeholder: 'Paste the suspicious message here…', note: 'Include the actual message and relevant URLs. Remove passwords, one-time codes and unrelated personal data.', examples: 'SMS, chat messages, social media requests' },
];

export function readRoute() {
  const route = location.hash.slice(1);
  return ['home', 'history', 'help', 'case', ...categories.map(c => 'investigate/' + c.id)].includes(route) ? route : 'home';
}
