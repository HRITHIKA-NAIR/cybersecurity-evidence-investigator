import { useState } from 'react';
import AssessmentCard from './AssessmentCard';
import AttackChain from './AttackChain';
import AttackFindings from './AttackFindings';
import CaseSummary from './CaseSummary';
import ChallengePanel from './ChallengePanel';
import EmailIntelligence from './EmailIntelligence';
import EvidencePanel from './EvidencePanel';
import FileIntelligence from './FileIntelligence';
import ThreatIntelligence from './ThreatIntelligence';
import URLIntelligence from './URLIntelligence';
import RecoveryGuide from './RecoveryGuide';
export default function CaseResults({ result, challenge, onReview, busy }) {
  const [section, setSection] = useState('overview');
  return <div className="case-results"><p className="success-note" role="status">{result.investigation_id ? 'Investigation available in your private history.' : 'This result was not saved. Check the service status before leaving.'}</p><CaseSummary result={result} challengeResult={challenge} /><nav className="result-nav" aria-label="Result sections">{[['overview','Overview'],['evidence','Supporting evidence'],['technical','Technical details'],['recovery','What to do next']].map(([id,label]) => <button key={id} aria-pressed={section === id} onClick={() => setSection(id)}>{label}</button>)}</nav>
    {section === 'overview' && <><AssessmentCard result={result} challengeLoading={busy} onChallenge={onReview} /><AttackFindings findings={result.attack_findings || []} evidenceItems={result.evidence_items || []} /><p className="muted">A second review considers counter-evidence. It can still be wrong.</p><ChallengePanel result={challenge} /></>}
    {section === 'evidence' && <><EvidencePanel items={result.evidence_items || []} /><AttackChain stages={result.attack_chain || []} evidenceItems={result.evidence_items || []} />{!result.evidence_items?.length && <p>No supporting evidence was captured. Treat this result as incomplete.</p>}</>}
    {section === 'technical' && <><EmailIntelligence analysis={result.email_analysis} /><FileIntelligence fileInfo={result.file_info} analysis={result.file_analysis} /><URLIntelligence results={result.url_analysis || []} /><ThreatIntelligence results={result.threat_intelligence || []} />{!result.email_analysis && !result.file_analysis && !result.url_analysis?.length && !result.threat_intelligence?.length && <p>No technical checks are available for this input.</p>}</>}
    {section === 'recovery' && <RecoveryGuide findings={result.attack_findings || []} />}
  </div>;
}
