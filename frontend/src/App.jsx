import { useState } from "react";

import AssessmentCard from "./components/AssessmentCard";
import AttackChain from "./components/AttackChain";
import AttackFindings from "./components/AttackFindings";
import CaseSummary from "./components/CaseSummary";
import ChallengePanel from "./components/ChallengePanel";
import EmailIntelligence from "./components/EmailIntelligence";
import EvidencePanel from "./components/EvidencePanel";
import FileIntelligence from "./components/FileIntelligence";
import HistoryDrawer from "./components/HistoryDrawer";
import InvestigationInput from "./components/InvestigationInput";
import InvestigationProgress from "./components/InvestigationProgress";
import ThreatIntelligence from "./components/ThreatIntelligence";
import URLIntelligence from "./components/URLIntelligence";
import {
  challengeInvestigation,
  getInvestigations,
  investigateFile,
  investigateText,
} from "./services/api";
import "./App.css";

const SUPPORTED_FILES =
  ".txt,.md,.csv,.json,.eml,.pdf,.docx,.docm,.pptx,.pptm,.xlsx,.xlsm,.html,.htm,.svg,.js,.ps1,.vbs,.bat,.cmd,.lnk,.iso,.zip,.7z,.png,.jpg,.jpeg,.gif,.bmp,.webp";

function App() {
  const [content, setContent] = useState("");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [
    challengeResult,
    setChallengeResult,
  ] = useState(null);
  const [
    challengeLoading,
    setChallengeLoading,
  ] = useState(false);
  const [history, setHistory] = useState([]);
  const [
    historyOpen,
    setHistoryOpen,
  ] = useState(false);

  const loadHistory = async () => {
    try {
      const data =
        await getInvestigations();
      setHistory(data.slice(0, 10));
    } catch {
      setHistory([]);
    }
  };

  const openHistory = async () => {
    await loadHistory();
    setHistoryOpen(true);
  };

  const selectHistory = (item) => {
    setResult({
      ...item,
      investigation_id:
        item.investigation_id ||
        item.id,
    });
    setChallengeResult(
      item.challenge_result || null
    );
    setFile(null);
    setContent("");
    setError("");
    setHistoryOpen(false);
  };

  const investigate = async () => {
    if (!content.trim() && !file) {
      setError(
        "Enter suspicious content or select a file."
      );
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);
    setChallengeResult(null);

    try {
      const data = file
        ? await investigateFile(file)
        : await investigateText(
            content.trim()
          );

      setResult(data);
      await loadHistory();
    } catch (requestError) {
      setError(
        requestError.message ||
          "Could not connect to the investigation service."
      );
    } finally {
      setLoading(false);
    }
  };

  const challengeConclusion = async () => {
    if (!result?.investigation_id) {
      return;
    }

    setChallengeLoading(true);
    setError("");

    try {
      const data =
        await challengeInvestigation(
          result.investigation_id
        );

      setChallengeResult(data);
      await loadHistory();
    } catch (requestError) {
      setError(
        requestError.message ||
          "Could not challenge the current conclusion."
      );
    } finally {
      setChallengeLoading(false);
    }
  };

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>EVIDENCE</h1>
          <p>
            Cybersecurity Evidence Investigator
          </p>
          <span className="tagline">
            Evidence before verdict.
          </span>
        </div>

        <div className="status">
          <span className="status-dot" />
          SYSTEM READY
        </div>
      </header>

      {historyOpen && (
        <HistoryDrawer
          history={history}
          onClose={() =>
            setHistoryOpen(false)
          }
          onSelect={selectHistory}
        />
      )}

      <main className="dashboard">
        <InvestigationInput
          content={content}
          file={file}
          supportedFiles={SUPPORTED_FILES}
          loading={loading}
          error={error}
          onContentChange={setContent}
          onFileChange={setFile}
          onError={setError}
          onSubmit={investigate}
          onOpenHistory={openHistory}
        />

        <InvestigationProgress
          loading={loading}
          result={result}
          hasFile={Boolean(file)}
        />

        <CaseSummary
          result={result}
          challengeResult={
            challengeResult
          }
        />

        <AssessmentCard
          result={result}
          challengeLoading={
            challengeLoading
          }
          onChallenge={
            challengeConclusion
          }
        />

        <AttackFindings
          findings={
            result?.attack_findings
          }
          evidenceItems={
            result?.evidence_items
          }
        />

        <AttackChain
          stages={result?.attack_chain}
          evidenceItems={
            result?.evidence_items
          }
        />

        <EmailIntelligence
          analysis={
            result?.email_analysis
          }
        />

        <FileIntelligence
          fileInfo={result?.file_info}
          analysis={
            result?.file_analysis
          }
        />

        <URLIntelligence
          results={result?.url_analysis}
        />

        <ThreatIntelligence
          results={
            result?.threat_intelligence
          }
        />

        <EvidencePanel
          items={result?.evidence_items}
        />

        <ChallengePanel
          result={challengeResult}
        />
      </main>
    </div>
  );
}

export default App;
