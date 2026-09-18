import { useState } from "react";
import EmailIntelligence from "./components/EmailIntelligence";
import FileIntelligence from "./components/FileIntelligence";
import HistoryDrawer from "./components/HistoryDrawer";
import {
  challengeInvestigation,
  getInvestigations,
  investigateFile,
  investigateText,
} from "./services/api";
import "./App.css";

const SUPPORTED_FILES =
  ".txt,.md,.csv,.json,.eml,.pdf,.docx,.pptx,.xlsx,.html,.htm,.svg,.zip,.png,.jpg,.jpeg,.gif,.bmp,.webp";

function App() {
  const [content, setContent] = useState("");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [challengeResult, setChallengeResult] = useState(null);
  const [challengeLoading, setChallengeLoading] = useState(false);

  const [history, setHistory] = useState([]);
  const [historyOpen, setHistoryOpen] = useState(false);

  const loadHistory = async () => {
    try {
      const data = await getInvestigations();
      setHistory(data.slice(0, 10));
    } catch {
      console.log("History unavailable");
    }
  };

  const openHistory = async () => {
    await loadHistory();
    setHistoryOpen(true);
  };

  const investigate = async () => {
    if (!content.trim() && !file) {
      setError("Enter suspicious content or select a file.");
      return;
    }

    setLoading(true);
    setError("");
    setChallengeResult(null);

    try {
      const data = file
        ? await investigateFile(file)
        : await investigateText(content.trim());

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
    if (!result) {
      return;
    }

    setChallengeLoading(true);
    setError("");

    try {
      const data = await challengeInvestigation(
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

  const getRiskClass = (verdict) => {
    if (verdict === "High Risk") {
      return "risk-high";
    }

    if (verdict === "Suspicious") {
      return "risk-suspicious";
    }

    if (verdict === "Low Risk") {
      return "risk-low";
    }

    return "risk-inconclusive";
  };

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>EVIDENCE</h1>
          <p>Cybersecurity Evidence Investigator</p>
        </div>

        <div className="status">
          <span className="status-dot"></span>
          SYSTEM READY
        </div>
      </header>

      {historyOpen && (
        <HistoryDrawer
          history={history}
          onClose={() => setHistoryOpen(false)}
        />
      )}

      <main className="dashboard">
        <section className="panel">
          <div className="investigate-heading">
            <h2>Investigate</h2>

            <button
              className="history-button"
              onClick={openHistory}
            >
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path
                  d="M12 8v5l3 2M3.05 11a9 9 0 1 0 2.64-5.36L3 8M3 3v5h5"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>

              HISTORY
            </button>
          </div>

          <label className="upload-box">
            <span className="upload-title">
              Upload suspicious file
            </span>

            <span className="upload-text">
              {file
                ? file.name
                : "Choose a supported file"}
            </span>

            <span className="upload-formats">
              PDF · DOCX · PPTX · XLSX · EML · ZIP ·
              HTML/SVG · PNG/JPG/WEBP/GIF/BMP ·
              TXT/MD/CSV/JSON · max 10 MB
            </span>

            <input
              type="file"
              accept={SUPPORTED_FILES}
              onChange={(event) =>
                setFile(event.target.files[0] || null)
              }
            />
          </label>

          <div className="divider">
            <span>OR</span>
          </div>

          <textarea
            value={content}
            onChange={(event) =>
              setContent(event.target.value)
            }
            placeholder="Paste a suspicious URL, email, or text..."
            rows="8"
          />

          <p className="processing-notice">
            Extracted domains and public routing IPs may be
            checked with VirusTotal. Submitted URLs may be
            contacted by the backend for bounded redirect checks,
            and extracted content may be processed by Gemini.
            Raw uploaded files are not sent to VirusTotal.
            Avoid submitting sensitive or confidential information.
          </p>

          {error && <p className="error">{error}</p>}

          <button
            onClick={investigate}
            disabled={loading}
          >
            {loading
              ? "Investigating..."
              : "Start Investigation"}
          </button>
        </section>

        <section className="panel">
          <h2>Investigation Progress</h2>

          <ul className="progress-list">
            <li>
              {result?.stages?.extract_indicators
                ? "✓"
                : "○"}{" "}
              Extract indicators
            </li>

            <li>
              {result?.stages?.analyze_url
                ? "✓"
                : "○"}{" "}
              Analyze URL
            </li>

            <li>
              {result?.stages?.investigate_domain
                ? "✓"
                : "○"}{" "}
              Investigate domain
            </li>

            <li>
              {result?.stages?.gather_evidence
                ? "✓"
                : "○"}{" "}
              Gather security evidence
            </li>

            <li>
              {challengeResult ? "✓" : "○"}{" "}
              Search counter-evidence
            </li>

            <li>
              {result?.stages?.calculate_assessment
                ? "✓"
                : "○"}{" "}
              Calculate assessment
            </li>
          </ul>
        </section>

        <section className="results-grid">
          <div className="panel">
            <h2>Threat Score</h2>

            <div
              className={`score ${
                result
                  ? getRiskClass(result.verdict)
                  : ""
              }`}
            >
              {result
                ? `${result.threat_score} / 100`
                : "-- / 100"}
            </div>
          </div>

          <div className="panel">
            <h2>AI Assessment</h2>

            {result ? (
              <>
                <p
                  className={`verdict-badge ${getRiskClass(
                    result.verdict
                  )}`}
                >
                  {result.verdict}
                </p>

                <p>
                  Confidence: {result.confidence}%
                </p>

                <p>{result.reasoning}</p>

                {result.insufficient_evidence && (
                  <p className="warning-text">
                    Evidence is insufficient for a
                    definitive conclusion.
                  </p>
                )}

                <button
                  className="challenge-button"
                  onClick={challengeConclusion}
                  disabled={challengeLoading}
                >
                  {challengeLoading
                    ? "Challenging Conclusion..."
                    : "Challenge Conclusion"}
                </button>
              </>
            ) : (
              <p>
                No investigation has been run yet.
              </p>
            )}
          </div>
        </section>

        <FileIntelligence
          fileInfo={result?.file_info}
          analysis={result?.file_analysis}
        />

        <EmailIntelligence
          analysis={result?.email_analysis}
        />

        <section className="panel">
          <h2>Evidence</h2>

          {result ? (
            result.evidence?.length > 0 ? (
              <ul>
                {result.evidence.map(
                  (item, index) => (
                    <li key={index}>
                      {item}
                    </li>
                  )
                )}
              </ul>
            ) : (
              <p>No evidence was collected.</p>
            )
          ) : (
            <p>
              Evidence will appear here after
              investigation.
            </p>
          )}
        </section>

        {challengeResult && (
          <section className="panel challenge-panel">
            <h2>Counter-Evidence Review</h2>

            {challengeResult.counter_evidence?.length >
            0 ? (
              <ul>
                {challengeResult.counter_evidence.map(
                  (item, index) => (
                    <li key={index}>
                      {item}
                    </li>
                  )
                )}
              </ul>
            ) : (
              <p>
                No meaningful counter-evidence was
                identified in the collected evidence.
              </p>
            )}

            <h3>Revised Assessment</h3>

            <p
              className={`verdict-badge ${getRiskClass(
                challengeResult.revised_verdict
              )}`}
            >
              {challengeResult.revised_verdict}
            </p>

            <p>
              Confidence:{" "}
              {challengeResult.revised_confidence}%
            </p>

            <p>{challengeResult.reasoning}</p>

            <p>
              Conclusion changed:{" "}
              <strong>
                {challengeResult.conclusion_changed
                  ? "Yes"
                  : "No"}
              </strong>
            </p>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
