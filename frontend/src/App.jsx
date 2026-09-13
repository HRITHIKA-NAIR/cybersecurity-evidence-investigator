import { useState } from "react";
import "./App.css";

function App() {
  const [content, setContent] = useState("");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [submittedContent, setSubmittedContent] = useState("");

  const [challengeResult, setChallengeResult] = useState(null);
  const [challengeLoading, setChallengeLoading] = useState(false);

  const [history, setHistory] = useState([]);
  const [historyOpen, setHistoryOpen] = useState(false);

  const loadHistory = async () => {
    try {
      const response = await fetch(
        "http://127.0.0.1:8001/investigations"
      );

      if (!response.ok) {
        return;
      }

      const data = await response.json();
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
      let investigationContent = content;

      if (file) {
        investigationContent = await file.text();
      }

      setSubmittedContent(investigationContent);

      const response = await fetch(
        "http://127.0.0.1:8001/investigate",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            content: investigationContent,
          }),
        }
      );

      if (!response.ok) {
        throw new Error("Investigation failed.");
      }

      const data = await response.json();

      setResult(data);
      await loadHistory();
    } catch {
      setError(
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
      const response = await fetch(
        "http://127.0.0.1:8001/challenge",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            investigation_id: result.investigation_id,
            content: submittedContent,
            indicators: result.indicators,
            url_analysis: result.url_analysis,
            threat_intelligence:
              result.threat_intelligence,
            original_assessment: {
              threat_score: result.threat_score,
              verdict: result.verdict,
              confidence: result.confidence,
              reasoning: result.reasoning,
            },
          }),
        }
      );

      if (!response.ok) {
        throw new Error("Challenge failed.");
      }

      const data = await response.json();

      setChallengeResult(data);
      await loadHistory();
    } catch {
      setError(
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
        <>
          <div
            className="history-backdrop"
            onClick={() => setHistoryOpen(false)}
          ></div>

          <aside className="history-sidebar">
            <div className="history-sidebar-header">
              <div className="history-sidebar-title">
                <svg
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    d="M12 8v5l3 2M3.05 11a9 9 0 1 0 2.64-5.36L3 8M3 3v5h5"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>

                <span>HISTORY</span>
              </div>

              <button
                className="history-close"
                onClick={() => setHistoryOpen(false)}
                aria-label="Close history"
              >
                ×
              </button>
            </div>

            <div className="history-list">
              {history.length > 0 ? (
                history.map((item) => (
                  <div
                    className="history-item"
                    key={item.id}
                  >
                    <div className="history-main">
                      <span className="history-id">
                        CASE #{item.id}
                      </span>

                      <span className="history-verdict">
                        {item.verdict}
                      </span>
                    </div>

                    <div className="history-details">
                      <span>
                        Score {item.threat_score}/100
                      </span>

                      <span>
                        Confidence {item.confidence}%
                      </span>
                    </div>

                    <div className="history-status">
                      {item.challenge_result
                        ? "Challenged"
                        : "Initial assessment"}
                    </div>

                    <div className="history-input">
                      {item.content.length > 90
                        ? `${item.content.slice(0, 90)}...`
                        : item.content}
                    </div>

                    <div className="history-date">
                      {new Date(
                        `${item.created_at}Z`
                      ).toLocaleString()}
                    </div>
                  </div>
                ))
              ) : (
                <p className="history-empty">
                  No investigations stored yet.
                </p>
              )}
            </div>
          </aside>
        </>
      )}

      <main className="dashboard">
        <section className="panel">
          <div className="investigate-heading">
            <h2>Investigate</h2>

            <button
              className="history-button"
              onClick={openHistory}
            >
              <svg
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
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
                : "Choose a .txt or .eml file"}
            </span>

            <input
              type="file"
              accept=".txt,.eml"
              onChange={(event) =>
                setFile(
                  event.target.files[0] || null
                )
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
            Submitted domains may be checked with VirusTotal
            and content may be processed by Gemini. Avoid
            submitting sensitive or confidential information.
          </p>

          {error && (
            <p className="error">
              {error}
            </p>
          )}

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
              {challengeResult
                ? "✓"
                : "○"}{" "}
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