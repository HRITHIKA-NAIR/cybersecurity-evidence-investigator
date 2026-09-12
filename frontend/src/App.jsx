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
    } catch {
      setError(
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
        </div>

        <div className="status">
          <span className="status-dot"></span>
          SYSTEM READY
        </div>
      </header>

      <main className="dashboard">
        <section className="panel">
          <h2>Investigate</h2>

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
          <h2>
            Investigation Progress
          </h2>

          <ul className="progress-list">
            <li>
              {result?.stages
                ?.extract_indicators
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
              {result?.stages
                ?.investigate_domain
                ? "✓"
                : "○"}{" "}
              Investigate domain
            </li>

            <li>
              {result?.stages
                ?.gather_evidence
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
              {result?.stages
                ?.calculate_assessment
                ? "✓"
                : "○"}{" "}
              Calculate assessment
            </li>
          </ul>
        </section>

        <section className="results-grid">
          <div className="panel">
            <h2>Threat Score</h2>

            <div className="score">
              {result
                ? `${result.threat_score} / 100`
                : "-- / 100"}
            </div>
          </div>

          <div className="panel">
            <h2>AI Assessment</h2>

            {result ? (
              <>
                <p>
                  <strong>
                    {result.verdict}
                  </strong>
                </p>

                <p>
                  Confidence:{" "}
                  {result.confidence}%
                </p>

                <p>
                  {result.reasoning}
                </p>

                {result.insufficient_evidence && (
                  <p className="warning-text">
                    Evidence is
                    insufficient for a
                    definitive conclusion.
                  </p>
                )}

                <button
                  className="challenge-button"
                  onClick={
                    challengeConclusion
                  }
                  disabled={
                    challengeLoading
                  }
                >
                  {challengeLoading
                    ? "Challenging Conclusion..."
                    : "Challenge Conclusion"}
                </button>
              </>
            ) : (
              <p>
                No investigation has been
                run yet.
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
              <p>
                No evidence was collected.
              </p>
            )
          ) : (
            <p>
              Evidence will appear here
              after investigation.
            </p>
          )}
        </section>

        {challengeResult && (
          <section className="panel challenge-panel">
            <h2>
              Counter-Evidence Review
            </h2>

            {challengeResult
              .counter_evidence?.length >
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
                No meaningful
                counter-evidence was
                identified in the
                collected evidence.
              </p>
            )}

            <h3>
              Revised Assessment
            </h3>

            <p>
              <strong>
                {
                  challengeResult.revised_verdict
                }
              </strong>
            </p>

            <p>
              Confidence:{" "}
              {
                challengeResult.revised_confidence
              }
              %
            </p>

            <p>
              {
                challengeResult.reasoning
              }
            </p>

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