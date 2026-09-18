import { useState } from "react";
import "./App.css";

const API_URL =
  import.meta.env.VITE_API_URL ||
  "http://127.0.0.1:8001";

const SUPPORTED_FILES =
  ".txt,.md,.csv,.json,.eml,.pdf,.docx,.pptx,.xlsx,.html,.htm,.svg,.zip";

async function requestJson(url, options) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.detail || "The investigation request failed."
    );
  }

  return data;
}

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
      const data = await requestJson(
        `${API_URL}/investigations`
      );
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
      let data;

      if (file) {
        const formData = new FormData();
        formData.append("file", file);

        data = await requestJson(
          `${API_URL}/investigate-file`,
          {
            method: "POST",
            body: formData,
          }
        );
      } else {
        data = await requestJson(
          `${API_URL}/investigate`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              content: content.trim(),
            }),
          }
        );
      }

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
      const data = await requestJson(
        `${API_URL}/challenge`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            investigation_id: result.investigation_id,
          }),
        }
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
        <>
          <div
            className="history-backdrop"
            onClick={() => setHistoryOpen(false)}
          ></div>

          <aside className="history-sidebar">
            <div className="history-sidebar-header">
              <div className="history-sidebar-title">
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
                history.map((item) => {
                  const preview =
                    item.content ||
                    "No extractable text was stored.";

                  return (
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
                        {preview.length > 90
                          ? `${preview.slice(0, 90)}...`
                          : preview}
                      </div>

                      <div className="history-date">
                        {new Date(
                          `${item.created_at}Z`
                        ).toLocaleString()}
                      </div>
                    </div>
                  );
                })
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
                : "Choose or drop a supported file"}
            </span>

            <span className="upload-formats">
              PDF · DOCX · PPTX · XLSX · EML · ZIP ·
              HTML/SVG · TXT/MD/CSV/JSON · max 10 MB
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
            checked with VirusTotal, and extracted content may
            be processed by Gemini. Raw uploaded files are not
            sent to VirusTotal by this workflow. Avoid submitting
            sensitive or confidential information.
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

        {result?.file_info && (
          <section className="panel file-panel">
            <div className="file-heading">
              <div>
                <h2>File Intelligence</h2>
                <p className="file-note">
                  Static inspection only. The uploaded artifact
                  was not executed.
                </p>
              </div>

              <span className="analysis-badge">
                STATIC ONLY
              </span>
            </div>

            <div className="file-grid">
              <div className="file-field">
                <span>Filename</span>
                <strong>
                  {result.file_info.filename}
                </strong>
              </div>

              <div className="file-field">
                <span>Detected Type</span>
                <strong>
                  {result.file_info.detected_type}
                </strong>
              </div>

              <div className="file-field">
                <span>Declared MIME</span>
                <strong>
                  {result.file_info.declared_mime ||
                    "Not provided"}
                </strong>
              </div>

              <div className="file-field">
                <span>Size</span>
                <strong>
                  {result.file_info.size_bytes.toLocaleString()} bytes
                </strong>
              </div>
            </div>

            <div className="file-hash">
              <span>SHA-256</span>
              <code>{result.file_info.sha256}</code>
            </div>

            <div className="file-findings">
              <h3>
                Static Findings{" "}
                <span className="finding-count">
                  {result.file_analysis?.finding_count || 0}
                </span>
              </h3>

              {result.file_analysis?.findings?.length >
              0 ? (
                <div className="finding-list">
                  {result.file_analysis.findings.map(
                    (finding, index) => (
                      <article
                        className="finding-card"
                        key={index}
                      >
                        <div className="finding-topline">
                          <strong>
                            {finding.attack_type}
                          </strong>

                          <span
                            className={`severity severity-${finding.severity.toLowerCase()}`}
                          >
                            {finding.severity}
                          </span>
                        </div>

                        <div className="finding-meta">
                          {finding.category} ·{" "}
                          {finding.status} ·{" "}
                          {finding.confidence}% confidence
                        </div>

                        <ul>
                          {finding.evidence.map(
                            (item, evidenceIndex) => (
                              <li key={evidenceIndex}>
                                {item}
                              </li>
                            )
                          )}
                        </ul>
                      </article>
                    )
                  )}
                </div>
              ) : (
                <p className="file-clear">
                  No static warning indicators were detected
                  by the checks run. This does not prove the
                  file is safe.
                </p>
              )}
            </div>

            {result.file_analysis?.urls?.length > 0 && (
              <div className="file-urls">
                <h3>URLs Found in File Structure</h3>
                <ul>
                  {result.file_analysis.urls.map(
                    (url, index) => (
                      <li key={index}>
                        <code>{url}</code>
                      </li>
                    )
                  )}
                </ul>
              </div>
            )}
          </section>
        )}

        {result?.email_analysis && (
          <section className="panel email-panel">
            <div className="email-heading">
              <div>
                <h2>Email Intelligence</h2>
                <p className="email-note">
                  Header-derived evidence only. Claimed identity
                  is not verified, and routing geography describes
                  mail infrastructure rather than a person's
                  physical location.
                </p>
              </div>
            </div>

            <div className="email-grid">
              <div className="email-field">
                <span>Claimed Sender</span>
                <strong>
                  {result.email_analysis
                    .claimed_sender_name ||
                    "Not available"}
                </strong>
              </div>

              <div className="email-field">
                <span>Sender Address</span>
                <strong>
                  {result.email_analysis
                    .sender_address ||
                    "Not available"}
                </strong>
              </div>

              <div className="email-field">
                <span>Sender Domain</span>
                <strong>
                  {result.email_analysis
                    .sender_domain ||
                    "Not available"}
                </strong>
              </div>

              <div className="email-field">
                <span>Reply-To</span>
                <strong>
                  {result.email_analysis.reply_to ||
                    "Not available"}
                </strong>
              </div>

              <div className="email-field">
                <span>Return-Path</span>
                <strong>
                  {result.email_analysis
                    .return_path ||
                    "Not available"}
                </strong>
              </div>

              <div className="email-field">
                <span>Subject</span>
                <strong>
                  {result.email_analysis.subject ||
                    "Not available"}
                </strong>
              </div>

              <div className="email-field">
                <span>Message-ID</span>
                <strong>
                  {result.email_analysis
                    .message_id ||
                    "Not available"}
                </strong>
              </div>

              <div className="email-field">
                <span>Claimed Send Time</span>
                <strong>
                  {result.email_analysis
                    .claimed_send_time ||
                    "Not available"}
                </strong>
              </div>

              <div className="email-field">
                <span>Earliest Received Time</span>
                <strong>
                  {result.email_analysis
                    .earliest_received_time ||
                    "Not available"}
                </strong>
              </div>

              <div className="email-field">
                <span>Originating Routing IP</span>
                <strong>
                  {result.email_analysis
                    .originating_ip ||
                    "Not available"}
                </strong>
              </div>

              <div className="email-field">
                <span>Likely Routing Country</span>
                <strong>
                  {result.email_analysis
                    .routing_intelligence
                    ?.status === "success"
                    ? result.email_analysis
                        .routing_intelligence
                        .country ||
                      "Not available"
                    : "Not available"}
                </strong>
              </div>

              <div className="email-field">
                <span>Network / ASN</span>
                <strong>
                  {result.email_analysis
                    .routing_intelligence
                    ?.status === "success"
                    ? [
                        result.email_analysis
                          .routing_intelligence
                          .as_owner,
                        result.email_analysis
                          .routing_intelligence
                          .asn
                          ? `AS${result.email_analysis
                              .routing_intelligence
                              .asn}`
                          : null,
                        result.email_analysis
                          .routing_intelligence
                          .network,
                      ]
                        .filter(Boolean)
                        .join(" · ") ||
                      "Not available"
                    : "Not available"}
                </strong>
              </div>
            </div>

            <div className="email-auth">
              <span>
                SPF:{" "}
                <strong>
                  {result.email_analysis
                    .authentication?.spf ||
                    "not_reported"}
                </strong>
              </span>
              <span>
                DKIM:{" "}
                <strong>
                  {result.email_analysis
                    .authentication?.dkim ||
                    "not_reported"}
                </strong>
              </span>
              <span>
                DMARC:{" "}
                <strong>
                  {result.email_analysis
                    .authentication?.dmarc ||
                    "not_reported"}
                </strong>
              </span>
            </div>

            <p className="email-auth-note">
              SPF, DKIM, and DMARC values above are
              reported by the uploaded message headers;
              they are not independently re-verified yet.
            </p>

            {result.email_analysis.warnings?.length >
              0 && (
              <div className="email-warnings">
                <h3>Header Indicators</h3>
                <ul>
                  {result.email_analysis
                    .warnings.map(
                      (warning, index) => (
                        <li key={index}>
                          {warning}
                        </li>
                      )
                    )}
                </ul>
              </div>
            )}

            {result.email_analysis.attachments?.length >
              0 && (
              <div className="email-warnings">
                <h3>Attachments</h3>
                <ul>
                  {result.email_analysis
                    .attachments.map(
                      (attachment, index) => (
                        <li key={index}>
                          {attachment.filename ||
                            "Unnamed attachment"}{" "}
                          · {attachment.content_type} ·{" "}
                          {attachment.size_bytes} bytes
                        </li>
                      )
                    )}
                </ul>
              </div>
            )}
          </section>
        )}

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
