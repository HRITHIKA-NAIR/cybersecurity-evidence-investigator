import { useState } from "react";
import "./App.css";

function App() {
  const [content, setContent] = useState("");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const investigate = async () => {
    if (!content.trim() && !file) {
      setError("Enter suspicious content or select a file.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      let investigationContent = content;

      if (file) {
        investigationContent = await file.text();
      }

      const response = await fetch("http://127.0.0.1:8001/investigate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ content: investigationContent }),
      });

      if (!response.ok) {
        throw new Error("Investigation failed.");
      }

      const data = await response.json();
      setResult(data);
    } catch {
      setError("Could not connect to the investigation service.");
    } finally {
      setLoading(false);
    }
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

      <main className="dashboard">
        <section className="panel">
          <h2>Investigate</h2>

          <label className="upload-box">
            <span className="upload-title">Upload suspicious file</span>
            <span className="upload-text">
              {file ? file.name : "Choose a .txt or .eml file"}
            </span>

            <input
              type="file"
              accept=".txt,.eml"
              onChange={(event) => setFile(event.target.files[0])}
            />
          </label>

          <div className="divider">
            <span>OR</span>
          </div>

          <textarea
            value={content}
            onChange={(event) => setContent(event.target.value)}
            placeholder="Paste a suspicious URL, email, or text..."
            rows="8"
          />

          {error && <p className="error">{error}</p>}

          <button onClick={investigate} disabled={loading}>
            {loading ? "Investigating..." : "Start Investigation"}
          </button>
        </section>

        <section className="panel">
          <h2>Investigation Progress</h2>

          <ul className="progress-list">
            <li>{result ? "✓" : "○"} Extract indicators</li>
            <li>{result ? "✓" : "○"} Analyze URL</li>
            <li>{result ? "✓" : "○"} Investigate domain</li>
            <li>{result ? "✓" : "○"} Gather security evidence</li>
            <li>{result ? "✓" : "○"} Search counter-evidence</li>
            <li>{result ? "✓" : "○"} Calculate assessment</li>
          </ul>
        </section>

        <section className="results-grid">
          <div className="panel">
            <h2>Threat Score</h2>
            <div className="score">
              {result ? `${result.threat_score} / 100` : "-- / 100"}
            </div>
          </div>

          <div className="panel">
            <h2>AI Assessment</h2>

            {result ? (
              <>
                <p>{result.verdict}</p>
                <p>Confidence: {result.confidence}%</p>
              </>
            ) : (
              <p>No investigation has been run yet.</p>
            )}
          </div>
        </section>

        <section className="panel">
          <h2>Evidence</h2>

          {result ? (
            <ul>
              {result.evidence.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          ) : (
            <p>Evidence will appear here after investigation.</p>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;