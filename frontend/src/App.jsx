import "./App.css";

function App() {
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
            <span className="upload-text">Choose a .txt or .eml file</span>
            <input type="file" accept=".txt,.eml" />
          </label>

          <div className="divider">
            <span>OR</span>
          </div>

          <textarea
            placeholder="Paste a suspicious URL, email, or text..."
            rows="8"
          />

          <button>Start Investigation</button>
        </section>

        <section className="panel">
          <h2>Investigation Progress</h2>

          <ul className="progress-list">
            <li>○ Extract indicators</li>
            <li>○ Analyze URL</li>
            <li>○ Investigate domain</li>
            <li>○ Gather security evidence</li>
            <li>○ Search counter-evidence</li>
            <li>○ Calculate assessment</li>
          </ul>
        </section>

        <section className="results-grid">
          <div className="panel">
            <h2>Threat Score</h2>
            <div className="score">-- / 100</div>
          </div>

          <div className="panel">
            <h2>AI Assessment</h2>
            <p>No investigation has been run yet.</p>
          </div>
        </section>

        <section className="panel">
          <h2>Evidence</h2>
          <p>Evidence will appear here after investigation.</p>
        </section>
      </main>
    </div>
  );
}

export default App;