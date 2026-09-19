function ThreatIntelligence({
  results = [],
}) {
  if (!results.length) {
    return null;
  }

  return (
    <section className="panel">
      <h2>Threat Intelligence</h2>
      <p className="panel-subtitle">
        VirusTotal evidence is shown as reported.
        Undetected does not mean harmless.
      </p>

      <div className="threat-grid">
        {results.map((result, index) => (
          <article
            className="threat-card"
            key={
              (result.domain ||
                result.ip ||
                "intel") +
              "-" +
              index
            }
          >
            <div className="threat-card-topline">
              <strong>
                {result.domain ||
                  result.ip ||
                  "Threat intelligence result"}
              </strong>
              <span
                className={
                  "intel-status intel-" +
                  (
                    result.status ||
                    "unknown"
                  )
                }
              >
                {result.status || "unknown"}
              </span>
            </div>

            {result.status === "success" ? (
              <div className="intel-stats">
                <div>
                  <span>Malicious</span>
                  <strong>
                    {result.malicious ?? 0}
                  </strong>
                </div>
                <div>
                  <span>Suspicious</span>
                  <strong>
                    {result.suspicious ?? 0}
                  </strong>
                </div>
                <div>
                  <span>Harmless</span>
                  <strong>
                    {result.harmless ?? 0}
                  </strong>
                </div>
                <div>
                  <span>Undetected</span>
                  <strong>
                    {result.undetected ?? 0}
                  </strong>
                </div>
              </div>
            ) : (
              <p className="limitation-note">
                {result.message ||
                  "Threat intelligence unavailable."}
              </p>
            )}
          </article>
        ))}
      </div>
    </section>
  );
}

export default ThreatIntelligence;
