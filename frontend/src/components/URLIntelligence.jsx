function finalUrl(result) {
  const hops =
    result.redirect_analysis?.hops || [];

  if (hops.length > 0) {
    return hops[hops.length - 1].url;
  }

  return (
    result.normalized_url ||
    result.url ||
    "Not available"
  );
}

function URLIntelligence({
  results = [],
}) {
  if (!results.length) {
    return null;
  }

  return (
    <section className="panel">
      <h2>URL Intelligence</h2>
      <p className="panel-subtitle">
        Structural indicators and bounded redirect
        observations. URL heuristics do not prove a
        destination is malicious.
      </p>

      <div className="url-list">
        {results.map((result, index) => {
          const redirect =
            result.redirect_analysis || {};
          const hops = redirect.hops || [];

          return (
            <article
              className="url-card"
              key={
                result.url +
                "-" +
                index
              }
            >
              <div className="url-grid">
                <div>
                  <span>Original URL</span>
                  <code>
                    {result.url ||
                      "Not available"}
                  </code>
                </div>

                <div>
                  <span>Registered Domain</span>
                  <strong>
                    {result.registered_domain ||
                      result.hostname ||
                      "Not available"}
                  </strong>
                </div>

                <div>
                  <span>Final Observed URL</span>
                  <code>
                    {finalUrl(result)}
                  </code>
                </div>

                <div>
                  <span>Redirect Status</span>
                  <strong>
                    {redirect.status ||
                      "Not checked"}
                  </strong>
                </div>
              </div>

              {result.findings?.length > 0 && (
                <div className="url-section">
                  <h3>URL Indicators</h3>
                  <ul>
                    {result.findings.map(
                      (finding, findingIndex) => (
                        <li
                          key={findingIndex}
                          className={
                            "url-finding " +
                            (
                              finding.type ||
                              "info"
                            )
                          }
                        >
                          {finding.message}
                        </li>
                      )
                    )}
                  </ul>
                </div>
              )}

              {hops.length > 0 && (
                <div className="url-section">
                  <h3>Redirect Hops</h3>
                  <ol className="redirect-list">
                    {hops.map(
                      (hop, hopIndex) => (
                        <li key={hopIndex}>
                          <code>{hop.url}</code>
                          <span>
                            HTTP{" "}
                            {hop.status_code}
                            {" · "}
                            {hop.method}
                          </span>
                        </li>
                      )
                    )}
                  </ol>
                </div>
              )}

              {redirect.reason && (
                <p className="limitation-note">
                  {redirect.reason}
                </p>
              )}
            </article>
          );
        })}
      </div>
    </section>
  );
}

export default URLIntelligence;
