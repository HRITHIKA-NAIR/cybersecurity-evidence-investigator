function FileIntelligence({ fileInfo, analysis }) {
  if (!fileInfo && !analysis) {
    return null;
  }

  const findings = analysis?.findings || [];
  const qrPayloads = analysis?.qr?.payloads || [];
  const urls = analysis?.urls || [];
  const metadata = analysis?.metadata || {};
  const nestedArtifacts =
    analysis?.nested_artifacts || [];
  const metadataEntries =
    Object.entries(metadata).filter(
      ([, value]) =>
        value !== null &&
        value !== undefined &&
        value !== ""
    );

  return (
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

      {fileInfo ? (
        <>
          <div className="file-grid">
            <div className="file-field">
              <span>Filename</span>
              <strong>{fileInfo.filename}</strong>
            </div>

            <div className="file-field">
              <span>Detected Type</span>
              <strong>{fileInfo.detected_type}</strong>
            </div>

            <div className="file-field">
              <span>Declared MIME</span>
              <strong>
                {fileInfo.declared_mime || "Not provided"}
              </strong>
            </div>

            <div className="file-field">
              <span>Size</span>
              <strong>
                {fileInfo.size_bytes.toLocaleString()} bytes
              </strong>
            </div>
          </div>

          <div className="file-hash">
            <span>SHA-256</span>
            <code>{fileInfo.sha256}</code>
          </div>
        </>
      ) : (
        <p className="limitation-note">
          File metadata is not available for this stored
          history record, but persisted static findings
          are shown below.
        </p>
      )}

      {metadataEntries.length > 0 && (
        <div className="file-urls">
          <h3>Document Metadata</h3>
          <div className="file-grid">
            {metadataEntries.map(
              ([key, value]) => (
                <div
                  className="file-field"
                  key={key}
                >
                  <span>
                    {key.replaceAll("_", " ")}
                  </span>
                  <strong>
                    {String(value)}
                  </strong>
                </div>
              )
            )}
          </div>
        </div>
      )}

      {nestedArtifacts.length > 0 && (
        <div className="file-urls">
          <h3>Nested Artifacts</h3>
          <ul>
            {nestedArtifacts.map(
              (artifact, index) => (
                <li key={index}>
                  {artifact.file_info?.filename ||
                    "Unnamed attachment"}{" "}
                  ·{" "}
                  {artifact.file_info
                    ?.detected_type ||
                    "unknown type"}
                </li>
              )
            )}
          </ul>
        </div>
      )}

      <div className="file-findings">
        <h3>
          Static Findings{" "}
          <span className="finding-count">
            {analysis?.finding_count || 0}
          </span>
        </h3>

        {findings.length > 0 ? (
          <div className="finding-list">
            {findings.map((finding, index) => (
              <article
                className="finding-card"
                key={`${finding.attack_type}-${index}`}
              >
                <div className="finding-topline">
                  <strong>{finding.attack_type}</strong>

                  <span
                    className={`severity severity-${finding.severity.toLowerCase()}`}
                  >
                    {finding.severity}
                  </span>
                </div>

                <div className="finding-meta">
                  {finding.category} · {finding.status} ·{" "}
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
            ))}
          </div>
        ) : (
          <p className="file-clear">
            No static warning indicators were detected
            by the checks run. This does not prove the
            file is safe.
          </p>
        )}
      </div>

      {qrPayloads.length > 0 && (
        <div className="file-urls">
          <h3>QR Payloads</h3>
          <ul>
            {qrPayloads.map((item, index) => (
              <li key={`${item.source}-${index}`}>
                <code>{item.payload}</code>
                <span className="qr-source">
                  {" "}· {item.source}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {urls.length > 0 && (
        <div className="file-urls">
          <h3>URLs Extracted from File</h3>
          <ul>
            {urls.map((url) => (
              <li key={url}>
                <code>{url}</code>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

export default FileIntelligence;
