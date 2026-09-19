import {
  buildEvidenceIndex,
  evidenceLabel,
} from "../utils/evidence";
import { getSeverityClass } from "../utils/risk";

function AttackFindings({
  findings = [],
  evidenceItems = [],
}) {
  if (!findings.length) {
    return null;
  }

  const evidenceIndex =
    buildEvidenceIndex(evidenceItems);

  return (
    <section className="panel">
      <div className="panel-heading-row">
        <div>
          <h2>Attack Findings</h2>
          <p className="panel-subtitle">
            Multiple findings can apply to one case.
            Status reflects evidence strength, not a
            claim that compromise definitely occurred.
          </p>
        </div>

        <span className="finding-count">
          {findings.length}
        </span>
      </div>

      <div className="finding-list">
        {findings.map((finding, index) => (
          <details
            className="finding-card"
            key={
              finding.attack_type +
              "-" +
              index
            }
          >
            <summary>
              <div className="finding-summary-main">
                <strong>
                  {finding.attack_type}
                </strong>
                <span className="finding-meta">
                  {finding.category} ·{" "}
                  {finding.status} ·{" "}
                  {finding.confidence}% confidence
                </span>
              </div>

              <span
                className={
                  "severity " +
                  getSeverityClass(
                    finding.severity
                  )
                }
              >
                {finding.severity}
              </span>
            </summary>

            <div className="finding-details">
              <div>
                <span className="detail-label">
                  Detector
                </span>
                <p>{finding.detector}</p>
              </div>

              {finding.limitations?.length > 0 && (
                <div>
                  <span className="detail-label">
                    Limitations
                  </span>
                  <ul>
                    {finding.limitations.map(
                      (item, itemIndex) => (
                        <li key={itemIndex}>
                          {item}
                        </li>
                      )
                    )}
                  </ul>
                </div>
              )}

              <div>
                <span className="detail-label">
                  Evidence
                </span>
                <ul>
                  {finding.evidence_ids.map(
                    (id) => (
                      <li key={id}>
                        <code>{id}</code>{" "}
                        {evidenceLabel(
                          evidenceIndex.get(id)
                        )}
                      </li>
                    )
                  )}
                </ul>
              </div>
            </div>
          </details>
        ))}
      </div>
    </section>
  );
}

export default AttackFindings;
