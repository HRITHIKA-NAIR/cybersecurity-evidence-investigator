import { getRiskClass } from "../utils/risk";

function ChallengePanel({
  result,
}) {
  if (!result) {
    return null;
  }

  return (
    <section className="panel challenge-panel">
      <div className="panel-heading-row">
        <div>
          <h2>Challenge Conclusion</h2>
          <p className="panel-subtitle">
            Adversarial re-review of the same
            collected evidence.
          </p>
        </div>

        <span
          className={
            "verdict-badge " +
            getRiskClass(
              result.revised_verdict
            )
          }
        >
          {result.revised_verdict}
        </span>
      </div>

      <div className="challenge-summary">
        <div>
          <span>Revised risk score</span>
          <strong>
            {result.revised_threat_score}/100
          </strong>
        </div>

        <div>
          <span>Revised confidence</span>
          <strong>
            {result.revised_confidence}%
          </strong>
        </div>

        <div>
          <span>Conclusion changed</span>
          <strong>
            {result.conclusion_changed
              ? "Yes"
              : "No"}
          </strong>
        </div>
      </div>

      <p>{result.reasoning}</p>

      {result.persistence?.status ===
        "unavailable" && (
        <p className="warning-text">
          {result.persistence.message}
        </p>
      )}

      {result.uncertainty?.length > 0 && (
        <div className="challenge-evidence">
          <h3>Uncertainty</h3>
          <ul>
            {result.uncertainty.map(
              (item, index) => (
                <li key={index}>{item}</li>
              )
            )}
          </ul>
        </div>
      )}

      <div className="challenge-evidence">
        <h3>Counter-Evidence</h3>

        {result.counter_evidence?.length >
        0 ? (
          <ul>
            {result.counter_evidence.map(
              (item, index) => (
                <li key={index}>{item}</li>
              )
            )}
          </ul>
        ) : (
          <p className="empty-state">
            No meaningful counter-evidence was
            identified in the collected evidence.
          </p>
        )}
      </div>
    </section>
  );
}

export default ChallengePanel;
