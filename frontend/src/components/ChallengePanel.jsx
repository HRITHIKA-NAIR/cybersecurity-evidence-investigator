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
