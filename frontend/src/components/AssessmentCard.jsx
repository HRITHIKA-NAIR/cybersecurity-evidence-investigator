import { getRiskClass } from "../utils/risk";

function AssessmentCard({
  result,
  challengeLoading,
  onChallenge,
}) {
  return (
    <section className="assessment-grid">
      <div className="panel score-panel">
        <span className="eyebrow">
          OVERALL RISK
        </span>

        <div
          className={
            "score " +
            (result
              ? getRiskClass(
                  result.verdict
                )
              : "")
          }
        >
          {result
            ? result.threat_score
            : "--"}
        </div>

        <span className="score-denominator">
          / 100
        </span>
      </div>

      <div className="panel assessment-panel">
        <span className="eyebrow">
          ASSESSMENT
        </span>

        {result ? (
          <>
            <div className="assessment-topline">
              <p
                className={
                  "verdict-badge " +
                  getRiskClass(
                    result.verdict
                  )
                }
              >
                {result.verdict}
              </p>

              <span className="confidence-pill">
                {result.confidence}% confidence
              </span>
            </div>

            <p className="assessment-reasoning">
              {result.reasoning}
            </p>

            {result.insufficient_evidence && (
              <p className="warning-text">
                Evidence is insufficient for a
                definitive conclusion.
              </p>
            )}

            {result.persistence?.status ===
              "unavailable" && (
              <p className="warning-text">
                {result.persistence.message}
              </p>
            )}

            <button
              className="challenge-button"
              onClick={onChallenge}
              disabled={
                challengeLoading ||
                !result.investigation_id
              }
            >
              {challengeLoading
                ? "Challenging Conclusion..."
                : "Challenge Conclusion"}
            </button>
          </>
        ) : (
          <p className="empty-state">
            No investigation has been run yet.
          </p>
        )}
      </div>
    </section>
  );
}

export default AssessmentCard;
