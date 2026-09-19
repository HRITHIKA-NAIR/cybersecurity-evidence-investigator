import { getRiskClass } from "../utils/risk";

function CaseSummary({
  result,
  challengeResult,
}) {
  if (!result) {
    return null;
  }

  return (
    <section className="case-summary">
      <div>
        <span>CASE</span>
        <strong>#{result.investigation_id}</strong>
      </div>

      <div>
        <span>VERDICT</span>
        <strong
          className={getRiskClass(
            result.verdict
          )}
        >
          {result.verdict}
        </strong>
      </div>

      <div>
        <span>SCORE</span>
        <strong>
          {result.threat_score}/100
        </strong>
      </div>

      <div>
        <span>CONFIDENCE</span>
        <strong>{result.confidence}%</strong>
      </div>

      <div>
        <span>FINDINGS</span>
        <strong>
          {result.attack_findings?.length || 0}
        </strong>
      </div>

      <div>
        <span>CHALLENGE</span>
        <strong>
          {challengeResult
            ? "Reviewed"
            : "Not run"}
        </strong>
      </div>
    </section>
  );
}

export default CaseSummary;
