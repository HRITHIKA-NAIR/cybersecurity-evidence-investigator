import {
  buildEvidenceIndex,
  evidenceLabel,
} from "../utils/evidence";

function AttackChain({
  stages = [],
  evidenceItems = [],
}) {
  if (!stages.length) {
    return null;
  }

  const evidenceIndex =
    buildEvidenceIndex(evidenceItems);

  return (
    <section className="panel">
      <h2>Attack Chain</h2>
      <p className="panel-subtitle">
        Only stages supported by collected evidence
        are shown. Missing stages are not inferred.
      </p>

      <div className="attack-chain">
        {stages.map((stage) => (
          <div
            className="chain-stage"
            key={
              stage.order +
              "-" +
              stage.stage
            }
          >
            <div className="chain-order">
              {stage.order}
            </div>

            <div className="chain-body">
              <span className="chain-stage-name">
                {stage.stage}
              </span>
              <strong>{stage.value}</strong>
              <span className="chain-confidence">
                {stage.confidence}% confidence
              </span>

              <details>
                <summary>
                  Evidence references
                </summary>
                <ul>
                  {stage.evidence_ids.map(
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
              </details>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

export default AttackChain;
