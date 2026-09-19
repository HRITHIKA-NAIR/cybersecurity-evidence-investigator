import {
  formatValue,
} from "../utils/evidence";

function EvidencePanel({
  items = [],
}) {
  if (!items.length) {
    return null;
  }

  const groups = items.reduce(
    (accumulator, item) => {
      const key =
        item.source || "unknown";
      accumulator[key] =
        accumulator[key] || [];
      accumulator[key].push(item);
      return accumulator;
    },
    {}
  );

  return (
    <section className="panel">
      <h2>Exact Evidence</h2>
      <p className="panel-subtitle">
        Deterministic and external evidence grouped
        by source. Evidence IDs are used by findings
        and attack-chain stages.
      </p>

      <div className="evidence-groups">
        {Object.entries(groups).map(
          ([source, sourceItems]) => (
            <div
              className="evidence-group"
              key={source}
            >
              <h3>
                {source.replaceAll("_", " ")}
              </h3>

              <div className="evidence-list">
                {sourceItems.map((item) => (
                  <details
                    className="evidence-item"
                    key={item.id}
                  >
                    <summary>
                      <code>{item.id}</code>
                      <span>
                        {item.type.replaceAll(
                          "_",
                          " "
                        )}
                      </span>
                      <span className="evidence-confidence">
                        {Math.round(
                          item.confidence * 100
                        )}
                        %
                      </span>
                    </summary>

                    <pre>
                      {formatValue(item.value)}
                    </pre>
                  </details>
                ))}
              </div>
            </div>
          )
        )}
      </div>
    </section>
  );
}

export default EvidencePanel;
