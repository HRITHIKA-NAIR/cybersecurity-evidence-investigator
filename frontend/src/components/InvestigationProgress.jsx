const STAGES = [
  { key: "validate", label: "Validate input" },
  { key: "parse", label: "Parse artifact" },
  { key: "extract", label: "Extract evidence" },
  { key: "enrich", label: "Enrich intelligence" },
  { key: "classify", label: "Classify attacks" },
  { key: "reason", label: "Reason over evidence" },
];

function statusForStage({
  stage,
  loading,
  result,
  hasFile,
}) {
  if (
    stage.key === "parse" &&
    !hasFile
  ) {
    return "na";
  }

  if (result) {
    if (
      stage.key === "reason" &&
      result.stages?.calculate_assessment === false
    ) {
      return "limited";
    }

    return "done";
  }

  if (loading) {
    return "active";
  }

  return "pending";
}

function InvestigationProgress({
  loading,
  result,
  hasFile,
}) {
  const stateClass = loading
    ? "progress-active"
    : result
      ? "progress-complete"
      : "";

  return (
    <section className="panel progress-panel">
      <div className="panel-heading-row">
        <div>
          <h2>Investigation Progress</h2>
          <p className="panel-subtitle">
            Processing is bounded and evidence-first.
            Runtime execution of uploaded artifacts is
            not performed.
          </p>
        </div>

        <span
          className={
            "progress-state " + stateClass
          }
        >
          {loading
            ? "PROCESSING"
            : result
              ? "COMPLETE"
              : "READY"}
        </span>
      </div>

      <div className="stage-grid">
        {STAGES.map((stage) => {
          const status = statusForStage({
            stage,
            loading,
            result,
            hasFile,
          });

          const icon =
            status === "done"
              ? "✓"
              : status === "na"
                ? "—"
                : status === "limited"
                  ? "!"
                  : status === "active"
                    ? "…"
                    : "○";

          return (
            <div
              className={
                "stage-item stage-" +
                status
              }
              key={stage.key}
            >
              <span className="stage-icon">
                {icon}
              </span>
              <span>{stage.label}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}

export default InvestigationProgress;
