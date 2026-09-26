function formatCreatedAt(value) {
  if (!value) {
    return "Unknown time";
  }

  const hasTimezone =
    /(?:Z|[+-]\d{2}:\d{2})$/i.test(
      value
    );
  const date = new Date(
    hasTimezone ? value : value + "Z"
  );

  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString();
}

function HistoryDrawer({
  history,
  onClose,
  onSelect,
}) {
  return (
    <>
      <div
        className="history-backdrop"
        onClick={onClose}
      />

      <aside className="history-sidebar">
        <div className="history-sidebar-header">
          <div className="history-sidebar-title">
            <svg
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path
                d="M12 8v5l3 2M3.05 11a9 9 0 1 0 2.64-5.36L3 8M3 3v5h5"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <span>HISTORY</span>
          </div>

          <button
            className="history-close"
            onClick={onClose}
            aria-label="Close history"
          >
            ×
          </button>
        </div>

        <div className="history-list">
          {history.length > 0 ? (
            history.map((item) => {
              const preview =
                item.content ||
                "No extractable text was stored.";

              return (
                <button
                  type="button"
                  className="history-item"
                  key={item.id}
                  onClick={() =>
                    onSelect(item)
                  }
                >
                  <div className="history-main">
                    <span className="history-id">
                      CASE #{item.id}
                    </span>

                    <span className="history-verdict">
                      {item.verdict}
                    </span>
                  </div>

                  <div className="history-details">
                    <span>
                      Score {item.threat_score}/100
                    </span>
                    <span>
                      Confidence {item.confidence}%
                    </span>
                  </div>

                  <div className="history-status">
                    {item.challenge_result
                      ? "Challenged"
                      : "Initial assessment"}
                  </div>

                  <div className="history-input">
                    {preview.length > 90
                      ? preview.slice(0, 90) + "..."
                      : preview}
                  </div>

                  <div className="history-date">
                    {formatCreatedAt(
                      item.created_at
                    )}
                  </div>
                </button>
              );
            })
          ) : (
            <p className="history-empty">
              No investigations stored yet.
            </p>
          )}
        </div>
      </aside>
    </>
  );
}

export default HistoryDrawer;
