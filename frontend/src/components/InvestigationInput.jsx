import UploadZone from "./UploadZone";

function InvestigationInput({
  content,
  file,
  supportedFiles,
  loading,
  error,
  onContentChange,
  onFileChange,
  onError,
  onSubmit,
  onOpenHistory,
}) {
  return (
    <section className="panel investigation-panel">
      <div className="panel-heading-row">
        <div>
          <h2>Investigate</h2>
          <p className="panel-subtitle">
            Submit suspicious text, a URL, an email
            message, or a supported artifact for
            evidence-first analysis.
          </p>
        </div>

        <button
          className="history-button"
          onClick={onOpenHistory}
        >
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
          HISTORY
        </button>
      </div>

      <UploadZone
        file={file}
        accept={supportedFiles}
        onFileChange={onFileChange}
        onError={onError}
      />

      <div className="divider">
        <span>OR</span>
      </div>

      <textarea
        value={content}
        onChange={(event) =>
          onContentChange(
            event.target.value
          )
        }
        placeholder="Paste a suspicious URL, email, or text..."
        rows="8"
        maxLength={100000}
        disabled={Boolean(file)}
      />

      {file && (
        <p className="input-hint">
          The selected file will be investigated.
          Remove it to investigate pasted text instead.
        </p>
      )}

      <p className="processing-notice">
        Extracted domains, public routing IPs, and
        SHA-256 file hashes may be checked with
        VirusTotal. Submitted URLs may be
        contacted by the backend for bounded redirect
        checks, and extracted content may be processed
        by Gemini. Raw uploaded files are not sent to
        VirusTotal. Avoid submitting sensitive or
        confidential information.
      </p>

      {error && (
        <p className="error">
          {error}
        </p>
      )}

      <button
        className="primary-button"
        onClick={onSubmit}
        disabled={loading}
      >
        {loading
          ? "Investigating..."
          : "Start Investigation"}
      </button>
    </section>
  );
}

export default InvestigationInput;
