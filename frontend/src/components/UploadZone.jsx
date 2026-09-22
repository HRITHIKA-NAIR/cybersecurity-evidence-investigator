const MAX_FILE_BYTES = 10 * 1024 * 1024;

function UploadZone({
  file,
  accept,
  onFileChange,
  onError,
}) {
  const validateAndSet = (candidate) => {
    if (!candidate) {
      return;
    }

    if (candidate.size > MAX_FILE_BYTES) {
      onError(
        "The selected file exceeds the 10 MB upload limit."
      );
      return;
    }

    onError("");
    onFileChange(candidate);
  };

  const handleDrop = (event) => {
    event.preventDefault();
    validateAndSet(
      event.dataTransfer.files?.[0]
    );
  };

  return (
    <div
      className="upload-zone"
      onDragOver={(event) =>
        event.preventDefault()
      }
      onDrop={handleDrop}
    >
      <div>
        <span className="upload-title">
          Upload suspicious file
        </span>

        <span className="upload-text">
          {file
            ? file.name
            : "Choose a file or drag it here"}
        </span>

        <span className="upload-formats">
          PDF · DOCX/DOCM · PPTX/PPTM · XLSX/XLSM ·
          EML · ZIP/7Z · HTML/SVG ·
          JS/PS1/VBS/BAT/CMD · LNK/ISO ·
          PNG/JPG/WEBP/GIF/BMP ·
          TXT/MD/CSV/JSON · max 10 MB
        </span>
      </div>

      <div className="upload-actions">
        <label className="secondary-button file-picker">
          Browse
          <input
            type="file"
            accept={accept}
            onChange={(event) =>
              validateAndSet(
                event.target.files?.[0]
              )
            }
          />
        </label>

        {file && (
          <button
            type="button"
            className="ghost-button"
            onClick={() =>
              onFileChange(null)
            }
          >
            Remove
          </button>
        )}
      </div>
    </div>
  );
}

export default UploadZone;
