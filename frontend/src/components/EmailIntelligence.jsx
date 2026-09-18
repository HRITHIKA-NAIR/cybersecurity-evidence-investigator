function EmailIntelligence({ analysis }) {
  if (!analysis) {
    return null;
  }

  const routing = analysis.routing_intelligence;
  const networkDetails =
    routing?.status === "success"
      ? [
          routing.as_owner,
          routing.asn ? `AS${routing.asn}` : null,
          routing.network,
        ]
          .filter(Boolean)
          .join(" · ") || "Not available"
      : "Not available";

  return (
    <section className="panel email-panel">
      <div className="email-heading">
        <div>
          <h2>Email Intelligence</h2>
          <p className="email-note">
            Header-derived evidence only. Claimed identity
            is not verified, and routing geography describes
            mail infrastructure rather than a person&apos;s
            physical location.
          </p>
        </div>
      </div>

      <div className="email-grid">
        <div className="email-field">
          <span>Claimed Sender</span>
          <strong>
            {analysis.claimed_sender_name ||
              "Not available"}
          </strong>
        </div>

        <div className="email-field">
          <span>Sender Address</span>
          <strong>
            {analysis.sender_address ||
              "Not available"}
          </strong>
        </div>

        <div className="email-field">
          <span>Sender Domain</span>
          <strong>
            {analysis.sender_domain ||
              "Not available"}
          </strong>
        </div>

        <div className="email-field">
          <span>Reply-To</span>
          <strong>
            {analysis.reply_to ||
              "Not available"}
          </strong>
        </div>

        <div className="email-field">
          <span>Return-Path</span>
          <strong>
            {analysis.return_path ||
              "Not available"}
          </strong>
        </div>

        <div className="email-field">
          <span>Subject</span>
          <strong>
            {analysis.subject ||
              "Not available"}
          </strong>
        </div>

        <div className="email-field">
          <span>Message-ID</span>
          <strong>
            {analysis.message_id ||
              "Not available"}
          </strong>
        </div>

        <div className="email-field">
          <span>Claimed Send Time</span>
          <strong>
            {analysis.claimed_send_time ||
              "Not available"}
          </strong>
        </div>

        <div className="email-field">
          <span>Earliest Received Time</span>
          <strong>
            {analysis.earliest_received_time ||
              "Not available"}
          </strong>
        </div>

        <div className="email-field">
          <span>Originating Routing IP</span>
          <strong>
            {analysis.originating_ip ||
              "Not available"}
          </strong>
        </div>

        <div className="email-field">
          <span>Likely Routing Country</span>
          <strong>
            {routing?.status === "success"
              ? routing.country || "Not available"
              : "Not available"}
          </strong>
        </div>

        <div className="email-field">
          <span>Network / ASN</span>
          <strong>{networkDetails}</strong>
        </div>
      </div>

      <div className="email-auth">
        {["spf", "dkim", "dmarc"].map(
          (mechanism) => (
            <span key={mechanism}>
              {mechanism.toUpperCase()}:{" "}
              <strong>
                {analysis.authentication?.[
                  mechanism
                ] || "not_reported"}
              </strong>
            </span>
          )
        )}
      </div>

      <p className="email-auth-note">
        SPF, DKIM, and DMARC values above are reported
        by the uploaded message headers; they are not
        independently re-verified yet.
      </p>

      {analysis.warnings?.length > 0 && (
        <div className="email-warnings">
          <h3>Header Indicators</h3>
          <ul>
            {analysis.warnings.map(
              (warning, index) => (
                <li key={index}>{warning}</li>
              )
            )}
          </ul>
        </div>
      )}

      {analysis.attachments?.length > 0 && (
        <div className="email-warnings">
          <h3>Attachments</h3>
          <ul>
            {analysis.attachments.map(
              (attachment, index) => (
                <li key={index}>
                  {attachment.filename ||
                    "Unnamed attachment"}{" "}
                  · {attachment.content_type} ·{" "}
                  {attachment.size_bytes} bytes
                </li>
              )
            )}
          </ul>
        </div>
      )}
    </section>
  );
}

export default EmailIntelligence;
