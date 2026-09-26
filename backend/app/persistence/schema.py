SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS investigations (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
        legacy_source_id BIGINT UNIQUE,
        input_type TEXT NOT NULL,
        content TEXT NOT NULL,
        indicators JSONB NOT NULL DEFAULT '{}'::jsonb,
        url_analysis JSONB NOT NULL DEFAULT '[]'::jsonb,
        threat_intelligence JSONB NOT NULL DEFAULT '[]'::jsonb,
        file_analysis JSONB,
        threat_score SMALLINT NOT NULL CHECK (
            threat_score BETWEEN 0 AND 100
        ),
        verdict TEXT NOT NULL,
        confidence SMALLINT NOT NULL CHECK (
            confidence BETWEEN 0 AND 100
        ),
        reasoning TEXT NOT NULL,
        insufficient_evidence BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,
    # investigations.user_id is added as a migration step too, in case this
    # table already exists from before this column was introduced.
    """
    ALTER TABLE investigations
        ADD COLUMN IF NOT EXISTS user_id BIGINT REFERENCES users(id) ON DELETE CASCADE
    """,
    """
    CREATE TABLE IF NOT EXISTS artifacts (
        id BIGSERIAL PRIMARY KEY,
        investigation_id BIGINT NOT NULL
            REFERENCES investigations(id) ON DELETE CASCADE,
        artifact_key VARCHAR(64),
        filename TEXT,
        extension TEXT,
        declared_mime TEXT,
        detected_type TEXT,
        size_bytes BIGINT,
        sha256 VARCHAR(64),
        parser TEXT,
        characters_extracted INTEGER,
        truncated BOOLEAN NOT NULL DEFAULT FALSE,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        UNIQUE (investigation_id, artifact_key)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS evidence_items (
        id BIGSERIAL PRIMARY KEY,
        investigation_id BIGINT NOT NULL
            REFERENCES investigations(id) ON DELETE CASCADE,
        evidence_key VARCHAR(64) NOT NULL,
        type TEXT NOT NULL,
        source TEXT NOT NULL,
        value JSONB,
        confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
        artifact_ref TEXT,
        provenance JSONB NOT NULL DEFAULT '{}'::jsonb,
        UNIQUE (investigation_id, evidence_key)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS attack_findings (
        id BIGSERIAL PRIMARY KEY,
        investigation_id BIGINT NOT NULL
            REFERENCES investigations(id) ON DELETE CASCADE,
        attack_type TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        confidence SMALLINT NOT NULL CHECK (
            confidence BETWEEN 0 AND 100
        ),
        detector TEXT NOT NULL,
        limitations JSONB NOT NULL DEFAULT '[]'::jsonb
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS finding_evidence (
        finding_id BIGINT NOT NULL
            REFERENCES attack_findings(id) ON DELETE CASCADE,
        evidence_item_id BIGINT NOT NULL
            REFERENCES evidence_items(id) ON DELETE CASCADE,
        PRIMARY KEY (finding_id, evidence_item_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS attack_chain_stages (
        id BIGSERIAL PRIMARY KEY,
        investigation_id BIGINT NOT NULL
            REFERENCES investigations(id) ON DELETE CASCADE,
        stage_order INTEGER NOT NULL,
        stage TEXT NOT NULL,
        value TEXT NOT NULL,
        confidence SMALLINT NOT NULL CHECK (
            confidence BETWEEN 0 AND 100
        ),
        evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS email_metadata (
        investigation_id BIGINT PRIMARY KEY
            REFERENCES investigations(id) ON DELETE CASCADE,
        claimed_sender_name TEXT,
        sender_address TEXT,
        sender_domain TEXT,
        reply_to TEXT,
        return_path TEXT,
        subject TEXT,
        message_id TEXT,
        claimed_send_time TIMESTAMPTZ,
        earliest_received_time TIMESTAMPTZ,
        originating_ip TEXT,
        routing_country TEXT,
        routing_asn BIGINT,
        routing_owner TEXT,
        authentication JSONB NOT NULL DEFAULT '{}'::jsonb,
        warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
        attachments JSONB NOT NULL DEFAULT '[]'::jsonb,
        raw_metadata JSONB NOT NULL DEFAULT '{}'::jsonb
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS redirect_hops (
        id BIGSERIAL PRIMARY KEY,
        investigation_id BIGINT NOT NULL
            REFERENCES investigations(id) ON DELETE CASCADE,
        original_url TEXT NOT NULL,
        hop_order INTEGER NOT NULL,
        url TEXT NOT NULL,
        resolved_ips JSONB NOT NULL DEFAULT '[]'::jsonb,
        status_code INTEGER,
        method TEXT,
        blocked_reason TEXT,
        is_final BOOLEAN NOT NULL DEFAULT FALSE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS challenge_results (
        investigation_id BIGINT PRIMARY KEY
            REFERENCES investigations(id) ON DELETE CASCADE,
        revised_threat_score SMALLINT NOT NULL CHECK (
            revised_threat_score BETWEEN 0 AND 100
        ),
        revised_verdict TEXT NOT NULL,
        revised_confidence SMALLINT NOT NULL CHECK (
            revised_confidence BETWEEN 0 AND 100
        ),
        counter_evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
        uncertainty JSONB NOT NULL DEFAULT '[]'::jsonb,
        reasoning TEXT NOT NULL,
        conclusion_changed BOOLEAN NOT NULL DEFAULT FALSE,
        raw_result JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_investigations_created_at
        ON investigations (created_at DESC)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_artifacts_sha256
        ON artifacts (sha256)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_evidence_investigation
        ON evidence_items (investigation_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_findings_investigation
        ON attack_findings (investigation_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_chain_investigation
        ON attack_chain_stages (investigation_id, stage_order)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_redirect_investigation
        ON redirect_hops (investigation_id, hop_order)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_email_sender_domain
        ON email_metadata (sender_domain)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_investigations_user
        ON investigations (user_id)
    """,
    # --- Row Level Security -------------------------------------------
    # `investigations` is the only table with a real owner column
    # (user_id). Every other table is scoped transitively through it.
    # FORCE ROW LEVEL SECURITY matters here: without it, the role that
    # *owns* these tables (the app's own DATABASE_URL role, since it's
    # the one that ran this migration) would silently bypass RLS -
    # only non-owner roles would be restricted, which defeats the
    # purpose since the app itself connects as the owner.
    #
    # Policies read `app.current_user_id`, a per-transaction session
    # variable the backend sets via `SET LOCAL` at the start of every
    # request (see persistence/session.py). If it is ever left unset,
    # `current_setting(..., true)` returns NULL, every comparison
    # evaluates to NULL/false, and the policy denies access - i.e. this
    # fails closed, not open.
    """
    ALTER TABLE investigations ENABLE ROW LEVEL SECURITY
    """,
    """
    ALTER TABLE investigations FORCE ROW LEVEL SECURITY
    """,
    """
    DROP POLICY IF EXISTS investigations_owner_isolation ON investigations
    """,
    """
    CREATE POLICY investigations_owner_isolation ON investigations
        USING (user_id = current_setting('app.current_user_id', true)::bigint)
        WITH CHECK (user_id = current_setting('app.current_user_id', true)::bigint)
    """,
]

_CHILD_TABLE_POLICIES = [
    ("artifacts", "investigation_id"),
    ("evidence_items", "investigation_id"),
    ("attack_findings", "investigation_id"),
    ("attack_chain_stages", "investigation_id"),
    ("redirect_hops", "investigation_id"),
    ("email_metadata", "investigation_id"),
    ("challenge_results", "investigation_id"),
]

for _table, _fk_column in _CHILD_TABLE_POLICIES:
    SCHEMA_STATEMENTS.append(
        f"ALTER TABLE {_table} ENABLE ROW LEVEL SECURITY"
    )
    SCHEMA_STATEMENTS.append(
        f"ALTER TABLE {_table} FORCE ROW LEVEL SECURITY"
    )
    SCHEMA_STATEMENTS.append(
        f"DROP POLICY IF EXISTS {_table}_owner_isolation ON {_table}"
    )
    SCHEMA_STATEMENTS.append(
        f"""
        CREATE POLICY {_table}_owner_isolation ON {_table}
            USING (
                EXISTS (
                    SELECT 1 FROM investigations i
                    WHERE i.id = {_table}.{_fk_column}
                      AND i.user_id = current_setting('app.current_user_id', true)::bigint
                )
            )
            WITH CHECK (
                EXISTS (
                    SELECT 1 FROM investigations i
                    WHERE i.id = {_table}.{_fk_column}
                      AND i.user_id = current_setting('app.current_user_id', true)::bigint
                )
            )
        """
    )

# finding_evidence has no investigation_id column of its own - it links
# attack_findings to evidence_items - so its policy joins through
# attack_findings instead.
SCHEMA_STATEMENTS.extend(
    [
        "ALTER TABLE finding_evidence ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE finding_evidence FORCE ROW LEVEL SECURITY",
        "DROP POLICY IF EXISTS finding_evidence_owner_isolation ON finding_evidence",
        """
        CREATE POLICY finding_evidence_owner_isolation ON finding_evidence
            USING (
                EXISTS (
                    SELECT 1 FROM attack_findings f
                    JOIN investigations i ON i.id = f.investigation_id
                    WHERE f.id = finding_evidence.finding_id
                      AND i.user_id = current_setting('app.current_user_id', true)::bigint
                )
            )
            WITH CHECK (
                EXISTS (
                    SELECT 1 FROM attack_findings f
                    JOIN investigations i ON i.id = f.investigation_id
                    WHERE f.id = finding_evidence.finding_id
                      AND i.user_id = current_setting('app.current_user_id', true)::bigint
                )
            )
        """,
    ]
)
