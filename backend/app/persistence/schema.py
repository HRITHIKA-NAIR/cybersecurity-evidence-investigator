SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS investigations (
        id BIGSERIAL PRIMARY KEY,
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
]

# Existing unowned records are quarantined: never attach them to the next person who signs in.
SCHEMA_STATEMENTS += [
    "ALTER TABLE investigations ADD COLUMN IF NOT EXISTS owner_id UUID",
    "CREATE INDEX IF NOT EXISTS idx_investigations_owner ON investigations (owner_id, created_at DESC)",
    "CREATE TABLE IF NOT EXISTS usage_budgets (bucket TEXT PRIMARY KEY, used INTEGER NOT NULL DEFAULT 0)",
]
PRIVATE_TABLES = (
    "investigations", "artifacts", "evidence_items", "attack_findings",
    "finding_evidence", "attack_chain_stages", "email_metadata", "redirect_hops",
    "challenge_results", "usage_budgets",
)
for table in PRIVATE_TABLES:
    SCHEMA_STATEMENTS += [
        f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY",
        f"REVOKE ALL ON public.{table} FROM PUBLIC",
        f"""DO $$ BEGIN
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN
            REVOKE ALL ON public.{table} FROM anon;
        END IF;
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticated') THEN
            REVOKE ALL ON public.{table} FROM authenticated;
        END IF;
        END $$""",
    ]

SCHEMA_STATEMENTS += ["""
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'evidence_app') THEN
    CREATE ROLE evidence_app NOLOGIN NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'evidence_budget') THEN
    CREATE ROLE evidence_budget NOLOGIN NOBYPASSRLS;
  END IF;
  EXECUTE format('GRANT evidence_app, evidence_budget TO %I', current_user);
END $$
""", "GRANT USAGE ON SCHEMA public TO evidence_app, evidence_budget"]
OWNER = "owner_id = NULLIF(current_setting('app.user_id', true), '')::uuid"
for table in PRIVATE_TABLES:
    if table == "usage_budgets":
        role, predicate = "evidence_budget", "true"
    elif table == "investigations":
        role, predicate = "evidence_app", OWNER
    elif table == "finding_evidence":
        role = "evidence_app"
        predicate = """EXISTS (SELECT 1 FROM attack_findings f JOIN evidence_items e
          ON e.investigation_id = f.investigation_id
          WHERE f.id = finding_evidence.finding_id AND e.id = finding_evidence.evidence_item_id)"""
    else:
        role = "evidence_app"
        predicate = f"EXISTS (SELECT 1 FROM investigations i WHERE i.id = {table}.investigation_id)"
    SCHEMA_STATEMENTS += [
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.{table} TO {role}",
        f"DROP POLICY IF EXISTS evidence_owner_access ON public.{table}",
        f"CREATE POLICY evidence_owner_access ON public.{table} FOR ALL TO {role} USING ({predicate}) WITH CHECK ({predicate})",
    ]
for table in ("investigations", "artifacts", "evidence_items", "attack_findings", "attack_chain_stages", "redirect_hops"):
    SCHEMA_STATEMENTS.append(f"GRANT USAGE, SELECT ON SEQUENCE public.{table}_id_seq TO evidence_app")
