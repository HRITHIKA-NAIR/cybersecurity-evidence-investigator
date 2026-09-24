# Technical and test design document

This TDD covers implementation decisions and the tests that establish their behavior. The SDD describes the component structure; this document concentrates on contracts, failure handling and validation.

## Request and identity path

The browser obtains an access token through Supabase Auth and sends it in an Authorization Bearer header. FastAPI calls the configured Supabase user endpoint over HTTPS. It accepts only a valid UUID identity with a confirmed email and rejects anonymous users. It does not trust decoded unverified JWT claims or browser-supplied ownership.

For each user-data transaction, user_connection sets the evidence_app role and a transaction-local app.user_id value. The investigations policy compares owner_id with this value. Child-table policies require a visible parent, and finding-to-evidence links must refer to the same investigation. Pool reuse cannot preserve the transaction-local identity after commit or rollback.

A separate evidence_budget role can update operational usage counters. The production database login should be evidence_runtime with NOINHERIT and NOBYPASSRLS, with membership only in the required application roles. Migrations use a separate owner credential. Do not deploy the owner or Supabase service-role key into the browser.

## API contracts

| Route | Input | Expected response or behavior |
| --- | --- | --- |
| GET /live | None | 200 when the API process responds |
| GET /health | None | 200 only when database schema, policies and restricted-role queries work; otherwise 503 |
| POST /investigate | JSON content | Authenticated investigation result; maximum 100000 characters |
| POST /investigate-file | Multipart file | Authenticated static file investigation; 10 MiB file ceiling |
| POST /challenge | Positive investigation_id | Owner-only review; absent or foreign case returns 404 |
| GET /investigations | Bearer identity | summary=true returns 100 bounded owner previews; default remains full cases for compatibility |
| GET /investigations/{id} | Bearer identity and ID | Owner case or 404 without revealing another user's case |
| DELETE /investigations/{id} | Bearer identity and ID | Deleted status or 404; cascade removes related rows |

Errors use a detail message. Authentication failures return 401; unconfirmed/anonymous account rejection returns 403; oversized bodies return 413; validation typically returns 422; quotas return 429; unavailable dependencies or occupied analysis slots return 503. Production API documentation is disabled.

## Bounds and abuse controls

SecurityMiddleware bounds request bodies before multipart parsing. It enforces a 120-request, 60-second per-peer window in one worker with bounded counter memory. Trusted proxy configuration determines the actual peer identity; blindly trusting forwarded headers would permit spoofing. Shared clients can share an IP allowance.

Expensive routes also reserve an atomic daily global and per-owner budget in PostgreSQL, defaulting to 50 and 10 requests. A transaction rolls back the global increment if the user budget fails. Failed work can consume a reserved allowance; this protects provider cost. Database failure closes the gate. Two in-flight analysis slots per process protect the free worker from simultaneous parser loads.

The per-process IP limiter is not distributed DDoS protection. Before scaling replicas or admitting large public traffic, add a trusted edge limiter and a shared request store. Persisted daily budgets already span workers.

## External integrations and uncertainty

ENABLE_GEMINI and ENABLE_VIRUSTOTAL default to false even if a key is present. GEMINI_MODELS is an explicit allowlist; no implicit upgrade to a more expensive model is configured. Review provider terms, account quotas and data-processing eligibility before enabling either service.

Untrusted evidence is delimited as data in the assessment instructions. Parsed AI output is validated against typed result models. These steps reduce risk but do not prove resistance to every prompt injection or hallucination. Deterministic findings and uncertainty remain visible if AI fails.

## Test matrix

| Test group | Evidence and remaining gate |
| --- | --- |
| Parser and detector regression | Existing pytest suite covers archives, documents, email, QR, indicators, findings and abstention |
| Auth and HTTP boundary | New tests cover all private routes, body ceilings, CORS, headers and Supabase rejection cases |
| RLS SQL behavior | Embedded PostgreSQL passes positive own-user and negative cross-user/browser-role cases |
| Real PostgreSQL adapter | Opt-in pytest test updated for ownership; PostgreSQL 16 CI must execute it |
| Frontend build | ESLint and production build pass; npm production audit reports no known vulnerabilities |
| Browser journeys | Mocked browser journeys and automated WCAG checks pass; real auth, device and screen-reader checks remain required |
| Production smoke | Script covers readiness, login requirement, text/file, history, review and cleanup using a disposable account |
| Cross-account deployment | Two separate confirmed test accounts must verify foreign-case denial through API and browser |

No authentic Supabase end-to-end or production test has been completed in this workspace. An embedded SQL test validates PostgreSQL policy behavior, not the deployed pooler, permissions, SMTP or network configuration.

## Continuation security checks

The frontend checks public configuration before Vite transforms source, allowing only the three documented VITE variables. It rejects privileged Supabase keys and URL credentials. After building, it checks emitted text for configured backend secret values and common credential forms. Four Node tests cover these boundaries. Build-generated dependency notices retain the available production package licences.

The history summary SQL returns at most 160 content characters plus case metadata, with the same owner filter and RLS context as full reads. The compatibility full-list endpoint remains authenticated. Browser checks verify automatic fetch, selection, deletion failure and success, and stale-session cleanup. Production readiness additionally rejects an overprivileged login; live verification of this gate remains mandatory.
