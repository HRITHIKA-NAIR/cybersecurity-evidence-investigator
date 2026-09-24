# API Reference

The FastAPI service exposes OpenAPI documentation at `/docs` in development. Production disables interactive API documentation. All investigation, history, deletion and challenge routes require `Authorization: Bearer <Supabase access token>` from a confirmed, non-anonymous account. Ownership comes from the verified identity, never a request field.

## GET /live

Returns `{"status":"running"}` when the API process can respond. This does not establish database readiness.

## GET /health

Readiness endpoint. A successful response requires PostgreSQL connectivity, the application schema, RLS policies and usable restricted roles. Production also rejects an overprivileged runtime login.

```json
{
  "status": "ok",
  "database": "ok"
}
```

If PostgreSQL is unavailable, the endpoint returns HTTP 503.

## POST /investigate

Investigates pasted text or URLs.

Request:

```json
{
  "content": "Urgent: verify your account at https://example.com"
}
```

The text payload is bounded to 100,000 characters.

Important response fields:

- `investigation_id`
- `persistence`
- `indicators`
- `url_analysis`
- `threat_intelligence`
- `evidence_items`
- `attack_findings`
- `attack_chain`
- `threat_score`
- `verdict`
- `confidence`
- `reasoning`
- `insufficient_evidence`

If PostgreSQL is temporarily unavailable, analysis may still complete with `investigation_id: null` and `persistence.status: "unavailable"`. Such an unsaved result cannot be challenged later because Challenge Conclusion is investigation-ID based.

## POST /investigate-file

Multipart upload endpoint.

Form field:

```text
file
```

Maximum upload size: 10 MiB (10,485,760 bytes). Empty and unsupported files are rejected.

The response contains the same overall investigation structure plus relevant `file_info`, `file_analysis` and/or `email_analysis`.

Files are not executed.

## GET /investigations

Returns up to 100 latest persisted investigations owned by the current user. The default full response remains available for compatibility.

The History UI calls `GET /investigations?summary=true`. Each summary contains `id`, `input_type`, `content_preview` (at most 160 characters), `threat_score`, `verdict` and `created_at`. Full evidence is fetched only when the user selects a case. Search currently filters these loaded summaries; it is not an unlimited database search.

## GET /investigations/{id}

Returns one persisted investigation with related artifact metadata, evidence items, attack findings, attack chain, email intelligence and challenge result where available.

Returns HTTP 404 if the ID does not exist or belongs to another user.

## DELETE /investigations/{id}

Deletes a case owned by the verified user and cascades its related evidence rows. Returns `{"status":"deleted"}` on success and HTTP 404 for absent or foreign cases. Database unavailability returns 503. Account deletion is a separate operator-assisted process documented on the data deletion page.

## POST /challenge

Request:

```json
{
  "investigation_id": 123
}
```

Runs the adversarial Challenge Conclusion review using the stored evidence for that investigation.

Typical fields:

- `revised_threat_score`
- `revised_verdict`
- `revised_confidence`
- `counter_evidence`
- `uncertainty`
- `reasoning`
- `conclusion_changed`
- `persistence`

If history cannot be read, the endpoint returns HTTP 503. If the AI review completes but saving the revised result fails, the review can still be returned with a persistence warning.

## External processing

Gemini and VirusTotal are disabled by default. If explicitly enabled after checking provider eligibility and privacy requirements, depending on the evidence:

- domains, public IP addresses and SHA-256 hashes may be queried through VirusTotal
- public HTTP(S) URLs may be contacted for bounded redirect checks
- extracted content/evidence may be supplied to Gemini

The backend does not perform active vulnerability exploitation or arbitrary port scanning.

## Failure and cost controls

Errors contain a `detail` message. Common statuses are 401 for invalid or expired sessions, 403 for ineligible accounts, 413 for oversized bodies, 422 for input validation, 429 for rate or daily-budget limits, and 503 for unavailable dependencies or occupied analysis capacity. Clients must not automatically retry paid analysis requests.

A bounded per-process IP throttle covers API requests. Expensive routes additionally reserve persistent global and per-user daily quotas before doing work; a database failure closes that gate. Because quota reservation happens before execution, failed attempts can consume allowance. The default single-worker deployment is required for the documented in-process concurrency and IP limits.
