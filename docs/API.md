# API Reference

The FastAPI service exposes OpenAPI documentation automatically at `/docs`.

## GET /health

Readiness endpoint. A successful response requires PostgreSQL connectivity.

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

Maximum upload size: 10 MB.

The response contains the same overall investigation structure plus relevant `file_info`, `file_analysis` and/or `email_analysis`.

Files are not executed.

## GET /investigations

Returns the latest ten persisted investigations, including structured V2 evidence required by the History UI.

## GET /investigations/{id}

Returns one persisted investigation with related artifact metadata, evidence items, attack findings, attack chain, email intelligence and challenge result where available.

Returns HTTP 404 if the ID does not exist.

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

Depending on the evidence:

- domains, public IP addresses and SHA-256 hashes may be queried through VirusTotal
- public HTTP(S) URLs may be contacted for bounded redirect checks
- extracted content/evidence may be supplied to Gemini

The backend does not perform active vulnerability exploitation or arbitrary port scanning.
