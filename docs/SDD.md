# Software design document

EVIDENCE uses a three-layer design: a static React client, a Python API with investigation services, and a relational PostgreSQL store. Supabase Auth is the identity authority. External content and provider output cross explicit trust boundaries.

## Components and responsibilities

| Component | Responsibility | Excluded responsibility |
| --- | --- | --- |
| App and navigation | Public orientation, route state, auth events and request lifecycle | Parsing or direct database queries |
| InvestigationForm | Category input, basic validation and processing acknowledgement | Final security validation |
| CaseResults | Progressive presentation of assessment and evidence | Making new detector decisions |
| HistoryPage | Case selection, loaded-case search and deletion confirmation | Defining ownership |
| API service client | Bearer headers, HTTP errors, timeout and cancellation | Trusting a browser user ID |
| main and security modules | Request validation, identity, bounds and quotas | Provider-specific analysis |
| Investigation services | Coordinate parsers, evidence, findings, assessment and persistence | Executing uploaded content |
| Parsers and detectors | Static extraction and bounded indicators | Guaranteeing artifact safety |
| Persistence modules | Relational writes, reads, ownership role and schema | Authentication UI |
| Integrations | Optional provider request and normalized response | Unrestricted autonomous tools |

## Data model

investigations is the aggregate root. It stores the verified owner UUID, input type, extracted content, result summary, selected JSON data and timestamp. One investigation can have many artifacts, evidence_items, attack_findings, attack_chain_stages and redirect_hops. email_metadata and challenge_results contain at most one row per investigation.

finding_evidence links findings to evidence items. The RLS policy requires both ends to belong to the same visible investigation. The parent foreign keys cascade deletion. An owner-and-created_at index serves private history. Child investigation indexes support hydration and ownership checks.

JSON snapshots preserve response compatibility alongside normalized tables. Writes must update both in one transaction. Remove redundant snapshots only after migrating their readers and tests.

usage_budgets stores daily counters under service-only access. Existing rows without owner_id remain quarantined. Do not attach them to the next person who signs in. Legacy migration now requires an explicit verified owner for a single-owner SQLite source.

## Processing sequence

An authenticated request reserves budget and an analysis slot. The engine bounds and parses input, extracts indicators, obtains permitted URL observations, runs deterministic detectors, builds evidence relationships and optionally requests an assessment. It persists the result in one user-scoped transaction and returns a normalized response.

Review loads the case through the same ownership boundary, reuses collected evidence, validates the revised assessment and writes the latest review result. It does not fetch a new independent body of evidence. The workspace loads bounded history summaries first and fetches full related evidence only for a selected case. The backward-compatible full-list API still hydrates related tables in batches.

## Deployment topology and trust

A Render static site serves the compiled client. The browser calls Supabase Auth directly with a public project key and calls the API with its bearer token. Only the API holds the runtime PostgreSQL credential and optional provider secrets. PostgreSQL is hosted by Supabase; uploads are not stored on the ephemeral API disk as an archive.

The API may contact attacker-controlled public URLs. Existing SSRF controls resolve and constrain addresses and redirects. The application never intentionally contacts private addresses or executes a payload, but parser vulnerabilities remain a material risk. Process isolation and a durable job system are recommended before processing sensitive or high-volume evidence.

## Repository organization

frontend/src contains application components, services, styles and utilities. frontend/public contains public educational and policy pages; scripts prepare deployment metadata. backend/app separates security, parsers, detectors, integrations, services and persistence. backend/tests contains regressions; backend/scripts contains administrative utilities. docs is the maintained source documentation, and data contains evaluation fixtures/results.

Unused prior input, progress and history components and their inactive styles were removed during the redesign. Unused starter React/Vite assets and the superseded UploadZone were removed after checking references. Sidebar, Overview and category metadata now have dedicated modules. The database facade app/database.py preserves imports into the persistence package and is intentional. Exception classes and package initializers are not unfinished feature stubs.
