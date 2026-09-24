# Project history and completion record

Version 2.3 · chronology from competition prototype to website launch plan

## 1. Competition prototype

The project began as a cybersecurity competition concept: turn suspicious content into an explainable investigation rather than a single opaque verdict. The original prototype focused on a single investigation surface and a SQLite-style persistence path. It proved the core parsing, indicator and assessment idea but made users choose from too much information at once.

## 2. Evidence engine growth

The backend evolved into bounded static inspection for text, URLs, email, documents, office files, archives, scripts, binaries and QR images. Deterministic detectors now create evidence items, findings and attack-chain stages. The design preserves uncertainty: no indicator is treated as proof of compromise, HTTPS is not proof of legitimacy, undetected reputation is not proof of safety and static inspection does not prove runtime behavior.

## 3. PostgreSQL architecture

The version-2 architecture replaced the original SQLite direction with PostgreSQL and normalized tables for investigations, artifacts, evidence items, attack findings, finding-to-evidence links, attack-chain stages, email metadata, redirect hops, challenge results and usage budgets. A persistence facade preserves existing service imports. Existing records without an owner are quarantined rather than assigned to the next account.

The runtime now uses a restricted non-inheriting role and transaction-local identity. RLS is enabled on every application table. Browser roles and direct public table access are revoked. A separate budget role can update service counters. The connection health endpoint is intentionally strict: it requires the schema, policies, restricted roles and queries to work.

## 4. Account and request security

Supabase Auth supplies the browser session. The API verifies the bearer token against the configured Supabase Auth user endpoint, requires a UUID and confirmed email, and rejects anonymous or invalid sessions. The client uses a publishable key as intended; server database, Gemini and VirusTotal secrets do not use a VITE prefix.

Request bodies are bounded before multipart parsing. Text, upload, archive, parser, redirect and connection limits are explicit. A bounded per-process request throttle, persistent global/user daily budgets and an in-flight analysis semaphore protect the free service. The application never trusts CORS as authorization, a browser owner ID or an unverified JWT claim.

## 5. UI/UX redesign

The product was reorganized into a workspace: Overview, My investigations, Links and websites, Emails, Files and QR codes, Texts and messages, and Already affected recovery guidance. Phishing is intentionally a finding across evidence types, not a separate user input category. Results are progressive: Overview, Supporting evidence, Technical details and What to do next.

The v2.3 interface uses a light/dark switch, native SVG shield illustration, Lucide icons, Motion transitions and a CSS shield loader that accelerates, decelerates, pauses and accelerates again. It includes skip links, focus management, responsive layouts, reduced-motion behavior and honest offline, slow, empty, error, denied, expired-session, no-result, validation and success states. Unused prior input, progress, history drawer and inactive style files were removed after the new components took over.

## 6. Public content and policy review

The website now has public user guidance, phishing education, privacy, terms, data deletion, acceptable use and copyright pages. A shipping policy is not included because the product sells no physical goods; adding one would be misleading. An unsubscribe flow is not included because there is no marketing subscription; if marketing email is later added, it needs separate opt-in and one-click unsubscribe. No session recording or analytics is enabled. There are no videos, so caption work is not applicable until video is introduced.

The adult-only beta position is documented. It is a product and provider eligibility requirement, not a complete legal assessment. Operator name, monitored contact, target country and final legal terms remain owner decisions.

## 7. Deployment and discoverability

The intended free deployment is a Render static site plus one free Python web service, with Supabase PostgreSQL/Auth remaining the data and identity layer. Free service sleep, quota, SMTP and provider restrictions are documented. Preview builds are noindex; launch builds require HTTPS site/API URLs, a support email, operator name and a production-ready flag. The build generates canonical metadata, robots.txt and sitemap.xml.

Google Search Console verification and sitemap submission are not automatic code actions. After publishing the final domain, the owner must verify domain ownership in Search Console, submit the generated sitemap, test canonical URLs and monitor indexing. Public pages target plain search language such as phishing checker, suspicious link analysis, email threat analysis and cybersecurity evidence; private cases never enter the sitemap.

## 8. What has been verified

The continuation backend suite passes 103 tests; the two skipped opt-in tests are live Gemini and live PostgreSQL. The embedded PostgreSQL regression passes idempotent schema, own-user isolation, cross-user read/write/delete denial, child isolation, browser-role denial and budget isolation. The frontend lint, build and production npm audit pass with zero reported vulnerabilities in the checked dependency tree.

A live Supabase project was not discoverable through the connected account during this work, so the live database, SMTP, two-user production test and deployed browser behavior remain release gates. Local Chromium checks now pass with synthetic sessions and mocked API responses. These checks cover interface behavior and representative automated accessibility, not real Supabase or deployed infrastructure. These are explicitly unverified, not silently marked complete.

## 9. Final handoff

Use feature/investigator-v2.2 as the source branch for v2.3 work, then create a reviewed v2.3 release tag or branch after the gates pass. Read the PRD, SRS, TDD, SDD, developer guide and launch checklist together. Do not enable external providers, index preview pages or invite public users until identity, database, contact, SMTP, deletion and smoke-test decisions are complete.

## Continuation audit

On 23 September 2026 a refreshed GitHub inventory confirmed four branches. The selected feature/investigator-v2.2 update stream was retained. The continuation fixes history loading and data minimization, mobile navigation and recovery access, contrast, stale-session handling, public build guards, early error headers and lazy pool synchronization. It removes inactive assets, adds mocked browser checks to CI and repairs the separate Word exporter. REPOSITORY_AUDIT.md records findings and limits; DEPLOYMENT.md gives the complete owner sequence. No external deployment, Search Console submission or live Supabase verification is claimed.
