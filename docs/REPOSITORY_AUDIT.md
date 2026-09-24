# Repository audit and release status

EVIDENCE version 2.3 continuation, 23 September 2026. The implementation is ready for review on feature/investigator-v2.2. Public launch remains blocked on an accessible Supabase project, configured credentials, real account tests and operator launch settings. This report distinguishes source inspection, local checks and external actions.

## Branch inventory

Git fetch and the GitHub branch API agree on four remote branches. The branch API pagination was exhausted.

| Remote branch | Starting commit | Purpose and decision |
| --- | --- | --- |
| master | 8161b55 | Older application baseline; preserved |
| feature/investigator-v2 | 7aadc4a | Same baseline as the other feature branches; preserved |
| feature/investigator-v2-2 | 7aadc4a | Duplicate branch tip, not a duplicate running deployment; preserved |
| feature/investigator-v2.2 | 7aadc4a remotely at audit start | Selected update stream; local v2.3 documentation commits already existed |

There are two local branches, master and feature/investigator-v2.2. Local branches and their remote tracking references are not additional independent product versions. No branch was deleted or merged. The selected branch remains the source for this work and the Render blueprint.

## Architecture assessment

The separation of frontend, backend and database code is suitable for a small beta. React does presentation, FastAPI owns security and orchestration, parser and detector modules collect evidence, and persistence modules own PostgreSQL queries. The browser never queries investigation tables directly. app/database.py is an intentional compatibility facade.

No byte-identical nonempty source duplicates or empty files were found in backend/app and frontend/src. Package initializers and exception classes are valid Python structures, not incomplete features. Large modules remain in file parsing, SSRF, AI normalization and evidence collection; split them only when a focused change justifies it. JSON snapshots coexist with normalized evidence tables for response compatibility, so their transactional consistency remains important.

Removed inactive UploadZone, input/history styles and starter React/Vite assets after checking imports. Category metadata, Sidebar and Overview now have dedicated modules. Administrative scripts, tests and evaluation fixtures are kept separate from runtime code. The SQLite migration utility is retained only for an explicit legacy import; the active application uses PostgreSQL.

## Confirmed issues and changes

| Finding | Change | Verification |
| --- | --- | --- |
| History required an extra click and downloaded full evidence for every case | Automatic bounded summary list; full case loaded on selection | Browser journey and summary integration assertion |
| Mobile rail took excessive space and hid recovery | Collapsible labelled navigation with recovery entry | 320px and 390px checks |
| Result colour contrast inconsistent with light theme | Theme-aware severity and technical badges | Automated contrast checks on representative results |
| Session failure could leave an account panel rather than login | Clear private memory, invalidate pending results and show login after 401 | Mocked expired-session browser check |
| File picker lacked the available drag-and-drop interaction | Unified one-file validation for browse and drop | Browser input validation and code review |
| Frontend credential guard ran after bundling | Pre-bundle public-variable allow-list and output credential scan | Four configuration regressions, build and source review |
| Early request rejection lacked response security headers | Security headers now also wrap early 400/413/429 responses | HTTP regression |
| Request middleware retained arbitrary counts of small body messages | Bounded byte buffer replay | Existing request suite plus review |
| Lazy pool construction could race during a cold start | Serialized pool creation and shutdown | Backend regression and code review |
| Health could accept a privileged production login | Production readiness rejects superuser, RLS-bypass, inheriting or table-owning login | Readiness code review; live runtime check remains required |
| Documentation mentioned an absent administrative deletion script | Added dry-run-first cleanup with Auth-account-absence gate | CLI review; live owner operation remains unexecuted |
| Word exporter wrote literal newline escapes and missed headings | Repaired separate-document generator and rendered documents | DOCX visual review |

## Database evidence

No DATABASE_URL or populated environment files were configured in this checkout. The connected Supabase account returned an empty project list. This does not prove that a project does not exist under another account or organization. It means its schema, ownership and live health cannot be verified here.

The safe diagnostic reports missing or invalid DATABASE_URL. The public /health endpoint is intentionally strict. /live confirms a running process; /health additionally requires database tables, RLS, policies and restricted roles. A failing /health must not be converted to a false success response.

All ten application tables enable RLS. Nine case/evidence tables use owner-scoped evidence_app policies; usage_budgets uses a separate service role. Browser anon and authenticated grants are revoked. The publishable Supabase key is expected in the browser and does not grant private table access. Live catalog and two-account API checks remain mandatory.

## Verification record

The updated backend suite passes 103 tests. Two opt-in tests were skipped: live Gemini and live PostgreSQL. The embedded PostgreSQL test passes schema idempotency, own-row access, missing identity, cross-user read/insert/update/delete denial, child isolation and cascade, browser-role denial and budget separation.

Frontend configuration tests pass four checks. Lint, build and production dependency audit pass. Browser tests use synthetic sessions and stubbed API responses; they cover layouts, themes, focus, automated accessibility, offline, validation, automatic history, detailed case fetch, search, deletion failure/success, 403, 429, 401, loading, slow requests and reduced motion. They do not prove live Supabase behavior or full WCAG conformance.

The production entry JavaScript is about 110 kB gzip, plus a separately loaded result chunk of about 5 kB gzip. These are build measurements, not an end-user speed score. No live Lighthouse, real-device or assistive-technology certification is claimed.

## Remaining risks and owner gates

1. Configure and test the live project, custom SMTP, runtime database login and exact redirect/CORS origins.
2. Run the real two-account smoke test with synthetic data before inviting users.
3. Keep optional AI/reputation providers disabled until terms, data handling and budgets are approved.
4. Global sign-out revokes refresh sessions; already-issued access tokens may survive until expiry. Choose a short practical access-token lifetime and test it. Immediate session revocation enforcement is not implemented in the API.
5. Parsers are bounded but run inside the API process. Isolated workers and a queue remain a future hardening item for hostile/high-volume uploads.
6. Throttling is per worker. Keep one worker and configure a trusted proxy/edge limit before scaling. Daily analysis budgets are shared through PostgreSQL.
7. Define retention and test restoration. The current product stores cases until deletion; it has no automatic expiry job.
8. Finalize operator identity, monitored contact, applicable jurisdiction and legal terms. These pages reduce ambiguity; they cannot guarantee immunity from legal claims.
9. Deployment and Google Search Console submission are not completed or verified by local code changes.

## Policy and accessibility applicability

| Requested check | Decision for this website | Remaining owner action |
| --- | --- | --- |
| Data deletion page | Present; case deletion implemented; account cleanup is verified operator work | Publish contact and rehearse the procedure |
| Acceptable use | Present; authorized defensive use only | Confirm jurisdiction and enforcement contact |
| Privacy disclosure | Present at signup, submission and public notice | Confirm actual processors, regions and retention |
| DMCA notice | Copyright reporting channel present; no safe-harbor claim | Determine whether a formal US designated-agent program applies |
| Age verification | Adult declaration; no date of birth or identity upload | Assess target audience and country/provider rules before public launch |
| Shipping policy | Not applicable; no physical goods | Revisit only if physical fulfilment is introduced |
| Unsubscribe links | Not applicable; no marketing subscription | Add explicit opt-in and unsubscribe before marketing mail |
| Necessary data only | Email identity plus submitted evidence; no phone or payment profile | Confirm each optional provider’s necessity |
| Session recording | Not installed | Obtain a fresh privacy review before adding replay or analytics |
| Font licences | System fonts; no font files redistributed | Retain third-party icon/software notices |
| Accessibility and skip links | Implemented; representative automated checks pass | Complete screen-reader, device and zoom testing |
| Heading structure | One main heading per application view | Review new public pages and added components |
| Video captions | Not applicable; no videos | Caption and transcribe any future video |
| Countdowns and dark patterns | No sales timer, forced marketing or preselected consent | Keep deletion and cancellation honest |
| Rate limits | All API requests through middleware; costly routes also use durable quotas | Set Auth provider limits and trusted edge throttling |
| RLS | Ten application tables covered with appropriate user/service policies | Verify actual deployed table catalog and two users |
| Frontend secrets | Public-variable allow-list and bundle scan added | Rotate any credential that was exposed before this audit |
| Google Search Console | No verified submission | Owner verifies final property and submits sitemap |
| Titles and descriptions | Present; homepage title survives hydration | Check final rendered URLs and avoid ranking promises |

Relevant legal sources: UAE personal-data law overview https://u.ae/en/about-the-uae/digital-uae/data/data-protection-laws; US DMCA section 512 https://www.copyright.gov/512/; US COPPA guidance https://www.ftc.gov/business-guidance/resources/complying-coppa-frequently-asked-questions. The applicable regime depends on the operator, establishment, audience and processing. An 18+ declaration alone does not resolve that assessment. The current pages are product policy drafts awaiting the operator’s legal review.
