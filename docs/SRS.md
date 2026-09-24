# Software requirements specification

This specification defines observable behavior for the website release. P0 requirements are release blockers. Requirements marked as operator gates depend on configured external services and must be verified in the deployed environment.

## Functional requirements

| ID | Requirement | Acceptance criterion |
| --- | --- | --- |
| FR01 | Public orientation and recovery | Visitors can understand capabilities and open guidance without login |
| FR02 | Four evidence categories | Link, email, file and message forms provide relevant labels and input rules |
| FR03 | Account creation and confirmation | Email signup requires terms and adult declaration; confirmation precedes investigation |
| FR04 | Login and recovery | Password login, generic reset messaging, password update and global sign-out work |
| FR05 | Text submission | Non-whitespace content up to 100000 characters is accepted; oversized input is rejected |
| FR06 | File submission | Supported non-empty files up to 10 MiB are bounded and parsed without execution |
| FR07 | Processing notice | A user explicitly acknowledges authority and configured processing before UI submission |
| FR08 | Investigation output | Findings preserve supporting evidence and meaningful uncertainty |
| FR09 | Result sections | Overview, evidence, technical detail and recovery are separately navigable |
| FR10 | Conclusion review | Only the owner can request a re-review of a persisted case |
| FR11 | Private history | An authenticated owner automatically loads their latest 100 case previews, searches them and fetches a selected case in full |
| FR12 | Case deletion | Confirmed deletion removes the case and dependent active-storage rows |
| FR13 | Theme preference | Light/dark switch persists where browser storage is available |
| FR14 | Service states | Loading, slow, offline, error, expired session, denied access, validation and success have feedback |
| FR15 | Policy access | Privacy, terms, acceptable use, copyright and data deletion pages are public |
| FR16 | Account deletion | Published contact and verified manual operator procedure are available at launch |

FR07 is an interface acknowledgement. It does not replace a legal basis, provider eligibility review or documented processor agreements. The public API still treats all authenticated submitted content as untrusted evidence.

## Security and privacy requirements

| ID | Requirement | Verification |
| --- | --- | --- |
| SEC01 | Server verifies Supabase bearer identity and confirmed email | Missing, invalid, expired, anonymous and unconfirmed sessions rejected |
| SEC02 | Identity comes from verified token, never a request owner field | Two-account direct API tests |
| SEC03 | Every application table has RLS | Schema and policy catalog checks; role-based SQL regression |
| SEC04 | User-owned rows and children are isolated | Cross-user SELECT, INSERT, UPDATE, DELETE and review attempts fail |
| SEC05 | Browser roles cannot query private application tables | Anonymous and authenticated database role tests |
| SEC06 | Secrets remain server-side | Build configuration guard and source/bundle scans |
| SEC07 | All API routes are throttled | Process-local IP window; durable per-user and global expensive-request budgets |
| SEC08 | Inputs and concurrency are bounded | Text/body/upload/archive/redirect limits and two analysis slots per worker |
| SEC09 | Outbound URL checks resist SSRF | Existing private-address, DNS and redirect regression suite |
| SEC10 | Evidence is not executed or rendered as HTML | Static parser review and React escaped output |
| SEC11 | Logs avoid raw evidence and provider exception text | Log review and synthetic outage checks |
| SEC12 | Cases can be deleted | Cascade verification and manual account deletion process |

usage_budgets is a service-only operational table with a separate role, not a user-readable dataset. RLS protects user tables through evidence_app; database administrators and managed service administrators retain administrative powers.

## Quality and operational requirements

The app should support current desktop and mobile browsers, narrow viewports and keyboard use. Aim for WCAG 2.2 AA; do not claim conformance until manual and assistive-technology testing is complete. Respect reduced motion. Do not add nonessential tracking to measure this target.

A database outage must pause new expensive API work rather than allow unlimited unsaved requests. A failure after analysis may return collected results with an explicit persistence-unavailable message. Do not label these results saved. Provider failure must not become a Low Risk assertion.

The client gives requests up to 180 seconds and shows a slow-service notice after 15 seconds. A client timeout cannot guarantee the server stopped; do not automatically retry a potentially completed investigation. Free hosting introduces unpredictable cold starts, so there is no latency or uptime promise.

Public pages need accurate titles, descriptions, canonical URLs and a sitemap built from the final domain. Preview builds must remain noindex. Private case content must never be placed in a sitemap or public page.

## External dependencies and release gates

A reachable PostgreSQL project, applied schema, restricted runtime login, Supabase Auth configuration, tested custom SMTP, provider eligibility decisions, operator identity/contact, live HTTPS hosting and passing production smoke tests are mandatory release inputs. Search Console verification and sitemap submission are owner actions; neither is proven by the existence of local files.
