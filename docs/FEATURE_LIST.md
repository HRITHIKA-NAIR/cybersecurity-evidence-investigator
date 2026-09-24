# Feature list

Version 2.3 · priority split

## Must have for the website MVP

1. Public overview that explains capabilities and limitations.
2. Four evidence categories: links and websites, emails, files and QR codes, texts and messages.
3. URL, content, file type, empty-file and 10 MiB upload validation.
4. Processing acknowledgement and authorization statement.
5. Supabase email/password signup, confirmation, login, reset, update and global sign-out.
6. FastAPI bearer verification with confirmed-email and anonymous-user checks.
7. PostgreSQL cases, artifacts, evidence, findings, attack-chain stages, email metadata, redirects, reviews and budgets.
8. RLS and least-privilege roles so each user accesses only their cases.
9. Static parsers and evidence-backed findings.
10. Optional AI and reputation integrations disabled by default.
11. Result sections: Overview, Supporting evidence, Technical details and What to do next.
12. Owner-only conclusion review.
13. History for 100 recent loaded cases, search and confirmed deletion.
14. Offline, slow, loading, error, empty, no-result, denied, expired-session, validation and success states.
15. Light/dark mode, skip link, focus management, keyboard use and reduced motion.
16. Public user guide, privacy, terms, acceptable use, copyright and data deletion.
17. Preview noindex mode, canonical metadata, robots and sitemap generation.
18. Free deployment blueprint, readiness, diagnostics, CI and authenticated smoke test.

## Nice to have after the website is stable

1. Self-service account deletion and verified export.
2. Isolated parser workers and a durable job queue.
3. Shared edge rate limiting.
4. Calibrated scores and detector feedback.
5. Redacted evidence export and audit trail.
6. Retention automation and operator deletion console.
7. Custom-domain and email deliverability onboarding.
8. Consent-based, evidence-free product analytics.
9. Native mobile app using the same API and design system.
10. Paid providers only after legal, privacy, regional and cost review.
11. Organization workspaces with a separate authorization model.

## Out of scope for v2.3

Endpoint cleaning, live malware execution, account takeover recovery, payment reversal, guaranteed verdicts, child-directed experiences, physical shipping, advertising, countdowns, dark patterns, hidden session recording and direct browser-to-Postgres access.

## Continuation refinements

Automatic case previews and on-demand full detail, collapsible mobile navigation with recovery, shared category metadata, validated drag and drop, stronger theme contrast, private-state clearing after 401, pre-bundle credential checks, emitted-bundle scanning, a production role readiness gate and a dry-run-first account-data cleanup script are implemented. These do not remove the live Auth/database/SMTP gates.
