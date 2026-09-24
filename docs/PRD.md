# Product requirements document

EVIDENCE is a website for understanding suspicious digital content and selecting a safer next step. This release reorganizes the existing investigator into a usable workspace and adds private accounts, ownership controls and release documentation. The release remains gated on live database, authentication, deployed-browser and deployment checks.

## Users and jobs

| User | Immediate need | Product response |
| --- | --- | --- |
| Less technical adult | Is this message or link suspicious and what should I do? | Input-specific form, plain-language overview and recovery guidance |
| Individual already affected | Contain an account, device or payment incident | Public situation selector with prioritized recovery steps |
| Authorized analyst | Inspect observations and challenge assumptions | Supporting evidence, technical details and re-review |
| Operator or developer | Run and maintain a small beta safely | Restricted database roles, quotas, diagnostic scripts and release runbook |

The adult beta scope does not establish legal compliance. Check provider age and regional restrictions before enabling an integration.

## Scope and priorities

P0 is a working private investigation flow: choose a category, submit authorized evidence, understand findings, revisit the case and delete it. P0 also covers verified authentication, database ownership isolation, bounded requests and clear failure states. P1 is discoverable public guidance, polished motion, theme controls and explainable recovery suggestions. Account deletion through verified operator support is documented; self-service account deletion is a later feature.

The investigation categories are Links and websites, Emails, Files and QR codes, and Texts and messages. Phishing is a possible finding across several input types. Giving it a separate input category would force users to diagnose a threat before investigating it.

## Main journeys

A visitor can explore capabilities and read recovery guidance without an account. An adult user creates an account, confirms their email, chooses an evidence category and reads the processing notice. On submission the interface shows an indeterminate shield animation. Results open in a dedicated workspace with Overview, Supporting evidence, Technical details and What to do next sections.

A returning user opens My investigations, automatically loads previews of the latest 100 cases, searches those previews and opens a case. Deletion requires a confirmation explaining that active-storage deletion cannot be undone. An affected user chooses what actually happened before following recovery guidance; a detected indicator alone does not establish a compromise.

## Included capabilities and boundaries

The existing engine parses supported text, email, documents, archives, scripts, links and images using bounded static inspection. It extracts indicators, collects permitted public URL observations, produces deterministic findings and stores evidence relationships. Optional Gemini assessment and VirusTotal reputation lookups require explicit operator configuration and provider eligibility review.

Uploaded artifacts are not executed. The product does not disinfect devices, perform live endpoint monitoring, recover accounts, reverse payments or offer a guarantee of safety. Scores are generated assessments, not calibrated probabilities. Inconclusive is a useful result when evidence is missing or a provider is disabled.

## Release acceptance

| Requirement | Acceptance evidence |
| --- | --- |
| Private cases | User A cannot list, read, change, review or delete user B's case |
| Clear navigation | Each input type is reachable from overview and navigation; results are split into sections |
| Honest service states | Offline, slow, empty, error, expired-session, validation and success states have actionable wording |
| Responsible processing | Notice precedes submission; optional processors default off; secret keys stay on the API |
| Accessibility | Keyboard completion, focus restoration, 200 percent zoom, reduced motion and both themes pass manual review |
| Deployability | Live readiness passes, SMTP confirmation works, two-account smoke test passes and rollback is documented |

## Success measures and future scope

In a supervised beta, target four of five adult testers choosing a category, finding next steps and understanding inconclusive results without assistance. Record consented observations without session replay or submitted evidence.

Future work includes verified exports, administrative deletion, job queues, isolated parsers and retention automation. Public launch requires the runbook gates to pass.
