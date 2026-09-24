# App charter

Version 2.3

## Name

EVIDENCE — Cybersecurity Evidence Investigator

## Use

EVIDENCE helps adults inspect suspicious links, emails, files, QR images and messages, understand observable warning signs and choose a safer next step. It is an evidence-organizing aid that supports human judgment.

## Scope

The first product is a website with a React frontend, FastAPI API, Supabase Auth and PostgreSQL. It accepts bounded evidence, performs static parsing and deterministic checks, presents observations and can optionally request eligible external assessment or reputation lookups. It does not execute uploads, clean devices, recover accounts, reverse transactions or guarantee safety.

The website is first because it is faster to test, easier to update and establishes the API and design-system foundation. A mobile app is a later client, not a second product definition.

## Users

Primary users are adults who received a suspicious message, link, email or attachment. Secondary users are authorized analysts and operators/developers. The product is not designed or marketed as child-directed; provider and regional age requirements must be reviewed before launch.

## Promise and roadmap

Clarity before action. EVIDENCE explains what was observed, what is unknown and what a person can do next. Website v2.3 includes public education, private accounts, category investigation, explainable results, recovery guidance, deletion and launch controls. Mobile v3+ reuses the API, authentication contract, tokenized design system and recovery content, then adds mobile-specific upload, share-sheet and offline-read features.

## Owner decisions required

Choose and publish the operator name and monitored support address. Confirm target country and audience. Create or connect the Supabase project and configure custom SMTP. Decide whether Gemini and VirusTotal are eligible and whether paid plans are required. Select the production domain. These inputs cannot be safely invented by implementation.
