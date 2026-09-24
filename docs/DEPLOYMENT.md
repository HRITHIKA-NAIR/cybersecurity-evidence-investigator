# Database testing and deployment runbook

Use this sequence for the EVIDENCE v2.3 website. The selected branch is feature/investigator-v2.2. A free beta can use Render static hosting, a single free Render API and Supabase Free PostgreSQL/Auth within their quotas. Public email signup needs an SMTP service; its free allowance and sender-domain requirements must be checked separately. A forever-free, always-on production service is not promised.

## Step 1 Install the development tools

On Windows, download Git from https://git-scm.com/downloads, Python 3.12 or 3.13 from https://www.python.org/downloads/ and Node 22 from https://nodejs.org/. During Python setup enable its PATH option. Open a new PowerShell window after installation.

```powershell
git --version
py --version
node --version
npm --version
git clone https://github.com/HRITHIKA-NAIR/cybersecurity-evidence-investigator.git
cd cybersecurity-evidence-investigator
git fetch origin
git switch feature/investigator-v2.2
Copy-Item .env.example backend/.env
Copy-Item frontend/.env.example frontend/.env
py -3.12 -m venv backend/.venv
backend/.venv/Scripts/python.exe -m pip install -r backend/requirements-dev.txt
```

If Python 3.13 is installed, replace py -3.12 with py -3.13. Existing checkouts should use git status first and preserve uncommitted work. Do not overwrite populated .env files. The explicit virtual-environment Python path avoids needing to change PowerShell execution policy.

## Step 2 Locate or create the correct Supabase project

Open https://supabase.com/dashboard and sign in with the account that owns this project. Check the organization selector before creating anything. The connected account exposed no projects during this audit, so confirm whether an existing project is in another organization or account. If none exists, create a project on the Free plan, choose the appropriate region, and save the database password securely.

Open the project and its Connect dialog. Choose the IPv4-compatible Session pooler for a long-lived Render backend and copy the actual connection URI. Do not guess the host or project reference. Encode reserved password characters correctly in a URI. Place this migration-owner URI in DATABASE_URL in backend/.env only. Never paste it into the chat or frontend settings.

Record the project HTTPS URL and publishable key from the dashboard. Set SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY in backend/.env, and VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY in frontend/.env. The publishable key is public by design. Never substitute a secret or service-role key.

## Step 3 Bootstrap and restrict the database

Run these commands from the repository root using the migration-owner connection:

```powershell
cd backend
.venv/Scripts/python.exe scripts/diagnose_database.py
.venv/Scripts/python.exe scripts/init_database.py
.venv/Scripts/python.exe scripts/provision_runtime.py
```

Before initialization the diagnostic may report that the schema is missing. That is expected for a new project. Initialization creates ten application tables, indexes, RLS and restricted roles. Provisioning prompts privately for a unique runtime password of at least 24 characters.

Replace backend/.env DATABASE_URL with a connection for evidence_runtime. For a Supabase shared pooler, the username includes the project reference, commonly evidence_runtime.PROJECT_REFERENCE. Confirm the actual custom-role connection format in Supabase rather than reusing the postgres password. Set APP_ENV=production and FRONTEND_ORIGIN=http://localhost:5173 for this restricted local test. Production mode prevents startup schema changes and activates the strict runtime-role health gate.

```powershell
.venv/Scripts/python.exe scripts/diagnose_database.py --readiness
.venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Open http://127.0.0.1:8001/live and http://127.0.0.1:8001/health in your browser. Both must return HTTP 200; health must report database ok. A 503 can mean missing configuration, a paused project, wrong password, DNS/IPv4 connectivity, absent schema/policies or an overprivileged/unusable runtime login. Keep the migration-owner credential outside the deployed API.

In Supabase Table Editor confirm investigations, artifacts, evidence_items, attack_findings, finding_evidence, attack_chain_stages, email_metadata, redirect_hops, challenge_results and usage_budgets exist. Run the dashboard Security Advisor. All application tables should have RLS; anon/authenticated browser roles should have no investigation-table grants. Supabase system schemas are managed by Supabase and are not replaced by this initializer.

## Step 4 Configure authentication and email

In Supabase Authentication enable email/password sign-in and email confirmation. Set the minimum password length to at least 12 in the provider settings; the browser constraint alone is not enforcement. Disable anonymous sign-ins. Configure the exact local redirect URL http://localhost:5173/ for testing; add the final HTTPS site URL before launch. Use a short practical JWT lifetime and test refresh behavior. Sign-out does not instantly invalidate all previously issued access tokens.

Open the Auth SMTP configuration. Choose an SMTP provider that supports a verified sender and whose free allowance fits your test volume. Enter its host, port, sender name/address, username and password into Supabase only. Follow the provider’s domain/sender verification steps and test confirmation and password recovery to two email addresses outside the Supabase project team. Supabase’s default SMTP is restricted to team addresses and is not the public-launch email service.

Configure Supabase Auth rate limits in the dashboard. Review bot protection before opening registration at scale. If enabling CAPTCHA in Supabase, add its client token flow before deployment; turning it on without that UI can break signup. Never disable email confirmation to conceal a delivery problem.

## Step 5 Run local checks

Keep the API terminal open. In another PowerShell window at the repository root:

```powershell
cd frontend
npm ci
npm test
npm run lint
npm run build
npx playwright install chromium
npm run test:browser
npm run dev
```

Open http://localhost:5173. Set VITE_API_URL=http://127.0.0.1:8001 in frontend/.env and restart the dev server after changing environment variables. Create and confirm two disposable adult test accounts. Test login, reset, logout, both themes and the four investigation categories using harmless synthetic evidence.

From backend, run .venv/Scripts/python.exe -m pytest -q. Live tests are opt-in. To run the PostgreSQL integration test, point DATABASE_URL at a disposable test database with a migration-capable role, set RUN_POSTGRES_TESTS=1 and run the test below. Never point routine integration tests at production data.

```powershell
$env:RUN_POSTGRES_TESTS="1"
.venv/Scripts/python.exe -m pytest tests/test_postgres_integration.py -q
Remove-Item Env:RUN_POSTGRES_TESTS
```

Restore the restricted runtime configuration afterward. GitHub Actions also provisions disposable PostgreSQL 16 for the adapter test. The browser automation uses mocked Auth/API responses; the next step is the real service test.

## Step 6 Run the real two account smoke test

Sign in as account A and inspect one authorized API request in the browser’s developer tools Network tab. Copy its short-lived Bearer token privately. Obtain the same from account B in a separate browser profile. Do not use another person’s account, include the Bearer prefix, store tokens in source control or post them in a support ticket.

```powershell
cd backend
$env:EVIDENCE_BASE_URL="http://127.0.0.1:8001"
.venv/Scripts/python.exe smoke_test.py --check-isolation
Remove-Item Env:EVIDENCE_BASE_URL
```

The script prompts privately for the two tokens, creates synthetic text/file cases, checks that B cannot list/read/review/delete A’s cases, tests review, and cleans up its own cases. It consumes analysis allowances. If it fails, investigate the actual error; do not weaken RLS or raise quotas solely to hide a defect.

## Step 7 Prepare free hosting

Open https://dashboard.render.com and connect the repository. Use render.yaml as the blueprint and keep both services on feature/investigator-v2.2. The API uses the Free plan; the frontend is a static site. Keep automatic deployment off during the first controlled release. Do not create Render Free PostgreSQL as the long-term database; this design uses Supabase.

For the API set APP_ENV=production, the restricted DATABASE_URL, SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY and the final frontend FRONTEND_ORIGIN. Keep ENABLE_GEMINI=false and ENABLE_VIRUSTOTAL=false. Set DAILY_ANALYSIS_LIMIT=50, USER_DAILY_ANALYSIS_LIMIT=10 and MAX_INFLIGHT_ANALYSES=2 initially. Pool defaults are min 1, max 5 and max waiting 20. Keep one worker.

API root directory is backend; build is pip install -r requirements.txt; start is uvicorn app.main:app --host 0.0.0.0 --port $PORT. Render’s liveness probe is /live; manually require /health before accepting the release. Inspect the proxy chain and set Uvicorn’s forwarded-header trust only to actual trusted proxy addresses. Do not blindly set a wildcard for an API reachable outside that proxy. Without trusted forwarding, the IP limiter may group clients behind a proxy; daily per-user quotas still apply.

For the static site use root frontend, build npm ci && npm run build, publish dist. Set VITE_API_URL, VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY to the deployed HTTPS endpoints/public key. Set SITE_URL to the exact frontend origin, SUPPORT_EMAIL to a monitored address, OPERATOR_NAME to the actual operator and LAUNCH_READY=false initially. HTTPS on the provided onrender.com address avoids needing to buy a custom domain just for hosting.

## Step 8 Verify the deployed beta

Add the final HTTPS site URL to Supabase Auth’s Site URL and redirect allow-list. Confirm the frontend origin matches backend CORS. If using custom domains, update the Content-Security-Policy connect-src entries in render.yaml to the exact API/Auth origins. The default policy permits Render and Supabase hosts; narrow it to actual hosts once chosen.

Visit deployed /live and /health. Repeat the account flows and the two-account smoke test with EVIDENCE_BASE_URL set to the deployed API. Check previews remain noindex, all public pages have the correct contact/operator, private content is not embedded in HTML or URLs, deletion works and history survives an API restart. Test a real phone, keyboard, screen reader and browser zoom. Free API cold starts can be slow; the UI provides an honest waiting state.

## Step 9 Complete the launch review

Review the policy applicability matrix in REPOSITORY_AUDIT.md and the developer guide. Confirm target countries and legal responsibility, retention/log/backup settings, support handling and supplier terms. Shipping is inapplicable with no physical goods. Marketing unsubscribe is inapplicable until there are marketing subscriptions. There is no session replay or video. Age declaration is an adult beta scope control, not identity verification or proof of all legal compliance.

Do not enable the unpaid Gemini integration for personal/confidential evidence. Its age/region rules must also be considered. VirusTotal’s public API has licensing and business-use restrictions. The default free beta retains deterministic evidence checks with these providers disabled, and AI synthesis may be unavailable or inconclusive.

When all gates pass, change LAUNCH_READY=true and rebuild/redeploy. The build validates HTTPS origins, the public key, operator and contact, scans for credential patterns, and generates canonical pages, robots.txt and sitemap.xml. A successful build does not replace the live checks above.

## Step 10 Submit public pages to Google

Open https://search.google.com/search-console. Add a URL-prefix property for the exact HTTPS Render subdomain, or a Domain property if you control a custom domain’s DNS. Complete Google’s offered verification method. For an HTML verification file, put the exact supplied file into frontend/public and redeploy; do not fabricate a verification token.

Open the deployed /sitemap.xml and check that every URL uses the final domain. Submit sitemap.xml in Search Console’s Sitemaps report. Use URL Inspection for the homepage, guide and phishing-checker page, then request indexing where available. Check that rendered titles/descriptions describe the actual capability. The homepage retains its phishing and suspicious-content title after React starts. Do not submit private hash routes or case content.

Submission and correct metadata do not guarantee indexing or a ranking. Search Console verification/submission have not been performed by this code update and remain owner actions.

## Step 11 Operate and recover

Monitor free-plan quotas, database growth, confirmation email delivery, 429/503 rates and support requests. Back up using a method supported by the chosen plan and test a restore before relying on it. Never commit backups containing user data. Automatic case expiry is not implemented, so publish and follow the chosen retention process.

For a failed release, pause new investigations, restore the previous known-good Render deployment and assess schema compatibility. Turning off indexing does not take a service offline or protect private data. The current additive changes do not delete user records. Future destructive migrations require their own backup and rollback plan.

For a verified account-deletion request, pause incoming work, let in-flight requests finish, revoke sessions and remove the Supabase Auth account through the dashboard. Use the migration-owner credential only for the cleanup script. Run python scripts/delete_user_data.py USER_UUID first to see counts. Then run it with --execute and type the same UUID when prompted. The script requires the Auth identity to be absent and removes only that owner’s cases and personal usage counters. It cannot erase provider logs or backups; explain those separately to the requester.

## Current official references

Checked 23 September 2026: Render free hosting https://render.com/docs/free; Supabase connections https://supabase.com/docs/guides/database/connecting-to-postgres; Supabase data security https://supabase.com/docs/guides/database/secure-data; SMTP https://supabase.com/docs/guides/auth/auth-smtp; Google sitemap submission https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap; Gemini terms https://ai.google.dev/gemini-api/terms; VirusTotal restrictions https://docs.virustotal.com/reference/public-vs-premium-api. Recheck quotas and terms before launch.
