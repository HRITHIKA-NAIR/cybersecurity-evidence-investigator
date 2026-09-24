# Technology stack document

The release keeps the existing React and FastAPI architecture. PostgreSQL is the persistent data store and Supabase Auth provides account identity. The browser accesses investigation data through the API rather than directly querying database tables.

| Layer | Selected technology | Purpose |
| --- | --- | --- |
| Browser application | React 19 and Vite 8 | Component UI and optimized static builds |
| Motion and icons | Motion 13 and Lucide React | Scoped transitions, spring effects and consistent SVG icons |
| Identity client | Supabase JavaScript client 2 | Signup, confirmation, password login, recovery and session refresh |
| API | Python 3.12 or 3.13, FastAPI, Uvicorn | Validated requests and authenticated investigation routes |
| Database access | Psycopg 3 and psycopg-pool | Parameterized PostgreSQL queries and bounded connection pooling |
| Persistence | PostgreSQL, hosted on Supabase | Relational cases, evidence, findings, ownership and quotas |
| Parsing | pypdf, python-docx, python-pptx, openpyxl, oletools, py7zr, Pillow and OpenCV | Supported document, archive, macro and QR inspection |
| Optional integrations | Google GenAI SDK and VirusTotal HTTP API | Explicitly enabled assessment and reputation lookups |
| Quality checks | pytest, Node test runner, Playwright, axe-core, ESLint and Vite build | Backend regressions, public-config guards, browser journeys, accessibility and build checks |
| Hosting candidate | Render static site and one free Python web service | CDN frontend and API with a sleeping free instance |
| CI | GitHub Actions with PostgreSQL 16 and Node 22 | Backend integration and frontend build checks |

## Versions and installation sources

The exact frontend versions are recorded in package-lock.json; use npm ci for repeatable installation. Backend core dependencies are pinned, while several parser dependencies and development tools have bounded version ranges in requirements files. For a deployed release, record the resolved environment with pip freeze and retain it with the release evidence; a comprehensive backend transitive lockfile is not yet provided.

Install Python from python.org, Node 22 from nodejs.org and Git from git-scm.com. A local PostgreSQL server is optional if using a dedicated Supabase test project. Do not use a production database for routine development or the disposable integration tests.

## Decisions

Keep animation in one library so bundle cost and reduced-motion behavior remain manageable. Native scrolling remains available to the browser, keyboard and assistive technologies. Keep raw file processing on the API; never execute a submitted payload. Use server-side provider credentials and a separate non-owner database login.

Use Supabase's publishable key in the browser as intended. It identifies the project; it is not a substitute for authorization and is not a secret. Database access is protected by grants, RLS and API identity validation, independently of the paid or free plan.

## Free service limits

The frontend can use Render's free static hosting. Its free API service sleeps after inactivity and is unsuitable for an uptime commitment. Supabase's free project has quotas and availability limitations that must be checked in the owner's dashboard. Do not use Render's expiring free PostgreSQL instance as the long-term database.

Public email confirmation needs custom SMTP: Supabase's default SMTP only serves authorized team addresses and is intended for testing. A provider's free sending allowance may still require domain verification or ownership of a domain. Therefore the full public service cannot honestly be promised to remain zero-cost under every configuration.

Gemini and VirusTotal default off. Their terms and quotas can make a particular public, commercial, regional or under-18 use ineligible. Budget guards limit requests; they are not a guarantee of zero provider charges if billing is enabled.

## Licenses and ownership

The site uses system fonts and does not redistribute a paid font. Retain notices for React, Motion, Lucide and Supabase dependencies, and review transitive dependency licenses before release. The repository owner must select an appropriate license for their own code; importing open-source packages does not assign a license to this project.
