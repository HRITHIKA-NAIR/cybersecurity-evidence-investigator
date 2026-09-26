# Deployment Guide

## Target architecture

- Frontend: Render static site
- Backend: Render Python web service
- Database: Supabase-hosted PostgreSQL

## 1. Create PostgreSQL

Create a Supabase project and obtain the PostgreSQL connection or pooler URL appropriate for the Render backend.

Store it only as the backend environment variable:

```text
DATABASE_URL
```

Do not place database credentials in frontend variables or source files.

The backend adds `sslmode=require` for remote PostgreSQL URLs that do not already request an equally strict mode.

For a long-lived Render backend, use the Supabase connection endpoint appropriate for the deployment environment. The application disables server-side prepared statements to remain compatible with common pooler configurations.

Recommended initial pool values:

```text
DB_POOL_MIN=1
DB_POOL_MAX=5
DB_POOL_MAX_WAITING=20
```

Tune only after measuring real load and Supabase connection limits.

## 2. Render backend

If the Render service root directory is `backend`:

Build:

```bash
python -m pip install -r requirements.txt
```

Start:

```bash
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

Backend environment:

```text
GEMINI_API_KEY
VIRUSTOTAL_API_KEY
FRONTEND_ORIGIN
DATABASE_URL
DB_POOL_MIN
DB_POOL_MAX
DB_POOL_MAX_WAITING
```

Set `FRONTEND_ORIGIN` to the exact deployed frontend origin without an unnecessary trailing slash.

## 3. Render frontend

Root directory:

```text
frontend
```

Build:

```bash
npm ci && npm run build
```

Publish directory:

```text
dist
```

Frontend environment:

```text
VITE_API_URL=https://your-backend-service
```

No backend secret may use a `VITE_` prefix.

## 4. Optional legacy SQLite migration

Only if old local history must be retained:

```bash
cd backend
python scripts/migrate_sqlite_to_postgres.py investigations.db
```

The source SQLite file remains a legacy migration input only. The running V2 service uses PostgreSQL.

## 5. Release gates

Before merging the feature branch:

```bash
cd backend
python -m compileall app
python -m pytest -q
```

With the real Supabase `DATABASE_URL` configured:

```powershell
$env:RUN_POSTGRES_TESTS="1"
python -m pytest tests/test_postgres_integration.py -q
Remove-Item Env:RUN_POSTGRES_TESTS
```

Frontend:

```bash
cd frontend
npm run lint
npm run build
```

Run the controlled evaluation against the local backend:

```bash
cd backend
python evaluate.py
```

## 6. Production smoke test

After deployment:

```powershell
cd backend
$env:EVIDENCE_BASE_URL="https://your-backend-service"
python smoke_test.py
Remove-Item Env:EVIDENCE_BASE_URL
```

This verifies:

- `/health`
- `/docs`
- text investigation
- file investigation
- PostgreSQL history
- Challenge Conclusion

## 7. Release verification

Confirm:

- `/health` returns HTTP 200 with database status `ok`
- frontend requests use the deployed backend URL
- CORS accepts only the intended frontend plus local development origins
- no secret `.env` file is tracked
- no raw malware/private email test artifact is tracked
- production history survives backend restarts
