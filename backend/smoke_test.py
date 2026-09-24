"""Authenticated smoke test. Run only against a disposable test account."""
from __future__ import annotations
import os
import argparse
import getpass
import httpx

def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-isolation', action='store_true', help='Also test a second confirmed account against the first account’s cases')
    args = parser.parse_args()
    base = os.getenv("EVIDENCE_BASE_URL", "http://127.0.0.1:8001").rstrip("/")
    token = os.getenv("EVIDENCE_TEST_TOKEN") or getpass.getpass('Short-lived access token for disposable confirmed account A (hidden): ').strip()
    if not token:
        raise SystemExit('An access token is required. Do not paste it into chat or commit it.')
    other = None
    if args.check_isolation:
        other = os.getenv('EVIDENCE_SECOND_TEST_TOKEN') or getpass.getpass('Short-lived access token for a different confirmed account B (hidden): ').strip()
        if not other or other == token:
            raise SystemExit('A different test account token is required for the isolation check.')
    ids = []
    with httpx.Client(base_url=base, timeout=180, follow_redirects=False) as client:
        assert client.get("/live").status_code == 200
        assert client.get("/health").status_code == 200
        assert client.get("/investigations").status_code == 401
        client.headers["Authorization"] = "Bearer " + token
        try:
            for path, args in [
                ("/investigate", {"json": {"content": "Synthetic smoke test: urgent account verification."}}),
                ("/investigate-file", {"files": {"file": ("smoke.txt", b"Synthetic test only.", "text/plain")}}),
            ]:
                response = client.post(path, **args)
                response.raise_for_status()
                case_id = response.json().get("investigation_id")
                assert case_id, "Result must be persisted."
                ids.append(case_id)
            history = client.get("/investigations")
            history.raise_for_status()
            assert set(ids).issubset({row["id"] for row in history.json()})
            if other:
                headers = {'Authorization': 'Bearer ' + other}
                other_history = client.get('/investigations?summary=true', headers=headers)
                other_history.raise_for_status()
                assert not set(ids).intersection({row['id'] for row in other_history.json()}), 'Foreign case was exposed in history.'
                for case_id in ids:
                    assert client.get('/investigations/' + str(case_id), headers=headers).status_code == 404
                    assert client.delete('/investigations/' + str(case_id), headers=headers).status_code == 404
                assert client.post('/challenge', json={'investigation_id': ids[0]}, headers=headers).status_code == 404
            response = client.post("/challenge", json={"investigation_id": ids[0]})
            response.raise_for_status()
            assert response.json()["persistence"]["status"] == "saved"
        finally:
            for case_id in ids:
                response = client.delete("/investigations/" + str(case_id))
                response.raise_for_status()
                assert client.get("/investigations/" + str(case_id)).status_code == 404
    print("PASS: readiness, unauthenticated denial, text, file, saved history, review and deletion.")
    if other:
        print('PASS: separate confirmed account cannot list, open, review or delete the created cases.')

if __name__ == "__main__":
    run()
