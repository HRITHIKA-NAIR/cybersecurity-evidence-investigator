from __future__ import annotations

import os

import httpx

BASE_URL = os.getenv(
    "EVIDENCE_BASE_URL",
    "http://127.0.0.1:8001",
).rstrip("/")


def _check(
    client: httpx.Client,
    method: str,
    path: str,
    **kwargs,
):
    response = client.request(
        method,
        BASE_URL + path,
        **kwargs,
    )
    response.raise_for_status()
    return response


def run():
    with httpx.Client(
        timeout=90,
        follow_redirects=True,
    ) as client:
        _check(
            client,
            "GET",
            "/health",
        )
        _check(
            client,
            "GET",
            "/docs",
        )

        text_result = _check(
            client,
            "POST",
            "/investigate",
            json={
                "content": (
                    "Production smoke test: urgent "
                    "verify your account and enter "
                    "your password."
                )
            },
        ).json()

        investigation_id = (
            text_result.get(
                "investigation_id"
            )
        )

        if not investigation_id:
            raise RuntimeError(
                "Text investigation was not "
                "persisted."
            )

        _check(
            client,
            "POST",
            "/investigate-file",
            files={
                "file": (
                    "smoke.txt",
                    (
                        b"Production file smoke "
                        b"test only."
                    ),
                    "text/plain",
                )
            },
        )

        history = _check(
            client,
            "GET",
            "/investigations",
        ).json()

        if not any(
            item.get("id")
            == investigation_id
            for item in history
        ):
            raise RuntimeError(
                "Saved investigation was not "
                "returned by history."
            )

        _check(
            client,
            "POST",
            "/challenge",
            json={
                "investigation_id": (
                    investigation_id
                )
            },
        )

    print(
        "Production smoke test passed: "
        "health, docs, text, file, history, "
        "and challenge."
    )


if __name__ == "__main__":
    run()
