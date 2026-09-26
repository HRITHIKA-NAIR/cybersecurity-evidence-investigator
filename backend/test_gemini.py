import os

import pytest
from dotenv import load_dotenv
from google import genai


@pytest.mark.skipif(
    os.getenv("RUN_GEMINI_SMOKE") != "1",
    reason="Live Gemini smoke test is opt-in.",
)
def test_gemini_smoke():
    load_dotenv()
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        pytest.skip("GEMINI_API_KEY is not configured.")

    client = genai.Client(api_key=api_key)
    last_error = None

    for model in (
        "gemini-3.1-flash-lite",
        "gemini-3.5-flash",
    ):
        try:
            response = client.models.generate_content(
                model=model,
                contents="Reply with exactly: GEMINI WORKING",
            )

            assert response.text.strip() == "GEMINI WORKING"
            return
        except Exception as error:
            last_error = error

    raise last_error
