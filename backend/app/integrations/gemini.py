from __future__ import annotations

import json
import os

from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

MODELS = (
    "gemini-3.1-flash-lite",
    "gemini-3.5-flash",
)
API_KEY = os.getenv("GEMINI_API_KEY")
CLIENT = (
    genai.Client(api_key=API_KEY)
    if API_KEY
    else None
)


def available() -> bool:
    return CLIENT is not None


def generate_json(
    prompt: str,
    *,
    label: str,
) -> dict:
    if CLIENT is None:
        raise RuntimeError(
            "Gemini API key is not configured."
        )

    response = None
    last_error = None

    for model in MODELS:
        try:
            response = (
                CLIENT.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0,
                    ),
                )
            )
            print(
                f"{label} model used: {model}"
            )
            break

        except Exception as error:
            print(
                f"{label} model failed "
                f"({model}): {error}"
            )
            last_error = error

    if response is None:
        if last_error:
            raise last_error

        raise RuntimeError(
            "Gemini returned no response."
        )

    text = response.text.strip()

    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]

    if text.endswith("```"):
        text = text[:-3]

    return json.loads(
        text.strip()
    )
