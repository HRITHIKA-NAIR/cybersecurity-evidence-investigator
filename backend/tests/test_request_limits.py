import pytest
from pydantic import ValidationError

from app.main import (
    InvestigationRequest,
    MAX_TEXT_CHARS,
)


def test_text_request_rejects_empty_content():
    with pytest.raises(
        ValidationError
    ):
        InvestigationRequest(
            content=""
        )


def test_text_request_rejects_oversized_content():
    with pytest.raises(
        ValidationError
    ):
        InvestigationRequest(
            content=(
                "a"
                * (MAX_TEXT_CHARS + 1)
            )
        )
