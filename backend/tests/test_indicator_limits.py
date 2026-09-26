from app.tools.indicators import (
    MAX_URL_INDICATORS,
    extract_indicators,
)


def test_indicator_extraction_bounds_outbound_urls():
    content = " ".join(
        (
            f"https://host-{index}.example.test/path"
        )
        for index in range(
            MAX_URL_INDICATORS + 5
        )
    )

    result = extract_indicators(
        content
    )

    assert (
        len(result["urls"])
        == MAX_URL_INDICATORS
    )
    assert (
        result["truncated"]["urls"]
        is True
    )
