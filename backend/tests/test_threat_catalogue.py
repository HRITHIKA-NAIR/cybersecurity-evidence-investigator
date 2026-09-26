from app.detectors.threat_catalogue import (
    ARCHITECTURE,
    CONTEXTUAL,
    DIRECT,
    DYNAMIC,
    INDICATOR,
    THREAT_CATALOGUE,
)


def test_v21_threat_catalogue_has_all_86_topics():
    assert set(
        THREAT_CATALOGUE
    ) == set(range(1, 87))


def test_catalogue_uses_supported_coverage_modes():
    allowed = {
        DIRECT,
        INDICATOR,
        DYNAMIC,
        CONTEXTUAL,
        ARCHITECTURE,
    }

    assert all(
        mode in allowed
        for _, mode
        in THREAT_CATALOGUE.values()
    )


def test_dynamic_only_families_are_not_direct():
    assert (
        THREAT_CATALOGUE[42][1]
        == DYNAMIC
    )
    assert (
        THREAT_CATALOGUE[57][1]
        == DYNAMIC
    )
    assert (
        THREAT_CATALOGUE[83][1]
        == DYNAMIC
    )
