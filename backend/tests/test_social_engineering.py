from app.detectors.social_engineering import (
    detect_social_engineering,
)


def _signals(content):
    return {
        item["signal"]
        for item in detect_social_engineering(
            content
        )
    }


def test_detects_credential_and_urgency_signals():
    signals = _signals(
        "Urgent: verify your account immediately "
        "and enter your password."
    )

    assert "Urgency Pressure" in signals
    assert "Credential Request" in signals


def test_detects_mfa_request():
    signals = _signals(
        "Please share your OTP verification code."
    )

    assert "MFA Code Request" in signals


def test_detects_payment_change_pressure():
    signals = _signals(
        "Urgent payment required. Change the bank "
        "account details before sending funds."
    )

    assert "Urgency Pressure" in signals
    assert (
        "Payment Change or Financial Pressure"
        in signals
    )


def test_benign_message_has_no_social_signal():
    assert (
        detect_social_engineering(
            "Team meeting is tomorrow at 10."
        )
        == []
    )
