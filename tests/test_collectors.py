
from modules.collectors import validate_cnic_format, validate_phone


def test_cnic_format_requires_13_digits():
    valid = validate_cnic_format("1234512345671")
    invalid = validate_cnic_format("12345")

    assert valid["evidence"]["format_valid"] is True
    assert invalid["evidence"]["format_valid"] is False


def test_phone_result_has_required_fields():
    output = validate_phone("+14155552671", "US")

    assert "status" in output
    assert "finding" in output
    assert "observed_at" in output
    assert "limitations" in output


def test_cnic_does_not_claim_identity_verification():
    output = validate_cnic_format("1234512345671")

    assert output["status"] == "inconclusive"
    assert any(
        "does not authenticate" in limitation.lower()
        for limitation in output["limitations"]
    )
