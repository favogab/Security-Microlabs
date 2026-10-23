
import sys
from pathlib import Path
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reputation import validate_ip, check_ip_reputation


def test_valid_public_ip():
    assert validate_ip("8.8.8.8") is True


def test_invalid_ip():
    assert validate_ip("999.999.999.999") is False


def test_reserved_ip():
    assert validate_ip("192.0.2.55") is False


def test_private_ip():
    assert validate_ip("192.168.1.1") is False


def test_ipv6_not_supported():
    assert validate_ip("2001:4860:4860::8888") is False


@patch("reputation.requests.get")
def test_successful_api_response(mock_get):
    mock_response = Mock()

    mock_response.json.return_value = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 0,
            "totalReports": 237,
            "countryCode": "US",
            "isp": "Google LLC",
            "lastReportedAt": None
        }
    }

    mock_get.return_value = mock_response

    result = check_ip_reputation("8.8.8.8", "fake-test-key")

    assert result["ip"] == "8.8.8.8"
    assert result["abuse_score"] == 0
    assert result["total_reports"] == 237

    mock_get.assert_called_once()
    mock_response.raise_for_status.assert_called_once()
