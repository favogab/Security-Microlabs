
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from extractor import (
    extract_ips,
    extract_urls,
    extract_domains,
    extract_hashes,
    analyze_report,
)


def test_extract_valid_ips():
    text = "Connected to 192.0.2.55 and 203.0.113.17"
    assert extract_ips(text) == [
        "192.0.2.55",
        "203.0.113.17",
    ]


def test_reject_invalid_ips():
    text = "Invalid: 999.999.999.999"
    assert extract_ips(text) == []


def test_remove_duplicate_ips():
    text = "192.0.2.55 192.0.2.55"
    assert extract_ips(text) == ["192.0.2.55"]


def test_extract_urls():
    text = "Visit https://example.org/download."
    assert extract_urls(text) == [
        "https://example.org/download"
    ]


def test_extract_domains():
    text = "Suspicious domain: malware-delivery.example"
    assert "malware-delivery.example" in extract_domains(text)


def test_extract_sha256():
    hash_value = "a" * 64
    assert extract_hashes(hash_value) == [hash_value]


def test_empty_report():
    assert analyze_report("") == {
        "ipv4": [],
        "domains": [],
        "urls": [],
        "sha256": [],
    }
