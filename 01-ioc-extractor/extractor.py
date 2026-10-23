
import re
import json
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit


IP_PATTERN = r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
URL_PATTERN = r"https?://[^\s<>\"']+"
DOMAIN_PATTERN = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
HASH_PATTERN = r"\b[a-fA-F0-9]{64}\b"


def extract_ips(text):
    valid_ips = set()

    for match in re.findall(IP_PATTERN, text):
        try:
            valid_ips.add(str(ipaddress.IPv4Address(match)))
        except ipaddress.AddressValueError:
            continue

    return sorted(valid_ips)


def extract_urls(text):
    urls = set()

    for match in re.findall(URL_PATTERN, text):
        url = match.rstrip(".,;!?")

        parsed = urlsplit(url)

        if parsed.hostname:
            urls.add(url)

    return sorted(urls)


def extract_domains(text):
    domains = set(re.findall(DOMAIN_PATTERN, text))

    for url in extract_urls(text):
        hostname = urlsplit(url).hostname

        if hostname:
            domains.add(hostname)

    return sorted(domains)


def extract_hashes(text):
    return sorted(set(re.findall(HASH_PATTERN, text)))


def analyze_report(text):
    return {
        "ipv4": extract_ips(text),
        "domains": extract_domains(text),
        "urls": extract_urls(text),
        "sha256": extract_hashes(text),
    }


def main():
    base_dir = Path(__file__).resolve().parent
    report_path = base_dir / "samples" / "report.txt"
    output_path = base_dir / "indicators.json"

    report = report_path.read_text(encoding="utf-8")
    results = analyze_report(report)

    print("\n=== IOC EXTRACTOR ===")

    for category, indicators in results.items():
        print(f"\n{category.upper()} ({len(indicators)})")

        for indicator in indicators:
            print(f"  - {indicator}")

    output_path.write_text(
        json.dumps(results, indent=4),
        encoding="utf-8"
    )

    print(f"\nResults saved to {output_path.name}")


if __name__ == "__main__":
    main()
