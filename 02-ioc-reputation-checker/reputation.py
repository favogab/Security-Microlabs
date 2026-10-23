
import ipaddress
import os
import requests
from dotenv import load_dotenv
import json
from pathlib import Path

def validate_ip(ip):
    try:
        address = ipaddress.ip_address(ip)

        if address.version != 4:
            return False

        return address.is_global

    except ValueError:
        return False


def check_ip_reputation(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=10
    )

    response.raise_for_status()

    data = response.json()["data"]

    return {
        "ip": data["ipAddress"],
        "abuse_score": data["abuseConfidenceScore"],
        "total_reports": data["totalReports"],
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "last_reported": data.get("lastReportedAt")
    }





def main():
    base_dir = Path(__file__).resolve().parent
    load_dotenv(base_dir / ".env")

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        print("[ERROR] Missing AbuseIPDB API key.")
        return

    input_path = base_dir / "samples" / "ips.json"
    output_path = base_dir / "reputation_report.json"

    with open(input_path, "r", encoding="utf-8") as file:
        sample_ips = json.load(file)["ipv4"]

    results = {
        "checked": [],
        "skipped": [],
        "errors": []
    }

    for ip in dict.fromkeys(sample_ips):
        if not isinstance(ip, str) or not validate_ip(ip):
            print(f"[SKIPPED] {ip}")
            results["skipped"].append(ip)
            continue

        try:
            result = check_ip_reputation(ip, api_key)
            results["checked"].append(result)

            print(f"\nIP: {result['ip']}")
            print(f"Abuse score: {result['abuse_score']}")
            print(f"Total reports: {result['total_reports']}")
            print(f"Country: {result['country']}")
            print(f"ISP: {result['isp']}")

        except (requests.exceptions.RequestException, ValueError, KeyError) as error:
            print(f"[ERROR] Could not check {ip}: {error}")
            results["errors"].append({
                "ip": ip,
                "error": str(error)
            })

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    print(f"\nReport saved to {output_path.name}")


if __name__ == "__main__":
    main()
