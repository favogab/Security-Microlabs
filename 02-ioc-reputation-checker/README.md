# IOC Reputation Checker

A Python-based cybersecurity automation tool that checks the reputation of public IPv4 addresses using the AbuseIPDB threat intelligence API.

The tool helps security analysts enrich IP indicators with reputation data during incident investigation and triage.

## Features

- Validates IPv4 addresses before querying the API.
- Skips private, reserved, and invalid IP addresses.
- Retrieves abuse confidence scores, report counts, country codes, ISP information, and last reported dates.
- Removes duplicate IP addresses to avoid unnecessary API requests.
- Handles HTTP and API errors without stopping the entire investigation.
- Exports structured investigation results to JSON.
- Includes automated tests with mocked API responses.

## Technologies

- Python 3
- Requests
- Python-dotenv
- Pytest
- AbuseIPDB API
- JSON

## Project Structure

```text
02-ioc-reputation-checker/
├── samples/
│   └── ips.json
├── tests/
│   └── test_reputation.py
├── reputation.py
├── reputation_report.json
└── README.md
```

## Installation

Install the required dependencies:

```bash
python -m pip install requests python-dotenv pytest
```

Create a `.env` file inside the project directory:

```dotenv
ABUSEIPDB_API_KEY=your_api_key_here
```

Obtain an API key from [AbuseIPDB](https://www.abuseipdb.com/).

**Security:** Never commit your `.env` file or API credentials to GitHub.

## Usage

Add the IP addresses you want to investigate to `samples/ips.json`:

```json
{
  "ipv4": [
    "8.8.8.8",
    "1.1.1.1",
    "192.0.2.55"
  ]
}
```

Run the program:

```bash
python reputation.py
```

The script validates the IP addresses, queries AbuseIPDB for eligible public IPv4 addresses, and saves the findings to `reputation_report.json`.

## Example Output

```json
{
  "checked": [
    {
      "ip": "8.8.8.8",
      "abuse_score": 0,
      "total_reports": 237,
      "country": "US",
      "isp": "Google LLC",
      "last_reported": null
    }
  ],
  "skipped": [
    "192.0.2.55"
  ],
  "errors": []
}
```

*Example values are illustrative snapshots and may differ from current AbuseIPDB results.*

## Testing

Run the automated tests:

```bash
python -m pytest -v
```

The tests cover IP validation and successful API response handling. HTTP requests are mocked during testing, so no real API requests are needed.

## Limitations

- Supports IPv4 addresses only.
- Requires an active AbuseIPDB API key and internet connection.
- Processes IP addresses from a predefined JSON file.
- Does not automatically classify IP addresses as malicious.
- Reputation information depends on third-party reporting and may change over time.

## Future Improvements

- Command-line arguments for custom input files.
- Additional API error-handling tests.
- Configurable reputation thresholds.
- Integration with the IOC Extractor project.

## Security Considerations

Reputation scores should support analyst investigations, not replace contextual analysis. A high number of abuse reports does not necessarily establish malicious activity.