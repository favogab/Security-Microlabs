# IOC Extractor

A lightweight Python security automation tool that extracts indicators of compromise (IOCs) from unstructured text reports.

## Features

- Extracts IPv4 addresses, domains, HTTP/HTTPS URLs, and SHA-256 hashes.
- Validates IPv4 addresses and removes duplicate indicators.
- Organizes results into categories.
- Exports findings to JSON.
- Includes automated tests using pytest.

## Technologies

Python 3, regular expressions, ipaddress, pathlib, urllib.parse, JSON, pytest.

## Usage

From the `01-ioc-extractor` directory:

```bash
python extractor.py
```

The tool reads `samples/report.txt` and generates `indicators.json`.

## Testing

```bash
python -m pytest -v
```

## Limitations

- Currently processes one predefined text file.
- Does not support defanged indicators.
- Uses basic URL and domain parsing, which can produce false positives.
- Does not determine whether extracted indicators are malicious.
- SHA-256 hashes are identified by their format only.

## Future Improvements

- Command-line file arguments.
- Defanged IOC normalization.
- Additional validation and extraction edge cases.
- Integration with threat intelligence APIs.