# Asset endpoint parser

Ingest a plaintext list of asset endpoints, sanitize each line as a URL, classify inventory severity, and store verified assets in SQLite with batched `INSERT OR IGNORE`.

## Requirements

- Python 3.10+
- Standard library only (`urllib.parse`, `sqlite3`)

## Usage

```bash
python3 -m asset_dashboard targets.txt assets.db
```

```python
from asset_dashboard import ingest_asset_endpoints

result = ingest_asset_endpoints("targets.txt", "assets.db")
print(result.inserted, result.skipped, result.duplicates)
```

`ingest_asset_endpoints()`:

1. Opens the plaintext list (`targets.txt`)
2. Sanitizes each line with `urllib.parse`
3. Classifies severity (or uses a custom `classify=` callback)
4. Writes verified assets with batched `INSERT OR IGNORE`

Copy `targets.example.txt` to `targets.txt` and replace the sample hosts with your inventory.

## Tests

```bash
python3 -m unittest tests.test_asset_ingest -v
```
