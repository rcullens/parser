import sqlite3
import tempfile
import unittest
from pathlib import Path

from asset_dashboard.classify import classify_asset_severity
from asset_dashboard.ingest import ingest_asset_endpoints
from asset_dashboard.parser import parse_asset_endpoint


class ParseAssetEndpointTests(unittest.TestCase):
    def test_accepts_https_url(self):
        asset = parse_asset_endpoint("https://assets.example.com/status")
        self.assertIsNotNone(asset)
        self.assertEqual(asset.url, "https://assets.example.com/status")
        self.assertEqual(asset.host, "assets.example.com")
        self.assertEqual(asset.path, "/status")
        self.assertIsNone(asset.port)

    def test_normalizes_bare_hostname(self):
        asset = parse_asset_endpoint("inventory.example.com")
        self.assertIsNotNone(asset)
        self.assertEqual(asset.url, "https://inventory.example.com/")
        self.assertEqual(asset.scheme, "https")

    def test_strips_userinfo(self):
        asset = parse_asset_endpoint("https://alice:secret@example.com/login")
        self.assertIsNotNone(asset)
        self.assertEqual(asset.url, "https://example.com/login")
        self.assertNotIn("alice", asset.url)
        self.assertNotIn("secret", asset.url)

    def test_keeps_nondefault_port(self):
        asset = parse_asset_endpoint("https://example.com:8443/health")
        self.assertEqual(asset.url, "https://example.com:8443/health")
        self.assertEqual(asset.port, 8443)

    def test_drops_default_https_port(self):
        asset = parse_asset_endpoint("https://example.com:443/")
        self.assertEqual(asset.url, "https://example.com/")
        self.assertIsNone(asset.port)

    def test_skips_comments_and_blanks(self):
        self.assertIsNone(parse_asset_endpoint(""))
        self.assertIsNone(parse_asset_endpoint("   "))
        self.assertIsNone(parse_asset_endpoint("# https://example.com"))

    def test_rejects_non_http_schemes(self):
        self.assertIsNone(parse_asset_endpoint("file:///etc/passwd"))
        self.assertIsNone(parse_asset_endpoint("javascript:alert(1)"))
        self.assertIsNone(parse_asset_endpoint("ftp://files.example.com/list"))

    def test_rejects_invalid_host(self):
        self.assertIsNone(parse_asset_endpoint("https:///nohost"))
        self.assertIsNone(parse_asset_endpoint("not a url"))
        self.assertIsNone(parse_asset_endpoint("https://exa mple.com"))


class ClassifyAssetSeverityTests(unittest.TestCase):
    def test_admin_path_is_critical(self):
        asset = parse_asset_endpoint("https://app.example.com/admin/users")
        self.assertEqual(classify_asset_severity(asset), "critical")

    def test_vpn_host_is_critical(self):
        asset = parse_asset_endpoint("https://vpn.example.com/")
        self.assertEqual(classify_asset_severity(asset), "critical")

    def test_api_path_is_high(self):
        asset = parse_asset_endpoint("https://shop.example.com/api/v1")
        self.assertEqual(classify_asset_severity(asset), "high")

    def test_prod_label_is_high(self):
        asset = parse_asset_endpoint("https://prod.assets.example.com/home")
        self.assertEqual(classify_asset_severity(asset), "high")

    def test_production_hostname_is_not_high_by_substring(self):
        asset = parse_asset_endpoint("https://production.example.com/home")
        self.assertEqual(classify_asset_severity(asset), "medium")

    def test_staging_is_low(self):
        asset = parse_asset_endpoint("https://staging.example.com/")
        self.assertEqual(classify_asset_severity(asset), "low")

    def test_plain_http_is_low(self):
        asset = parse_asset_endpoint("http://www.example.com/")
        self.assertEqual(classify_asset_severity(asset), "low")

    def test_generic_https_is_medium(self):
        asset = parse_asset_endpoint("https://www.example.com/about")
        self.assertEqual(classify_asset_severity(asset), "medium")


class IngestAssetEndpointsTests(unittest.TestCase):
    def test_batch_insert_or_ignore(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            targets = tmp_path / "targets.txt"
            db_path = tmp_path / "assets.db"
            targets.write_text(
                "\n".join(
                    [
                        "# inventory export",
                        "https://www.example.com/about",
                        "https://app.example.com/admin",
                        "https://app.example.com/admin",
                        "not-a-url",
                        "https://api.example.com/v2",
                        "javascript:alert(1)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            first = ingest_asset_endpoints(targets, db_path)
            self.assertEqual(first.valid, 3)
            self.assertEqual(first.inserted, 3)
            self.assertEqual(first.duplicates, 0)
            self.assertGreater(first.skipped, 0)

            second = ingest_asset_endpoints(targets, db_path)
            self.assertEqual(second.valid, 3)
            self.assertEqual(second.inserted, 0)
            self.assertEqual(second.duplicates, 3)

            conn = sqlite3.connect(db_path)
            rows = conn.execute(
                "SELECT url, severity FROM assets ORDER BY url"
            ).fetchall()
            conn.close()
            self.assertEqual(
                rows,
                [
                    ("https://api.example.com/v2", "high"),
                    ("https://app.example.com/admin", "critical"),
                    ("https://www.example.com/about", "medium"),
                ],
            )

    def test_custom_classifier_is_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            targets = tmp_path / "targets.txt"
            db_path = tmp_path / "assets.db"
            targets.write_text("https://custom.example.com/\n", encoding="utf-8")

            result = ingest_asset_endpoints(
                targets,
                db_path,
                classify=lambda asset: "high",
            )
            self.assertEqual(result.inserted, 1)
            conn = sqlite3.connect(db_path)
            severity = conn.execute("SELECT severity FROM assets").fetchone()[0]
            conn.close()
            self.assertEqual(severity, "high")


if __name__ == "__main__":
    unittest.main()
