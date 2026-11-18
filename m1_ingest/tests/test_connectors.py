import gzip
from datetime import date, datetime, timezone

import pytest

from app.connectors import cisa_kev, epss, nvd, osv, rss

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><guid>g1</guid><title>Patch &amp; Fix</title><link>https://x/1</link>
<description>&lt;p&gt;Fixes CVE-2024-1111&lt;/p&gt;</description>
<pubDate>Tue, 05 Nov 2024 10:00:00 GMT</pubDate></item>
<item><title>No guid</title><link>https://x/2</link></item></channel></rss>"""


def test_rss_parse():
    items = rss.parse_feed(RSS, {"url": "https://x", "config": {}})
    assert [i.external_id for i in items] == ["g1", "https://x/2"]
    assert items[0].title == "Patch & Fix" and items[0].body == "Fixes CVE-2024-1111"
    assert items[0].published_at == datetime(2024, 11, 5, 10, 0, tzinfo=timezone.utc)


def test_rss_rejects_garbage():
    with pytest.raises(ValueError):
        rss.parse_feed(b"<html>nope", {"url": "u"})


def test_kev_parse():
    rows = cisa_kev.parse_catalog({"vulnerabilities": [
        {"cveID": "cve-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
         "requiredAction": "Patch", "knownRansomwareCampaignUse": "Known"},
        {"cveID": ""}]})
    assert rows == [{"cve_id": "CVE-2021-44228", "date_added": date(2021, 12, 10),
                     "due_date": date(2021, 12, 24), "action": "Patch", "ransomware": "Known"}]


NVD = {"cve": {
    "id": "CVE-2024-0001", "vulnStatus": "Analyzed",
    "published": "2024-01-02T10:00:00.000", "lastModified": "2024-01-03T11:00:00.000",
    "descriptions": [{"lang": "es", "value": "hola"}, {"lang": "en", "value": "hello"}],
    "weaknesses": [{"description": [{"value": "CWE-79"}, {"value": "NVD-CWE-Other"}]}],
    "metrics": {"cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 5.0,
                                           "baseSeverity": "MEDIUM", "vectorString": "s"}},
        {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.8,
                                         "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N"}}]},
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:Apache:HTTP_Server:*:*:*:*:*:*:*:*",
         "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:vendor:prod:1.2:*:*:*:*:*:*:*"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}]}}


def test_nvd_parse():
    rec, aff = nvd.parse_cve(NVD)
    assert rec["cve_id"] == "CVE-2024-0001" and rec["description"] == "hello"
    assert rec["cvss_score"] == 9.8 and rec["cvss_version"] == "3.1"
    assert rec["cvss_severity"] == "CRITICAL" and rec["cwe_ids"] == ["CWE-79"]
    assert rec["published_at"] == datetime(2024, 1, 2, 10, 0, tzinfo=timezone.utc)
    assert len(aff) == 2
    assert aff[0]["vendor"] == "apache" and aff[0]["product"] == "http_server"
    assert aff[0]["version_exact"] is None and aff[0]["version_end_excluding"] == "2.4.50"
    assert aff[1]["version_exact"] == "1.2"


def test_nvd_without_metrics():
    rec, aff = nvd.parse_cve({"cve": {"id": "CVE-2024-0002", "descriptions": []}})
    assert rec["cvss_score"] is None and rec["cvss_version"] is None and rec["description"] is None
    assert aff == []


def test_epss_parse():
    raw = gzip.compress(b"#model_version:v2025.03.14,score_date:2025-04-01T00:00:00+0000\n"
                        b"cve,epss,percentile\nCVE-2024-0001,0.5,0.9\nbad,x,y\n")
    d, rows = epss.parse_csv(raw)
    assert d == date(2025, 4, 1) and rows == [("CVE-2024-0001", 0.5, 0.9)]


def test_osv_parse_ranges_and_versions():
    pkg = {"ecosystem": "PyPI", "package_name": "foo"}
    rows = osv.parse_vuln({"affected": [
        {"package": {"ecosystem": "PyPI", "name": "foo"},
         "ranges": [{"type": "ECOSYSTEM", "events": [
             {"introduced": "0"}, {"fixed": "1.5"}, {"introduced": "2.0"},
             {"last_affected": "2.3"}, {"introduced": "3.0"}]},
             {"type": "GIT", "events": [{"introduced": "abc"}]}],
         "versions": ["1.0"]},
        {"package": {"name": "no-eco"}}]})
    assert rows == [
        {**pkg, "version_start_including": None, "version_end_excluding": "1.5"},
        {**pkg, "version_start_including": "2.0", "version_end_including": "2.3"},
        {**pkg, "version_start_including": "3.0"},
        {**pkg, "version_exact": "1.0"}]
