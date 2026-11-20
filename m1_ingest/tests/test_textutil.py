from app.textutil import content_hash, detect_language, extract_cve_ids, strip_html


def test_strip_html_keeps_paragraphs_and_entities():
    html = "<p>Hallo&nbsp;<b>Welt</b> &amp; Co</p><script>x()</script><p>Zwei</p>"
    assert strip_html(html) == "Hallo Welt & Co\n\nZwei"


def test_strip_html_empty():
    assert strip_html(None) == ""


def test_hash_is_normalized_and_hex():
    a = content_hash("Patchday  ", "Foo\n bar")
    b = content_hash("patchday", "foo bar")
    assert a == b and len(a) == 64 and a == a.lower()
    assert content_hash("a", "b") != content_hash("a", "c")


def test_extract_cves_dedupes_and_uppercases():
    assert extract_cve_ids("cve-2024-12345, CVE-2024-12345") == ["CVE-2024-12345"]
    assert extract_cve_ids("CVE-2023-00012", "see CVE-2024-1234") == ["CVE-2023-00012", "CVE-2024-1234"]
    assert extract_cve_ids("CVE-2024-123", None, "nothing") == []


def test_detect_language():
    assert detect_language("Kritische Sicherheitslücke in Apache", "Angreifer können Code ausführen.") == "de"
    assert detect_language("Critical vulnerability found in Apache",
                           "Attackers can execute arbitrary code remotely.") == "en"
    assert detect_language("Hi", "", fallback="FR") == "fr"
    assert detect_language("Hi", "", fallback="nonsense!") is None
