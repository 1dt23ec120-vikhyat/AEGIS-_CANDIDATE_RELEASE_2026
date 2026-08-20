"""Unit tests for the platform IOC extraction engine."""

from __future__ import annotations

from core.domain.ioc import IocCollection, extract_iocs, refang


def test_refang_restores_defanged_indicators() -> None:
    assert refang("hxxps://evil[.]com") == "https://evil.com"
    assert refang("visit hxxp://a[dot]b[.]com") == "visit http://a.b.com"


def test_extract_urls_ips_emails() -> None:
    text = "Visit http://evil.example.com/login, mail a@b.com, from 203.0.113.5"
    iocs = extract_iocs(text)
    assert "http://evil.example.com/login" in iocs.urls
    assert "a@b.com" in iocs.emails
    assert "203.0.113.5" in iocs.ipv4_addresses


def test_extract_defanged_url() -> None:
    iocs = extract_iocs("payload from hxxp://malware[.]bad/dropper")
    assert "http://malware.bad/dropper" in iocs.urls


def test_extract_hashes_by_length() -> None:
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    iocs = extract_iocs(f"{sha256} {sha1} {md5}")
    assert sha256 in iocs.hashes
    assert sha1 in iocs.hashes
    assert md5 in iocs.hashes


def test_domains_covered_by_urls_are_not_duplicated() -> None:
    iocs = extract_iocs("http://evil.example.com/x and bare.example.org")
    assert "bare.example.org" in iocs.domains
    assert "evil.example.com" not in iocs.domains


def test_empty_text_returns_empty_collection() -> None:
    iocs = extract_iocs("")
    assert iocs.is_empty
    assert iocs.total == 0


def test_dedup_preserves_order() -> None:
    iocs = extract_iocs("http://a.com http://a.com http://b.com")
    assert iocs.urls == ("http://a.com", "http://b.com")


def test_merged_with_combines_and_dedupes() -> None:
    first = extract_iocs("http://a.com from 10.0.0.1")
    second = extract_iocs("http://a.com and http://c.com")
    merged = first.merged_with(second)
    assert set(merged.urls) == {"http://a.com", "http://c.com"}
    assert "10.0.0.1" in merged.ipv4_addresses


def test_ioc_collection_total() -> None:
    collection = IocCollection(urls=("http://a",), emails=("a@b.com",), hashes=("abc",))
    assert collection.total == 3
