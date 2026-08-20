"""Tests for the expanded IOC extraction engine (M8-P2a)."""

from __future__ import annotations

from core.domain.ioc import (
    IocCollection,
    IOCExtractionResult,
    TaggedIndicator,
    extract_iocs,
    extract_iocs_full,
    ioc_statistics,
)


def test_extract_ipv6() -> None:
    iocs = extract_iocs("peer at 2001:0db8:85a3:0000:0000:8a2e:0370:7334 responded")
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" in iocs.ipv6_addresses


def test_extract_jwt() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    iocs = extract_iocs(f"token = {jwt}")
    assert jwt in iocs.jwt_tokens


def test_extract_aws_key() -> None:
    iocs = extract_iocs("config aws_key=AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" in iocs.aws_keys


def test_extract_api_key() -> None:
    iocs = extract_iocs('api_key: "sk_test_abcdef1234567890abcdef"')
    assert any("abcdef1234567890abcdef" in k for k in iocs.api_keys)


def test_extract_discord_webhook() -> None:
    url = "https://discord.com/api/webhooks/123456789/abcdefABCDEF_123"
    iocs = extract_iocs(f"hook = {url}")
    assert url in iocs.discord_webhooks


def test_extract_bitcoin_legacy() -> None:
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    iocs = extract_iocs(f"send to {addr}")
    assert addr in iocs.bitcoin_wallets


def test_extract_bitcoin_bech32() -> None:
    addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    iocs = extract_iocs(f"pay {addr}")
    assert addr in iocs.bitcoin_wallets


def test_ioc_statistics() -> None:
    iocs = extract_iocs("http://evil.com and a@b.com from 10.0.0.1")
    stats = ioc_statistics(iocs)
    assert stats.url_count >= 1
    assert stats.email_count >= 1
    assert stats.total == iocs.total


def test_extraction_result_full() -> None:
    result = extract_iocs_full("http://evil.com", source="file", artifact_id="abc")
    assert isinstance(result, IOCExtractionResult)
    assert result.source == "file"
    assert result.artifact_id == "abc"
    assert result.statistics.url_count >= 1


def test_tagged_indicators_have_stable_ids() -> None:
    iocs = extract_iocs("http://evil.com")
    tagged = iocs.tagged()
    assert len(tagged) >= 1
    assert all(isinstance(t, TaggedIndicator) for t in tagged)
    assert all(t.ioc_id for t in tagged)
    # Same indicator always produces the same ID
    tagged2 = extract_iocs("http://evil.com").tagged()
    assert tagged[0].ioc_id == tagged2[0].ioc_id


def test_merged_with_includes_new_fields() -> None:
    a = IocCollection(jwt_tokens=("j1",), aws_keys=("k1",))
    b = IocCollection(jwt_tokens=("j2",), bitcoin_wallets=("b1",))
    merged = a.merged_with(b)
    assert set(merged.jwt_tokens) == {"j1", "j2"}
    assert merged.aws_keys == ("k1",)
    assert merged.bitcoin_wallets == ("b1",)
    assert merged.total == 4


def test_total_includes_all_new_fields() -> None:
    c = IocCollection(
        ipv6_addresses=("::1",),
        jwt_tokens=("j",),
        aws_keys=("k",),
        api_keys=("a",),
        discord_webhooks=("d",),
        bitcoin_wallets=("b",),
    )
    assert c.total == 6
