"""URL feature extraction.

Transforms a validated URL into the lexical and structural features defined by
the Feature Engineering Specification. The pipeline is deterministic,
reproducible, and independent of any downstream model - it uses only the
standard library.
"""

from __future__ import annotations

import math
from collections import Counter

from core.domain.analysis import FeatureValue
from core.domain.url import Url

_SHORTENER_HOSTS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "adf.ly",
        "cutt.ly",
        "rebrand.ly",
        "shorturl.at",
    }
)

_SUSPICIOUS_KEYWORDS = (
    "login",
    "signin",
    "verify",
    "account",
    "update",
    "secure",
    "banking",
    "confirm",
    "password",
    "credential",
    "webscr",
    "ebayisapi",
    "invoice",
    "wallet",
    "suspend",
)

_SPECIAL_CHARS = set("-_.~:/?#[]@!$&'()*+,;=%")


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _subdomain_count(url: Url) -> int:
    if url.is_ip_host:
        return 0
    labels = url.host.split(".")
    # Everything above the registered domain + TLD counts as a subdomain.
    return max(0, len(labels) - 2)


def _digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(c.isdigit() for c in text) / len(text)


def extract_features(url: Url) -> dict[str, FeatureValue]:
    """Extract the URL feature vector.

    Args:
        url: The validated URL.

    Returns:
        A mapping of feature name to value (lexical and structural features).
    """
    raw = url.raw
    lowered = raw.lower()

    features: dict[str, FeatureValue] = {
        # Lexical
        "url_length": len(raw),
        "hostname_length": len(url.host),
        "path_length": len(url.path),
        "query_length": len(url.query),
        "fragment_length": len(url.fragment),
        "digit_count": sum(c.isdigit() for c in raw),
        "alphabet_count": sum(c.isalpha() for c in raw),
        "special_char_count": sum(c in _SPECIAL_CHARS for c in raw),
        "hyphen_count": raw.count("-"),
        "underscore_count": raw.count("_"),
        "dot_count": raw.count("."),
        "slash_count": raw.count("/"),
        "question_mark_count": raw.count("?"),
        "equal_count": raw.count("="),
        "ampersand_count": raw.count("&"),
        "at_symbol_present": "@" in raw,
        "url_entropy": round(_shannon_entropy(raw), 4),
        # Structural
        "https_used": url.uses_https,
        "ip_address_used": url.is_ip_host,
        "subdomain_count": _subdomain_count(url),
        "shortened_url": url.host.lower() in _SHORTENER_HOSTS,
        "encoded_characters": raw.count("%"),
        "suspicious_keywords": sum(kw in lowered for kw in _SUSPICIOUS_KEYWORDS),
        "host_digit_ratio": round(_digit_ratio(url.host), 4),
    }
    return features


# Ordered feature names for the machine-learning model. Training and inference
# both build vectors from this list, guaranteeing column alignment.
MODEL_FEATURE_NAMES: tuple[str, ...] = (
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "digit_count",
    "alphabet_count",
    "special_char_count",
    "hyphen_count",
    "underscore_count",
    "dot_count",
    "slash_count",
    "question_mark_count",
    "equal_count",
    "ampersand_count",
    "at_symbol_present",
    "url_entropy",
    "https_used",
    "ip_address_used",
    "subdomain_count",
    "shortened_url",
    "encoded_characters",
    "suspicious_keywords",
    "host_digit_ratio",
)


def feature_vector(features: dict[str, FeatureValue]) -> list[float]:
    """Convert a feature mapping to an ordered numeric vector for the model."""
    return [float(features[name]) for name in MODEL_FEATURE_NAMES]
