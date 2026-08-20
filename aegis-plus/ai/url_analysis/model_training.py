"""URL model training (demonstration model).

Trains a LightGBM URL classifier on a **synthetic dataset** and writes the
booster artifact that the infrastructure loader serves at runtime. This model is
a **demonstration of the ML infrastructure** — it validates the end-to-end
pipeline (training → artifact → loader → analyzer → SHAP explanations → hybrid
evidence → persistence → UI) but is **not a production-quality phishing
classifier**. The synthetic data lacks the diversity, adversarial variety, and
real-world distribution of actual phishing URLs, and no held-out evaluation has
been performed.

When a real labelled dataset becomes available, replace ``build_dataset()`` with
a corpus loader, add a train/validation/test split, compute evaluation metrics,
and write the booster to the same path. All downstream components (analyzer,
hybrid engine, evidence model, API, UI) work unchanged.

Run as a module to (re)generate the demonstration artifact::

    python -m ai.url_analysis.model_training
"""

from __future__ import annotations

import random
from pathlib import Path

from ai.url_analysis.features import extract_features, feature_vector
from core.domain.url import Url

_SEED = 20260721
_SAMPLES_PER_CLASS = 1200
_HTTPS_PROBABILITY = 0.95
_IP_STYLE_CUTOFF = 0.3
_SHORTENER_STYLE_CUTOFF = 0.5

_BENIGN_HOSTS = (
    "www.google.com",
    "en.wikipedia.org",
    "github.com",
    "www.microsoft.com",
    "news.ycombinator.com",
    "www.python.org",
    "stackoverflow.com",
    "www.bbc.co.uk",
    "docs.aws.amazon.com",
    "www.nytimes.com",
)
_BENIGN_PATHS = ("", "/", "/about", "/products/item", "/blog/2026/post", "/search?q=news")
_BAD_WORDS = (
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "banking",
    "signin",
    "webscr",
)
_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly")


def _benign_url(rng: random.Random) -> str:
    scheme = "https" if rng.random() < _HTTPS_PROBABILITY else "http"
    host = rng.choice(_BENIGN_HOSTS)
    path = rng.choice(_BENIGN_PATHS)
    return f"{scheme}://{host}{path}"


def _phishing_url(rng: random.Random) -> str:
    style = rng.random()
    words = "-".join(rng.sample(_BAD_WORDS, k=rng.randint(2, 4)))
    if style < _IP_STYLE_CUTOFF:
        octets = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        return f"http://{octets}/{words}@secure.example.com/signin?password=1"
    if style < _SHORTENER_STYLE_CUTOFF:
        return f"http://{rng.choice(_SHORTENERS)}/{rng.randint(1000, 9999)}"
    subdomains = ".".join(rng.sample(_BAD_WORDS, k=rng.randint(3, 5)))
    tld = rng.choice(("example.com", "verify-login.top", "account-update.xyz"))
    return f"http://{subdomains}.{tld}/{words}?token={rng.randint(10000, 99999)}"


def build_dataset() -> tuple[list[list[float]], list[int]]:
    """Generate the synthetic training set of feature vectors and labels."""
    rng = random.Random(_SEED)
    vectors: list[list[float]] = []
    labels: list[int] = []
    for _ in range(_SAMPLES_PER_CLASS):
        for maker, label in ((_benign_url, 0), (_phishing_url, 1)):
            url = Url.create(maker(rng))
            vectors.append(feature_vector(extract_features(url)))
            labels.append(label)
    return vectors, labels


def train_and_save(output_path: Path) -> Path:
    """Train the classifier and save the booster to ``output_path``.

    Args:
        output_path: Destination for the LightGBM booster text model.

    Returns:
        The path written.
    """
    import lightgbm as lgb
    import numpy as np

    vectors, labels = build_dataset()
    dataset = lgb.Dataset(np.asarray(vectors, dtype=float), label=np.asarray(labels))
    params = {
        "objective": "binary",
        "metric": "binary_logloss",
        "num_leaves": 31,
        "learning_rate": 0.1,
        "min_data_in_leaf": 20,
        "feature_pre_filter": False,
        "verbose": -1,
        "seed": _SEED,
    }
    booster = lgb.train(params, dataset, num_boost_round=120)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(output_path))
    return output_path


if __name__ == "__main__":
    from config import ProjectPaths

    paths = ProjectPaths.create()
    written = train_and_save(paths.models_dir / "url_lightgbm.txt")
    print(f"Model written to {written}")
