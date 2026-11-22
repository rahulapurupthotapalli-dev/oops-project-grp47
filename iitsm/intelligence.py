"""Intelligent features: duplicate detection and automatic category suggestion (rule-based NLP)."""
import re

from .exceptions import InvalidInput

_STOP = {"the", "a", "an", "is", "are", "to", "of", "in", "on", "for", "and", "my", "our", "not", "make",
         "with", "from", "it", "be", "users", "user", "application", "app"}
_SYNONYMS = {"unavailable": "down", "unable": "down", "failing": "down", "failed": "down", "fails": "down",
             "outage": "down", "crashed": "down", "payments": "payment"}


def _words(text): return re.findall(r"[a-z]+", text.lower())
def _tokens(text): return {_SYNONYMS.get(w, w) for w in _words(text)} - _STOP


class DuplicateDetector:
    """Jaccard similarity on normalised tokens; only open incidents on the same service are compared."""
    def __init__(self, threshold: float = 0.5): self.threshold = threshold

    def find(self, description: str, candidates) -> list:
        a, hits = _tokens(description), []
        for other in candidates:
            b = _tokens(other.description)
            score = len(a & b) / len(a | b) if a | b else 0.0
            if score >= self.threshold:
                hits.append((other, score))
        return sorted(hits, key=lambda x: -x[1])


class CategoryCatalog:
    """Open for extension: admins register new categories (with keywords) at runtime."""
    DEFAULTS = {
        "NETWORK": {"wifi", "network", "vpn", "internet", "router", "latency"},
        "DATABASE": {"database", "sql", "query", "db"},
        "AUTHENTICATION": {"login", "password", "sso", "authentication", "otp"},
        "HARDWARE": {"laptop", "printer", "keyboard", "monitor", "mouse"},
        "SECURITY": {"phishing", "malware", "breach", "virus"},
        "STORAGE": {"storage", "disk", "bucket", "backup"},
        "CLOUD": {"cloud", "aws", "azure", "instance"},
        "APPLICATION": {"application", "app", "payment", "crash", "portal", "transaction"},
        "SOFTWARE": {"install", "software", "license", "update"},
        "GENERAL": set(),
    }

    def __init__(self): self._kw = {k: set(v) for k, v in self.DEFAULTS.items()}
    def register(self, name: str, keywords=()): self._kw[name.upper()] = {k.lower() for k in keywords}
    def names(self): return sorted(self._kw)

    def require(self, name: str) -> str:
        if name.upper() not in self._kw:
            raise InvalidInput(f"unknown category {name}")
        return name.upper()

    def suggest(self, description: str) -> str:
        words = set(_words(description))
        scores = {c: len(words & kw) for c, kw in self._kw.items() if kw}
        best = max(scores.values(), default=0)
        winners = [c for c, s in scores.items() if s == best and s > 0]
        return winners[0] if len(winners) == 1 else "GENERAL"
