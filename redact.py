#!/usr/bin/env python3
"""Deterministic redaction for log evidence sent to a hosted LLM.

The reports this service produces are useful precisely because they quote real
log lines, and real log lines carry credentials: bearer tokens a service logged
on error, a connection string with its password, an API key echoed by a failing
health check. Every one of those goes to whichever provider the active profile
names -- for a hosted profile, that means off the machine entirely.

Two design choices keep the report just as good while the provider sees none of
it:

  DROP           secrets. Tokens, keys, passwords, JWTs, PEM blocks. Replaced by
                 [[REDACTED-<kind>]] and gone. Nothing is learned from knowing a
                 token recurred, so nothing is lost.

  PSEUDONYMIZE   identifiers. Hosts, IPs, emails, MACs, container ids become
                 stable names (HOST_A, IP_3) that are consistent across the
                 whole prompt. This is the part that avoids nerfing the report:
                 log analysis is correlation, and the model still sees that the
                 same host appears in two streams four seconds apart. Blanket
                 [REDACTED] would destroy exactly the signal it is asked to
                 find.

The mapping never leaves the process, and the model's answer is mapped back
before the report is written, so a human still reads real hostnames.

Redaction is code rather than a model instruction on purpose: a model told to
"remove anything sensitive" is a model you are trusting with the thing you are
protecting, and a miss is silent.

Host names are harvested from the Loki stream labels rather than configured, so
this stays generic -- nothing about any particular deployment lives here.

Disable with REDACT_EVIDENCE=0 (not recommended for a hosted provider).
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from typing import Any

SECRET_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("private-key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("vault", re.compile(
        r"\$ANSIBLE_VAULT;[0-9.]+;[A-Z0-9]+(?:\s*\n?\s*[0-9a-f]{40,})+")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+")),
    ("auth-header", re.compile(
        r"(?i)\b(authorization|proxy-authorization)\s*[:=]\s*[\"']?"
        r"(?:bearer|basic|token|digest)?\s*[A-Za-z0-9._\-+/=]{8,}[\"']?")),
    ("url-credential", re.compile(r"\b([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@")),
    ("webhook", re.compile(
        r"(?i)\bhttps?://[^\s\"']*/(?:webhook|hooks?)/[A-Za-z0-9._\-]{12,}")),
    # Named like a credential, whatever the value looks like. Catches shapes
    # nobody anticipated, which is most of them.
    ("named-secret", re.compile(
        r"(?i)\b([a-z0-9_.\-]*"
        r"(?:token|secret|passwd|password|pwd|api[_-]?key|apikey|access[_-]?key|"
        r"private[_-]?key|credential|client[_-]?secret|auth)"
        r"[a-z0-9_.\-]*)\s*[:=]\s*[\"']?([^\s\"',;]{4,})[\"']?")),
    ("vendor-key", re.compile(
        r"\b(?:sk-[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|"
        r"xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})")),
]

MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
HEXID_RE = re.compile(r"\b[0-9a-f]{12,64}\b")
# person.sarah / device_tracker.jon - real names in a structural shape.
PERSON_ENTITY_RE = re.compile(r"\b(person|device_tracker|notify)\.([a-z0-9_]+)\b")

REDACTED_RE = re.compile(r"\[\[REDACTED-[a-z-]+\]\]")
PLACEHOLDER_RE = re.compile(
    r"\b(?:HOST_[A-Z]+|IP_\d+|MAC_\d+|EMAIL_\d+|ID_\d+|PERSON_\d+)\b"
    r"|\[\[REDACTED-[a-z-]+\]\]")

# Structurally identifiers, but hiding them only makes the report harder to read.
IP_KEEP = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "8.8.8.8", "1.1.1.1"}
# Label values that are not hostnames and must stay legible: the model needs to
# know a line came from Loki or Grafana to reason about it at all.
LABEL_KEYS_FOR_HOSTS = ("host", "hostname", "node")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class Redactor:
    """Scrub text before it is sent, restore pseudonyms in what comes back."""

    def __init__(self, host_hints: list[str] | None = None, enabled: bool = True):
        self.enabled = enabled
        self.maps: dict[str, dict[str, str]] = {}
        self.host_hints = sorted(
            {h for h in (host_hints or []) if h and len(h) > 2},
            key=len, reverse=True)

    @classmethod
    def from_entries(cls, entries: list, enabled: bool | None = None) -> "Redactor":
        """Build from the stream labels just fetched - no configuration needed."""
        if enabled is None:
            enabled = os.getenv("REDACT_EVIDENCE", "1").strip().lower() not in {
                "0", "false", "no", "off"}
        hosts: set[str] = set()
        for entry in entries:
            labels = getattr(entry, "labels", {}) or {}
            for key in LABEL_KEYS_FOR_HOSTS:
                value = labels.get(key)
                if value:
                    hosts.add(str(value))
        return cls(sorted(hosts), enabled=enabled)

    # ------------------------------------------------------------------ names

    def _name(self, kind: str, value: str) -> str:
        bucket = self.maps.setdefault(kind, {})
        if value in bucket:
            return bucket[value]
        n = len(bucket) + 1
        if kind == "host":
            label, m = "", n
            while m:
                m, r = divmod(m - 1, 26)
                label = chr(65 + r) + label
            token = f"HOST_{label}"
        else:
            token = f"{kind.upper()}_{n}"
        bucket[value] = token
        return token

    # ----------------------------------------------------------------- scrub

    def scrub(self, text: str) -> str:
        if not self.enabled or not text:
            return text
        text = self._drop_secrets(text)
        text = self._pseudonymize(text)
        text = self._sweep_entropy(text)
        return text

    def _drop_secrets(self, text: str) -> str:
        for kind, pattern in SECRET_RULES:
            def repl(m: re.Match[str], _k: str = kind) -> str:
                if REDACTED_RE.search(m.group(0)):
                    return m.group(0)
                if _k == "named-secret":
                    return f"{m.group(1)}=[[REDACTED-{_k}]]"
                if _k == "url-credential":
                    return f"{m.group(1)}[[REDACTED-{_k}]]@"
                return f"[[REDACTED-{_k}]]"
            text = pattern.sub(repl, text)
        return text

    def _pseudonymize(self, text: str) -> str:
        def guard(fn):
            def wrapped(m: re.Match[str]) -> str:
                return m.group(0) if PLACEHOLDER_RE.fullmatch(m.group(0)) else fn(m)
            return wrapped

        for host in self.host_hints:
            pattern = re.compile(
                rf"(?<![A-Za-z0-9._-])({re.escape(host)})(?![A-Za-z0-9-])", re.IGNORECASE)
            text = pattern.sub(lambda m, _h=host: self._name("host", _h), text)

        def person(m: re.Match[str]) -> str:
            if PLACEHOLDER_RE.fullmatch(m.group(2)):
                return m.group(0)
            return f"{m.group(1)}.{self._name('person', m.group(2).lower())}"
        text = PERSON_ENTITY_RE.sub(person, text)

        text = EMAIL_RE.sub(guard(lambda m: self._name("email", m.group(0).lower())), text)
        text = MAC_RE.sub(guard(lambda m: self._name("mac", m.group(0).lower())), text)

        def ipv4(m: re.Match[str]) -> str:
            v = m.group(0)
            if v in IP_KEEP or any(int(o) > 255 for o in v.split(".")):
                return v
            return self._name("ip", v)
        text = IPV4_RE.sub(guard(ipv4), text)

        text = HEXID_RE.sub(guard(lambda m: self._name("id", m.group(0).lower())), text)
        return text

    def _sweep_entropy(self, text: str, threshold: float = 3.6) -> str:
        def repl(m: re.Match[str]) -> str:
            s = m.group(0)
            if PLACEHOLDER_RE.fullmatch(s):
                return s
            if not (re.search(r"[A-Za-z]", s) and re.search(r"\d", s)):
                return s
            if re.fullmatch(r"[0-9a-f]+", s) or _entropy(s) < threshold:
                return s
            return "[[REDACTED-high-entropy]]"
        return re.compile(r"\b[A-Za-z0-9+/_=-]{24,}\b").sub(repl, text)

    # --------------------------------------------------------------- restore

    def _inverse(self) -> dict[str, str]:
        return {tok: val for bucket in self.maps.values() for val, tok in bucket.items()}

    def restore(self, text: str) -> str:
        """Map pseudonyms back, so the human report names real hosts."""
        if not self.enabled or not text:
            return text
        inverse = self._inverse()
        for token in sorted(inverse, key=len, reverse=True):
            text = re.sub(rf"\b{re.escape(token)}\b", inverse[token], text)
        return text

    def restore_obj(self, value: Any) -> Any:
        """restore() over every string in a parsed LLM response."""
        if not self.enabled:
            return value
        if isinstance(value, str):
            return self.restore(value)
        if isinstance(value, list):
            return [self.restore_obj(item) for item in value]
        if isinstance(value, dict):
            return {key: self.restore_obj(item) for key, item in value.items()}
        return value

    # ------------------------------------------------------------------ audit

    def residual_risks(self, text: str) -> list[str]:
        """Advisory check: what still looks dangerous after scrubbing."""
        risks = []
        for kind, pattern in SECRET_RULES:
            if any(not REDACTED_RE.search(m.group(0)) for m in pattern.finditer(text)):
                risks.append(kind)
        return risks

    def summary(self) -> dict[str, int]:
        return {kind: len(bucket) for kind, bucket in sorted(self.maps.items())}
