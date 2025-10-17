"""Reusable regex patterns and keyword lists for SNI detectors."""
from __future__ import annotations

import re
from typing import Mapping

ENDPOINT_PATTERN = re.compile(r"(?P<url>(?:https?|wss?)://[^\s\"'<>]+)")
AWS_ACCESS_KEY = re.compile(r"A(?:KI|SI)A[0-9A-Z]{16}")
AWS_SECRET_KEY = re.compile(r"(?<![A-Z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")
AUTH_KEYWORDS = {"auth", "oauth", "token", "bearer", "hmac", "secret", "signin"}
GRAPHQL_HINT = re.compile(r"(?:/graphql|\"query\"\s*:\s*\")", re.IGNORECASE)
GRPC_HINT = re.compile(r"\":authority\"|\":path\"", re.IGNORECASE)
REDIRECTOR_HOSTS = {"t.co", "bit.ly", "goo.gl", "tinyurl.com", "lnkd.in"}
AUTH_HEADER_PATTERN = re.compile(r"Authorization\s*[:=]\s*[\"']?(?P<token>[A-Za-z0-9._-]{16,})", re.IGNORECASE)
BEARER_PATTERN = re.compile(r"Bearer\s+(?P<token>[A-Za-z0-9._-]{16,})", re.IGNORECASE)
JWT_PATTERN = re.compile(r"(?P<token>[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")
CLOUD_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "aws_s3_host": re.compile(r"(?P<bucket>[a-z0-9.-]+)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com"),
    "aws_s3_uri": re.compile(r"s3://(?P<bucket>[a-z0-9._-]+)/?"),
    "gcs_host": re.compile(r"storage.googleapis.com/(?P<bucket>[a-z0-9._-]+)/?"),
    "gcs_uri": re.compile(r"gs://(?P<bucket>[a-z0-9._-]+)/?"),
    "firebase_project": re.compile(r"(?P<project>[a-z0-9-]+)\.firebase(?:io|app)\.com"),
    "firebase_storage": re.compile(r"firebasestorage.googleapis.com/v0/b/(?P<bucket>[a-z0-9._-]+)/?"),
}
BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/=]{32,256}")
KEYWORD_LOOKUP = re.compile(r"secret|token|hmac|aes|bearer|auth", re.IGNORECASE)
INTERNAL_SUFFIXES = {"lan", "local", "corp", "internal"}
FEATURE_KEYWORDS = ("feature", "flag", "toggle", "remote_config")
