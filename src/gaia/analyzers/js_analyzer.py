"""Noise-reduced JavaScript analyzer for endpoints, URLs, and secrets."""

from __future__ import annotations

import re
from typing import Dict, List, Set

# ==================== NOISE FILTERS ====================

NOISE_DOMAINS = {
    "schema.org",
    "www.w3.org",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "cloudflare.com",
    "cdnjs.cloudflare.com",
    "gstatic.com",
    "wikipedia.org",
    # XML namespaces and standards
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "purl.org",
    "purl.oclc.org",
    "openoffice.org",
    "docs.oasis-open.org",
    "sheetjs.openxmlformats.org",
    "ns.adobe.com",
    "www.xml.org",
    # Test/placeholder domains
    "example.com",
    "test.com",
    "localhost",
    "127.0.0.1",
    # Library-specific
    "fusioncharts.com",
    "jspdf.default.namespaceuri",
    "npmjs.org",
    "registry.npmjs.org",
    "jqwidgets.com",
    "ag-grid.com",
}

NOISE_STRINGS = {
    "data:",
    "javascript:",
    "xmlns",
    "sourceMappingURL",
    "http://",
    "https://",
    "/a",
    "/P",
    "/R",
    "/V",
    "/W",
    "zone.js",
    "bn.js",
    "hash.js",
    "md5.js",
    "sha.js",
    "des.js",
    "asn1.js",
    "declare.js",
    "elliptic.js",
}

MODULE_PREFIXES = (
    "./",
    "../",
    ".../",
    "./lib",
    "../lib",
    "./utils",
    "../utils",
    "./node_modules",
    "../node_modules",
    "./src",
    "../src",
    "./dist",
    "../dist",
    "module:",
    "webpack:",
)

# Patterns that are clearly internal JS/build artifacts
NOISE_PATTERNS = [
    re.compile(r"^\.\.?/"),  # Starts with ./ or ../
    re.compile(r"^[a-z]{2}(-[a-z]{2})?\.js$"),  # Locale files: en.js, en-gb.js
    re.compile(r"^[a-z]{2}(-[a-z]{2})?$"),  # Just locale: en, en-gb
    re.compile(r"-xform$"),  # Excel xform modules
    re.compile(r"^sha\d*$"),  # sha, sha1, sha256
    re.compile(r"^aes$|^des$|^md5$"),  # Crypto modules
    # PDF internal structure
    re.compile(r"^/[A-Z][a-z]+\s"),  # /Type /Font, /Filter /Standard
    re.compile(r"^/[A-Z][a-z]+$"),  # /Parent, /Kids, /Resources
    re.compile(r"^\d+ \d+ R$"),  # PDF object references
    # Excel/XML internal paths
    re.compile(r"^xl/"),  # Excel internal
    re.compile(r"^docProps/"),  # Document properties
    re.compile(r"^_rels/"),  # Relationships
    re.compile(r"^META-INF/"),  # Manifest
    re.compile(r"\.xml$"),  # XML files
    re.compile(r"^worksheets/"),
    re.compile(r"^theme/"),
    # Build/bundler artifacts
    re.compile(r"^webpack"),
    re.compile(r"^zone\.js$"),
    re.compile(r"^readable-stream/"),
    re.compile(r"^process/"),
    re.compile(r"^stream/"),
    re.compile(r"^buffer$"),
    re.compile(r"^events$"),
    re.compile(r"^util$"),
    re.compile(r"^path$"),
    # Generic noise
    re.compile(r"^\+"),  # Starts with +
    re.compile(r"^\$\{"),  # Template literal
    re.compile(r"^#"),  # Fragment only
    re.compile(r"^\?\ref="),
    re.compile(r"^/[a-z]$"),  # Single letter paths
    re.compile(r"^/[A-Z]$"),  # Single letter paths
    re.compile(r"^http://$"),  # Empty http://
    re.compile(r"_ngcontent"),  # Angular internals
    # Regex route patterns (not real paths)
    re.compile(r"[\[\]\(\)\*\+\?\^\$\|\\]"),  # Contains regex metacharacters
    re.compile(r"^/\$$"),  # Just /$
    re.compile(r"^/\*$"),  # Just /*
]

# ==================== ENDPOINT PATTERNS ====================

# Specific API endpoint patterns (high value targets)
SPECIFIC_ENDPOINT_PATTERNS = [
    # API endpoints
    re.compile(r'["\']((?:https?:)?//[^"\']+/api/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/api/v?\d*/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/v\d+/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/rest/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/graphql[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    # OAuth/Auth endpoints
    re.compile(r'["\'](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/auth[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/login[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/logout[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/token[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    # Sensitive paths
    re.compile(r'["\'](/admin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/dashboard[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/internal[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/debug[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/config[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/backup[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/private[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/upload[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/download[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    # Well-known paths
    re.compile(r'["\'](/\.well-known/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/idp/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
]

# General endpoint pattern (fallback)
ENDPOINT_PATTERN = re.compile(r"""["'](/[^"'\s<>]{1,200})["']""")

# ==================== URL PATTERNS ====================

URL_PATTERN = re.compile(r"""(https?://[^\s"'<>]+|wss?://[^\s"'<>]+|sftp://[^\s"'<>]+|ftp://[^\s"'<>]+|gs://[^\s"'<>]+)""")
SCHEMELESS_URL_PATTERN = re.compile(r"""//[^\s"'<>]+""")

# Cloud storage specific patterns
CLOUD_STORAGE_PATTERNS = [
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://storage\.googleapis\.com/[^\s"\'<>]*)'),
]

EMAIL_PATTERN = re.compile(r"""[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}""")

# ==================== SECRET PATTERNS ====================

SECRET_PATTERNS = [
    # Cloud providers
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("google_oauth2_token", re.compile(r"\b(ya29\.[a-z0-9_-]{30,})\b", re.IGNORECASE)),
    # Payment
    ("stripe_live_key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    # Code hosting
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{36,}")),
    # Communication
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    # Auth tokens
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    # Databases
    ("mongodb_uri", re.compile(r"mongodb(?:\+srv)?://[^\s\"'<>]+")),
    ("postgresql_uri", re.compile(r"postgres(?:ql)?://[^\s\"'<>]+")),
    ("mysql_uri", re.compile(r"mysql://[a-z0-9._%+\-]+:[^\s:@]+@(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{2,5})?(?:/[^\s\"'?:]+)?(?:\?[^\s\"']*)?", re.IGNORECASE)),
    # Search/Analytics
    ("algolia_admin_key", re.compile(r"(?i)algolia.{0,32}([a-z0-9]{32})\b")),
    ("algolia_app_id", re.compile(r"(?i)algolia.{0,16}([A-Z0-9]{10})\b")),
    ("segment_public_token", re.compile(r"\b(sgp_[A-Z0-9_-]{60,70})\b")),
    ("segment_api_key", re.compile(r"(?i)(?:segment|sgmt).{0,16}(?:secret|private|access|key|token).{0,16}([A-Z0-9_-]{40,50}\.[A-Z0-9_-]{40,50})")),
    # CDN/Infrastructure
    ("cloudflare_api_token", re.compile(r"(?i)cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_-]{38,42})\b")),
    ("cloudflare_service_key", re.compile(r"(?i)(?:cloudflare|x-auth-user-service-key).{0,64}(v1\.0-[a-z0-9._-]{160,})\b")),
    # Social
    ("facebook_app_id", re.compile(r"(?i)(?:facebook|fb).{0,8}(?:app|application).{0,16}(\d{15})\b")),
    ("facebook_secret_key", re.compile(r"(?i)(?:facebook|fb).{0,32}(?:api|app|application|client|consumer|secret|key).{0,32}([a-z0-9]{32})\b")),
    ("facebook_access_token", re.compile(r"(EAACEdEose0cBA[A-Z0-9]{20,})\b")),
]

# ==================== FILE PATTERNS ====================

FILE_PATTERN = re.compile(
    r"""["']([a-zA-Z0-9_/.-]+\.(?:"""
    r"sql|csv|xlsx|xls|json|xml|yaml|yml|"  # Data files
    r"txt|log|conf|config|cfg|ini|env|"  # Config/logs
    r"bak|backup|old|orig|copy|"  # Backups
    r"key|pem|crt|cer|p12|pfx|"  # Certificates
    r"doc|docx|pdf|"  # Documents
    r"zip|tar|gz|rar|7z|"  # Archives
    r"sh|bat|ps1|py|rb|pl"  # Scripts
    r"""))["']""",
    re.IGNORECASE,
)


# ==================== VALIDATION FUNCTIONS ====================

def _contains_noise(value: str) -> bool:
    lower = value.lower()
    if any(s in lower for s in NOISE_STRINGS):
        return True
    return False


def _matches_noise_pattern(value: str) -> bool:
    """Check if value matches any noise pattern."""
    for pattern in NOISE_PATTERNS:
        if pattern.search(value):
            return True
    return False


def is_valid_endpoint(value: str) -> bool:
    if not value or not value.startswith("/"):
        return False
    # Minimum meaningful length: at least /xx
    if len(value) < 2:
        return False
    # Just root path with nothing else is too generic
    if value == "/":
        return False
    if value.startswith(MODULE_PREFIXES):
        return False
    if _contains_noise(value):
        return False
    if _matches_noise_pattern(value):
        return False
    # Filter out regex metacharacters that indicate route patterns, not real paths
    if any(ch in value for ch in ("{", "}", "<", ">", " ", "(", ")", "[", "]", "*", "^", "$", "+", "?", "|", "\\")):
        return False
    return True


def is_valid_url(value: str) -> bool:
    if not value or _contains_noise(value):
        return False
    lower = value.lower()
    for d in NOISE_DOMAINS:
        if d in lower:
            return False
    return True


def is_valid_secret(value: str) -> bool:
    return bool(value) and len(value) >= 12 and not value.lower().startswith("placeholder")


def is_valid_email(value: str) -> bool:
    if not value:
        return False
    if value.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".svg")):
        return False
    return True


def is_valid_file(value: str) -> bool:
    if not value:
        return False
    if value.startswith(MODULE_PREFIXES):
        return False
    if _matches_noise_pattern(value):
        return False
    return True


def _mask_secret(value: str) -> str:
    if len(value) <= 14:
        return value
    return f"{value[:10]}...{value[-4:]}"


# ==================== MAIN ANALYSIS FUNCTION ====================

def analyze_js(js_text: str, source_url: str, base_url: str | None = None) -> Dict[str, object]:
    endpoints: Set[str] = set()
    urls: Set[str] = set()
    secrets: List[Dict[str, str]] = []
    emails: Set[str] = set()
    files: Set[str] = set()

    if not js_text:
        return {
            "endpoints": endpoints,
            "urls": urls,
            "secrets": secrets,
            "emails": emails,
            "files": files,
        }

    # Extract specific high-value endpoints first
    for pattern in SPECIFIC_ENDPOINT_PATTERNS:
        for match in pattern.findall(js_text):
            if is_valid_endpoint(match):
                endpoints.add(match)

    # General endpoint extraction
    for match in ENDPOINT_PATTERN.findall(js_text):
        if is_valid_endpoint(match):
            endpoints.add(match)

    # URL extraction
    for match in URL_PATTERN.findall(js_text):
        if is_valid_url(match):
            urls.add(match)

    for match in SCHEMELESS_URL_PATTERN.findall(js_text):
        if is_valid_url(match):
            urls.add("https:" + match)

    # Cloud storage URLs
    for pattern in CLOUD_STORAGE_PATTERNS:
        for match in pattern.findall(js_text):
            if is_valid_url(match):
                urls.add(match)

    # Email extraction
    for match in EMAIL_PATTERN.findall(js_text):
        if is_valid_email(match):
            emails.add(match)

    # File reference extraction
    for match in FILE_PATTERN.findall(js_text):
        if is_valid_file(match):
            files.add(match)

    # Secret extraction
    for name, pat in SECRET_PATTERNS:
        for m in pat.findall(js_text):
            if is_valid_secret(m):
                secrets.append(
                    {"type": name, "value": _mask_secret(m), "source": source_url}
                )

    return {
        "endpoints": endpoints,
        "urls": urls,
        "secrets": secrets,
        "emails": emails,
        "files": files,
    }


__all__ = ["analyze_js"]
