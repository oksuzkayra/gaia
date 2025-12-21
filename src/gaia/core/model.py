"""Domain models and enums used across Gaia."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


class EndpointType(str, Enum):
    api = "api"
    page = "page"
    asset = "asset"
    internal = "internal"
    debug = "debug"
    auth = "auth"
    other = "other"


class RiskType(str, Enum):
    idor = "idor"
    ssrf = "ssrf"
    open_redirect = "open_redirect"
    business_logic = "business_logic"
    misconfiguration = "misconfiguration"
    xss = "xss"
    sqli = "sqli"
    crlf = "crlf"
    ssti = "ssti"
    csti = "csti"
    lfi = "lfi"
    rfi = "rfi"
    xxe = "xxe"
    cmdi = "cmdi"
    rce = "rce"
    upload = "upload"
    rate_limit = "rate_limit"
    path_traversal = "path_traversal"
    csrf = "csrf"
    bruteforce = "bruteforce"
    user_enum = "user_enum"
    jwt = "jwt"
    deserialization = "deserialization"
    cache_poisoning = "cache_poisoning"
    host_header = "host_header"
    request_smuggling = "request_smuggling"
    injection = "injection"
    auth = "auth"
    info = "info"


class SourceTool(str, Enum):
    html = "html"
    js = "js"
    live = "live"
    wayback = "wayback"
    gau = "gau"
    arjun = "arjun"
    linkfinder = "linkfinder"
    other = "other"


class Parameter(BaseModel):
    name: str
    inferred_type: Optional[str] = None
    description: Optional[str] = None
    risks: List[RiskType] = Field(default_factory=list)


class Endpoint(BaseModel):
    path: str
    method: Optional[str] = None
    type: EndpointType = EndpointType.other
    parameters: List[Parameter] = Field(default_factory=list)
    sources: List[SourceTool] = Field(default_factory=list)
    notes: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_snippet: Optional[str] = None


class Finding(BaseModel):
    title: str
    description: str
    risks: List[RiskType]
    related_endpoints: List[str] = Field(default_factory=list)
    priority: int = 3
    affected_parameters: List[str] = Field(default_factory=list)
    risk_tags: List[str] = Field(default_factory=list)
    priority_label: Optional[str] = None


class AttackSurface(BaseModel):
    url: HttpUrl
    endpoints: List[Endpoint]
    findings: List[Finding] = Field(default_factory=list)


class AttackSurfaceReport(BaseModel):
    attack_surface: AttackSurface
    llm_model: Optional[str] = None
    llm_provider: Optional[str] = None
    raw_html: Optional[str] = None
    raw_js_snippets: Optional[Dict[str, str]] = None
    ai_parameter_findings: List[Finding] = Field(default_factory=list)
    ai_stats: Optional[Dict[str, int]] = None
    diagnostics: Dict[str, Any] = Field(default_factory=dict)
    parameter_notes: Dict[str, Dict[str, str]] = Field(default_factory=dict)
