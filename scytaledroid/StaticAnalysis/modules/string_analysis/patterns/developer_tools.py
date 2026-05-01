"""Developer tooling credential patterns."""

from __future__ import annotations

import re

from .base import DEFAULT_ORIGINS, StringPattern

PATTERNS: tuple[StringPattern, ...] = (
    StringPattern(
        name="github_token",
        description="Potential GitHub personal access token",
        pattern=re.compile(r"ghp_[A-Za-z0-9]{36,}"),
        category="developer_tools",
        provider="GitHub",
        tags=("token", "github"),
        min_length=40,
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="github_fine_grained_token",
        description="Potential GitHub fine-grained personal access token",
        pattern=re.compile(r"gho_[A-Za-z0-9]{36,}"),
        category="developer_tools",
        provider="GitHub",
        tags=("token", "github"),
        min_length=40,
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="github_app_token",
        description="Potential GitHub App installation token",
        pattern=re.compile(r"ghs_[A-Za-z0-9]{36,}"),
        category="developer_tools",
        provider="GitHub",
        tags=("token", "github"),
        min_length=40,
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="github_user_token",
        description="Potential GitHub user-to-server token",
        pattern=re.compile(r"ghu_[A-Za-z0-9]{36,}"),
        category="developer_tools",
        provider="GitHub",
        tags=("token", "github"),
        min_length=40,
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="github_refresh_token",
        description="Potential GitHub refresh token",
        pattern=re.compile(r"ghr_[A-Za-z0-9]{36,}"),
        category="developer_tools",
        provider="GitHub",
        tags=("token", "github"),
        min_length=40,
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="gitlab_personal_token",
        description="Potential GitLab personal access token",
        pattern=re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
        category="developer_tools",
        provider="GitLab",
        tags=("token", "gitlab"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
)

__all__ = ["PATTERNS"]