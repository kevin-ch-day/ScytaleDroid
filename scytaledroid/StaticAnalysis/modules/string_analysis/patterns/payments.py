"""Payment provider credential patterns."""

from __future__ import annotations

import re

from .base import DEFAULT_ORIGINS, StringPattern

PATTERNS: tuple[StringPattern, ...] = (
    StringPattern(
        name="stripe_secret_key",
        description="Potential Stripe secret key",
        pattern=re.compile(r"sk_(?:live|test)_[0-9A-Za-z]{24,}"),
        category="payments",
        provider="Stripe",
        tags=("secret", "stripe"),
        min_length=32,
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="stripe_publishable_key",
        description="Potential Stripe publishable key",
        pattern=re.compile(r"pk_(?:live|test)_[0-9A-Za-z]{24}"),
        category="payments",
        provider="Stripe",
        tags=("publishable_key", "stripe"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="braintree_access_token",
        description="Potential Braintree access token",
        pattern=re.compile(r"access_token\$[a-z0-9_\-]+\$[a-z0-9_\-]+\$[a-z0-9_\-]+", re.IGNORECASE),
        category="payments",
        provider="Braintree",
        tags=("access_token", "braintree"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="paypal_client_id",
        description="Potential PayPal client ID",
        pattern=re.compile(r"A[A-Za-z0-9]{20,}-[A-Za-z0-9_-]{10,}"),
        category="payments",
        provider="PayPal",
        tags=("client_id", "paypal"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
    StringPattern(
        name="square_access_token",
        description="Potential Square access token",
        pattern=re.compile(r"sq0(?:atp|csp|dev|prod)-[A-Za-z0-9\-_]{22}"),
        category="payments",
        provider="Square",
        tags=("token", "square"),
        preferred_origins=DEFAULT_ORIGINS,
    ),
)

__all__ = ["PATTERNS"]
