"""Compatibility wrapper for the scripted template catalog.

New code should prefer ``script_template_catalog.py``. This module stays as a
stable import surface for existing callers and tests.
"""

from .script_template_catalog import *  # noqa: F401,F403
from .script_template_catalog import __all__
