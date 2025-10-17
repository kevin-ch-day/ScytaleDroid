"""Detector registry for string-analysis post-processing."""
from __future__ import annotations

from typing import Iterator, Sequence

from ..schema import Observation
from .common import Fragment, collect_fragments
from .fragment import iter_fragment_observations
from .pairing import iter_aws_pair_observations

__all__ = [
    "Fragment",
    "collect_fragments",
    "iter_fragment_observations",
    "iter_aws_pair_observations",
]


def iterate_fragment_observations(fragment: Fragment) -> Iterator[Observation]:
    """Yield observations for a single fragment across registered detectors."""

    yield from iter_fragment_observations(fragment)


def iterate_pair_observations(fragments: Sequence[Fragment]) -> Iterator[Observation]:
    """Yield observations that require fragment correlation."""

    yield from iter_aws_pair_observations(fragments)
