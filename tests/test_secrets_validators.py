from types import SimpleNamespace

from scytaledroid.StaticAnalysis.detectors.secrets import (
    _build_findings,
    _prepare_group_insights,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.indexing.models import IndexedString
from scytaledroid.StaticAnalysis.modules.string_analysis.matcher import (
    EvaluatedMatch,
    MatchGroup,
    MatchRecord,
    MatchStatus,
)


def _make_pattern(name: str, description: str):
    return SimpleNamespace(
        name=name,
        description=description,
        category="secret",
        provider=None,
        tags=(name,),
    )


def test_prepare_group_insights_filters_placeholder_keys(tmp_path):
    pattern = _make_pattern("aws_access_key", "AWS Access Key")

    valid_entry = IndexedString(
        value="AKIA123456789ABCDE1",
        origin="classes.dex",
        origin_type="code",
        context="Authorization header",
    )
    placeholder_entry = IndexedString(
        value="AKIAIOSFODNN7EXAMPLE",
        origin="classes.dex",
        origin_type="code",
    )

    valid_match = EvaluatedMatch(
        record=MatchRecord(pattern=pattern, string_entry=valid_entry, fragment=valid_entry.value),
        status=MatchStatus.ACCEPTED,
    )
    placeholder_match = EvaluatedMatch(
        record=MatchRecord(pattern=pattern, string_entry=placeholder_entry, fragment=placeholder_entry.value),
        status=MatchStatus.ACCEPTED,
    )

    group = MatchGroup(pattern=pattern, accepted=(valid_match, placeholder_match), filtered=tuple())
    prepared = _prepare_group_insights({pattern.name: group})

    assert pattern.name in prepared
    info = prepared[pattern.name]
    matches = info["matches"]
    assert len(matches) == 1
    assert matches[0].record.string_entry.value == "AKIA123456789ABCDE1"
    assert info["usage_correlated"] is True
    assert info["confidence"] == "high"
    assert info["validator_hits"] == ("aws_key_prefix",)


def test_build_findings_marks_uncorrelated_as_info(tmp_path):
    pattern = _make_pattern("jwt_token", "JWT token")
    entry = IndexedString(
        value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.abc123",
        origin="strings.xml",
        origin_type="resource",
        context="example placeholder",
    )
    match = EvaluatedMatch(
        record=MatchRecord(pattern=pattern, string_entry=entry, fragment=entry.value),
        status=MatchStatus.ACCEPTED,
    )
    group = MatchGroup(pattern=pattern, accepted=(match,), filtered=tuple())
    prepared = _prepare_group_insights({pattern.name: group})
    info = prepared[pattern.name]
    # Lack of context should mark usage_correlated False
    info["usage_correlated"] = False
    findings = _build_findings(prepared, apk_path=tmp_path / "sample.apk")
    assert findings[0].status.name == "INFO"
    assert findings[0].metrics.get("confidence") == "medium"
