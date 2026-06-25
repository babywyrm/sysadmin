"""Tests for the taxonomy bridge module."""

from mcp_slayer.taxonomy import (
    OWASP_TO_THREATS,
    THREAT_METADATA,
    THREAT_TO_OWASP,
    OWASPCategory,
    PlaybookThreatID,
    get_threat_metadata,
    owasp_for_threat,
    threats_for_owasp,
)


def test_all_threats_have_owasp_mapping():
    for threat_id in PlaybookThreatID:
        assert threat_id in THREAT_TO_OWASP, f"{threat_id} missing from THREAT_TO_OWASP"
        assert len(THREAT_TO_OWASP[threat_id]) >= 1


def test_all_threats_have_metadata():
    for threat_id in PlaybookThreatID:
        meta = THREAT_METADATA[threat_id]
        assert "name" in meta
        assert "description" in meta
        assert "red_team_lane" in meta
        assert "owasp_llm" in meta


def test_reverse_mapping_covers_all_owasp_categories():
    for cat in OWASPCategory:
        assert cat in OWASP_TO_THREATS, f"{cat} missing from reverse mapping"
        assert len(OWASP_TO_THREATS[cat]) >= 1


def test_threats_for_owasp_returns_list():
    result = threats_for_owasp(OWASPCategory.PROMPT_INJECTION)
    assert PlaybookThreatID.PROMPT_INJECTION_DIRECT in result
    assert PlaybookThreatID.PROMPT_INJECTION_INDIRECT in result


def test_owasp_for_threat_returns_list():
    result = owasp_for_threat(PlaybookThreatID.CONFUSED_DEPUTY)
    assert OWASPCategory.PRIVILEGE_ESCALATION in result
    assert OWASPCategory.INSUFFICIENT_AUTH in result


def test_get_threat_metadata_returns_dict():
    meta = get_threat_metadata(PlaybookThreatID.SSRF_VIA_TOOL)
    assert meta["name"] == "SSRF via Tool"
    assert meta["red_team_lane"] == "RT-04"


def test_threat_count():
    # Core T01–T14 (14) + extended T37–T49 (9) = 23
    assert len(PlaybookThreatID) == 23


def test_owasp_count_is_10():
    assert len(OWASPCategory) == 10
