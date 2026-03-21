from alfa.core.filter_contract import FilterRequestModel, FilterAction, FilterResult


def test_filter_request_normalizes_timestamp_and_generates_correlation_id() -> None:
    request = FilterRequestModel(
        query=" safe query ",
        user_id=" user-1 ",
        session_id=" session-1 ",
        timestamp="2026-03-21T12:00:00Z",
    )
    assert request.query == "safe query"
    assert request.user_id == "user-1"
    assert request.session_id == "session-1"
    assert request.timestamp == "2026-03-21T12:00:00+00:00"
    assert request.correlation_id


def test_filter_request_rejects_empty_query() -> None:
    try:
        FilterRequestModel(
            query="   ",
            user_id="user-1",
            session_id="session-1",
            timestamp="2026-03-21T12:00:00+00:00",
        )
    except ValueError as exc:
        assert "query" in str(exc)
    else:
        raise AssertionError("Expected ValueError for empty query")


def test_filter_result_validates_ranges() -> None:
    result = FilterResult(
        filter_id="Cerber",
        risk_score=0.7,
        confidence=0.9,
        action=FilterAction.BLOCK,
    )
    assert result.filter_id == "Cerber"
    assert result.action == FilterAction.BLOCK
