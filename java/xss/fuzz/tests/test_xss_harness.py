import pytest

# 1. Simple parametrized test with ids
@pytest.mark.parametrize(
    "payload, should_escape",
    [
        ("<script>alert(1)</script>", True),
        ("<img src=x onerror=alert(1)>", True),
        ("plain text", False),
        ("<b>bold</b>", False),
    ],
    ids=["script", "img-onerror", "text", "bold"],
)
def test_param_sanitization(xss_client, payload, should_escape):
    body = xss_client.post("/echo", data={"input": payload}).text
    if should_escape:
        assert "&lt;" in body and "&gt;" in body
    else:
        assert payload in body

# 2. Indirect parametrization via fixture
@pytest.mark.parametrize(
    "injected_payload, expected_snippet",
    [
        ("<x>", "&lt;x&gt;"),
        ("<safe>ok</safe>", "<safe>ok</safe>"),
    ],
    indirect=["injected_payload"],
)
def test_indirect(injected_payload, expected_snippet):
    assert expected_snippet in injected_payload

# 3. Edge case: empty payload
@pytest.mark.xss
def test_empty_payload(xss_client):
    resp = xss_client.post("/echo", data={"input": ""})
    assert resp.text == ""

# 4. Logging behavior
def test_warning_logged(caplog, xss_client):
    caplog.set_level("WARNING", logger="xss_harness")
    _ = xss_client.post("/echo", data={"input": "<script>evil()</script>"})
    assert "Detected potentially malicious" in caplog.text

# 5. Environment-driven strict mode
def test_strict_mode(monkeypatch, xss_client):
    monkeypatch.setenv("XSS_MODE", "strict")
    body = xss_client.post("/echo", data={"input": "<b>bold</b>"}).text
    assert "&lt;b&gt;" in body

# 6. Async support
@pytest.mark.asyncio
async def test_async_harness(xss_client):
    resp = await xss_client.post_json("/echo", {"input": "<i>hello</i>"})
    text = await resp.text()
    assert "<i>hello</i>" in text
