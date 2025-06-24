
import pytest
from urllib.parse import urljoin

@pytest.fixture(scope="function")
def ci_endpoint(base_url):
    return urljoin(base_url, "/run")

# payloads defined inline; could also come from YAML
cmd_payloads = [
    {"name": "ls-root", "cmd": "; ls /",    "expect_code": 400},
    {"name": "whoami", "cmd": "`whoami`",  "expect_code": 400},
    {"name": "normal", "cmd": "echo test", "expect_code": 200},
]

@pytest.mark.parametrize("payload", cmd_payloads, ids=[p["name"] for p in cmd_payloads])
def test_command_injection(http_client, ci_endpoint, payload):
    resp = http_client.post(ci_endpoint, data={"cmd": payload["cmd"]})
    assert resp.status_code == payload["expect_code"]
    if payload["expect_code"] == 200:
        # normal behavior returns the command output
        assert "test" in resp.text

@pytest.mark.pentest
def test_subprocess_timeout(http_client, ci_endpoint):
    # Ensure long-running commands are killed
    resp = http_client.post(ci_endpoint, data={"cmd": "sleep 10"})
    assert resp.status_code == 408  # Request Timeout

@pytest.mark.xfail(reason="Known bypass on || operator", strict=False)
def test_bypass_with_or(http_client, ci_endpoint):
    resp = http_client.post(ci_endpoint, data={"cmd": "true || whoami"})
    assert "root" not in resp.text
