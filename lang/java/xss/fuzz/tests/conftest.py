# tests/conftest.py
import pytest
from xss_harness import XSSClient

def pytest_addoption(parser):
    parser.addoption(
        "--host", action="store", default="127.0.0.1",
        help="XSS harness host"
    )
    parser.addoption(
        "--port", action="store", type=int, default=8000,
        help="XSS harness port"
    )

@pytest.fixture(scope="session")
def xss_client(request):
    """Instantiate the XSSClient using CLI options."""
    host = request.config.getoption("--host")
    port = request.config.getoption("--port")
    client = XSSClient(host=host, port=port)
    yield client
    client.shutdown()

@pytest.fixture(autouse=True)
def record_test_info(request, tmp_path):
    """
    Automatically create a log file per test under tmp_path,
    so you can inspect request.param, etc.
    """
    test_name = request.node.name
    logfile = tmp_path / f"{test_name}.log"
    with open(logfile, "w") as f:
        f.write(f"Starting {test_name}\n")
    yield logfile
    with open(logfile, "a") as f:
        f.write(f"Finished {test_name}\n")
