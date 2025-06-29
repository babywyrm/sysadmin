import pytest
import logging

# Configure root logging for the test session
logging.basicConfig(level=logging.INFO)
logging.getLogger("site_monitor").setLevel(logging.DEBUG)

def pytest_addoption(parser):
    """
    Add a --url option to override test URLs at runtime.
    """
    parser.addoption(
        "--url",
        action="store",
        default=None,
        help="If set, run all SiteMonitor tests against this single URL"
    )

@pytest.fixture(scope="session")
def cli_url(request):
    """
    Provide the URL passed via --url, or None if not set.
    """
    return request.config.getoption("--url")
##
##
