import pytest

from unittest.mock import patch
from unittest.mock import MagicMock
from gatox.attack.attack import Attacker
from gatox.github.api import Api
from gatox.cli.output import Output

from gatox.attack.pwnrequest.steps.catcher import Catcher


@pytest.fixture(scope="function", autouse=True)
def mock_all_requests():
    with (
        patch("gatox.github.api.requests.get") as mock_get,
        patch("gatox.github.api.requests.post") as mock_post,
        patch("gatox.github.api.requests.put") as mock_put,
        patch("gatox.github.api.requests.delete") as mock_delete,
    ):

        yield {
            "get": mock_get,
            "post": mock_post,
            "put": mock_put,
            "delete": mock_delete,
        }


@pytest.fixture
def api_access():
    # This PAT is INVALID
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    abstraction_layer = MagicMock(Api)
    yield abstraction_layer


@patch("gatox.attack.pwnrequest.steps.catcher.time.sleep")
def test_catcher(mock_sleep, mock_all_requests, api_access):
    """Test the secrets catcher"""

    TEST_EXFIL = "ImdpdGh1Yl90b2tlbiI6eyJ2YWx1ZSI6Imdoc193MkQ4R1dWMzRNWDdrbllJQ0dmbUJIald0ZFdzdnMyMHdKekEiLCJpc1NlY3JldCI6dHJ1ZX0KInN5c3RlbS5naXRodWIudG9rZW4iOnsidmFsdWUiOiJnaHNfdzJEOEdXVjM0TVg3a25ZSUNHZm1CSGpXdGRXc3ZzMjB3SnpBIiwiaXNTZWNyZXQiOnRydWV9Cg==:InBhcmFtZXRlcnMiOnsiQWNjZXNzVG9rZW4iOiJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpTVXpJMU5pSXNJbmcxZENJNklraDVjVFJPUVZSQmFuTnVjVU0zYldSeWRFRm9hSEpEVWpKZlVTSjkuZXlKdVlXMWxhV1FpT2lKa1pHUmtaR1JrWkMxa1pHUmtMV1JrWkdRdFpHUmtaQzFrWkdSa1pHUmtaR1JrWkdRaUxDSnpZM0FpT2lKQlkzUnBiMjV6TGtkbGJtVnlhV05TWldGa09qQXdNREF3TURBd0xUQXdNREF0TURBd01DMHdNREF3TFRBd01EQXdNREF3TURBd01DQkJZM1JwYjI1ekxsSmxjM1ZzZEhNNllXSTNORFF5TmpjdFpXUXpOUzAwTnpsa0xUaGxPRFF0T1RSaU1qWm1PV1ZtWkdReE9qSXlNakE1TWpJeUxUVmtOak10TldVM1ppMDRaV00wTFdJeFpXVmxOREV6WWpVNE5pQkJZM1JwYjI1ekxsVndiRzloWkVGeWRHbG1ZV04wY3pvd01EQXdNREF3TUMwd01EQXdMVEF3TURBdE1EQXdNQzB3TURBd01EQXdNREF3TURBdk1UcENkV2xzWkM5Q2RXbHNaQzg0TnlCTWIyTmhkR2x2YmxObGNuWnBZMlV1UTI5dWJtVmpkQ0JTWldGa1FXNWtWWEJrWVhSbFFuVnBiR1JDZVZWeWFUb3dNREF3TURBd01DMHdNREF3TFRBd01EQXRNREF3TUMwd01EQXdNREF3TURBd01EQXZNVHBDZFdsc1pDOUNkV2xzWkM4NE55SXNJa2xrWlc1MGFYUjVWSGx3WlVOc1lXbHRJam9pVTNsemRHVnRPbE5sY25acFkyVkpaR1Z1ZEdsMGVTSXNJbWgwZEhBNkx5OXpZMmhsYldGekxuaHRiSE52WVhBdWIzSm5MM2R6THpJd01EVXZNRFV2YVdSbGJuUnBkSGt2WTJ4aGFXMXpMM05wWkNJNklrUkVSRVJFUkVSRUxVUkVSRVF0UkVSRVJDMUVSRVJFTFVSRVJFUkVSRVJFUkVSRVJDSXNJbWgwZEhBNkx5OXpZMmhsYldGekxtMXBZM0p2YzI5bWRDNWpiMjB2ZDNNdk1qQXdPQzh3Tmk5cFpHVnVkR2wwZVM5amJHRnBiWE12Y0hKcGJXRnllWE5wWkNJNkltUmtaR1JrWkdSa0xXUmtaR1F0WkdSa1pDMWtaR1JrTFdSa1pHUmtaR1JrWkdSa1pDSXNJbUYxYVNJNklqWXlPVGcwWmpjeUxXSTJaVFV0TkRRd1pDMDVNV0kyTFRVMk5qazROemxsTWpVMlpDSXNJbk5wWkNJNklqQmlNVEE0TVdZMkxXUTBOemN0TkRrek55MDRPRE5oTFdVNFl6YzNabVV4Wm1ZeFlTSXNJbUZqSWpvaVczdGNJbE5qYjNCbFhDSTZYQ0p5WldaekwyaGxZV1J6TDIxaGFXNWNJaXhjSWxCbGNtMXBjM05wYjI1Y0lqb3pmVjBpTENKaFkzTnNJam9pTVRBaUxDSnZjbU5vYVdRaU9pSmhZamMwTkRJMk55MWxaRE0xTFRRM09XUXRPR1U0TkMwNU5HSXlObVk1Wldaa1pERXVZV1JrTFhSaFp5NWZYMlJsWm1GMWJIUWlMQ0pwYzNNaU9pSjJjM1J2YTJWdUxtRmpkR2x2Ym5NdVoybDBhSFZpZFhObGNtTnZiblJsYm5RdVkyOXRJaXdpWVhWa0lqb2lkbk4wYjJ0bGJpNWhZM1JwYjI1ekxtZHBkR2gxWW5WelpYSmpiMjUwWlc1MExtTnZiWHgyYzI4Nk5qVXlOakJtT1RVdE5EUmxOQzAwWkdFeExUZ3dOek10TldGbU16Y3dZMkl4WlRSbUlpd2libUptSWpveE56TXlOek00TmpFMUxDSmxlSEFpT2pFM016STNOakUwTVRWOS5DWDV1TkNxS0JaU2dpUk5VcGZDOWM2SFluaTJrd25jdWNUQ2hoZDBrQ0tHb0tyMkNCeGlhdS0yaDFBNmFFZ24yb3NPcm05bkI0NDlVaFRQb1dGVmdpMmQ4QXJRdmFIWDJ2Um5xM3Foc0duUzM4dzFQSDVtemhzZDZONzdlZkd2Vk56M2xDcVlnc1c1SnI2REFJZDIyZGRkYjNDNWZEUU50UkttUmtnWXlmMU1Zd2ktM1U3bFBNcWVkd1g4UGlBWDdHNVdia3BFNWNlVE8wUFZyWkFPWENqTWZ3eXhTb2xpZjRMb25BY2dOdEZNUHQ5UjRlREExbXJIQkZ2bVd6R1dnV1B5YmtEa0FQLWVIRDhwU1hzeDlTRmo2aWNTU2EyYkVyYm5QS21ESFI3dGNMRVI3NG83Qk5PSXhFc1p5Zi0zQzNobFVXQ211OElhdzdmczkyZnJpSmcifQ==:IkNhY2hlU2VydmVyVXJsIjoiW14iCiJDYWNoZVNlcnZlclVybCI6Imh0dHBzOi8vYWNnaHViZXVzMi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbS9iZDFWRld2dVJJTlU4emtKQ2NPbWxjSlhGRXkwMFNQcm8yUTRpVjNHeHZOd2dNTFU3MC8i"
    TEST_PREV_RESULTS = {"catcher_gist": "ijevj", "exfil_gist": ""}

    api_access.get_gist_file.return_value = TEST_EXFIL
    test_catcher = Catcher(["system.github.token"], "test_gist_pat", 300)
    test_catcher.preflight(api_access, TEST_PREV_RESULTS)

    result = test_catcher.execute(api_access)

    assert result == True
    assert test_catcher.output["status"] == "SUCCESS"
    assert "github_token" in test_catcher.output["secrets"]["values"]


def test_catcher_timeout(mock_all_requests, api_access):
    """Test scenario where the secrets catcher times out due to a failed
    exfiltration.
    """
    pass


@patch("gatox.attack.pwnrequest.steps.catcher.time.sleep")
def test_catcher_invalid(mock_sleep, mock_all_requests, api_access):
    """Test scenario where the format of the exfiltrated data is invalid."""
    TEST_EXFIL = """FOOBARBAZA"""
    TEST_PREV_RESULTS = {
        "catcher_gist": "ijevj",
        "exfil_gist": "7ade67279440b7620568b067b9390e02",
    }

    api_access.get_gist_file.return_value = TEST_EXFIL

    test_catcher = Catcher(["test_secret"], "test_gist_pat", 300)
    test_catcher.preflight(api_access, TEST_PREV_RESULTS)
    result = test_catcher.execute(api_access)

    assert result == False
    assert test_catcher.output["status"] == "FAILURE"


@patch("gatox.attack.pwnrequest.steps.catcher.time.sleep")
def test_catcher_invalid2(mock_sleep, mock_all_requests, api_access):
    """Test scenario where the format of the exfiltrated data is invalid."""
    TEST_EXFIL = """ : : """
    TEST_PREV_RESULTS = {
        "catcher_gist": "ijevj",
        "exfil_gist": "7ade67279440b7620568b067b9390e02",
    }

    test_catcher = Catcher(["test_secret"], "test_gist_pat", 300)
    status = test_catcher.preflight(api_access, TEST_PREV_RESULTS)
    result = test_catcher.execute(api_access)

    assert result == False
    assert test_catcher.output["status"] == "FAILURE"
