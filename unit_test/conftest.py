import pytest
import httpx


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """
    Fixture to block real network calls during tests,
    raising an error if any attempt to send a request is made.
    """

    def mock_request(*args, **kwargs):
        raise RuntimeError("Blocked a real network call during tests.")

    monkeypatch.setattr(httpx.Client, "send", mock_request)
    monkeypatch.setattr(httpx.AsyncClient, "send", mock_request)
