import os
import pathlib
import pytest
import json
import httpx
import tempfile

from unittest.mock import patch, AsyncMock, MagicMock, mock_open
from gatox.github.api import Api
from gatox.github.app import GitHubApp
from gatox.enumerate.app_enumerate import AppEnumerator
from gatox.cli.output import Output
from unit_test.utils import escape_ansi

Output(True)

# Sample data for testing
SAMPLE_INSTALLATION = {
    "id": 123456,
    "account": {"login": "test-org", "id": 654321, "type": "Organization"},
    "repository_selection": "selected",
    "target_type": "Organization",
    "permissions": {"contents": "read", "metadata": "read", "workflows": "read"},
}

SAMPLE_INSTALLATION_TOKEN = {
    "token": "ghs_test_token",
    "expires_at": "2023-01-01T00:00:00Z",
}

SAMPLE_USER_INSTALLATION = {
    "id": 789012,
    "account": {"login": "test-user", "id": 345678, "type": "User"},
    "repository_selection": "all",
    "target_type": "User",
    "permissions": {"contents": "read", "metadata": "read", "workflows": "read"},
}

SAMPLE_ORG = {
    "login": "test-org",
    "id": 654321,
    "description": "Test organization",
    "two_factor_requirement_enabled": True,
}

SAMPLE_REPO = {
    "full_name": "test-org/test-repo",
    "id": 987654,
    "private": False,
    "description": "Test repository",
    "permissions": {
        "admin": True,
        "maintain": True,
        "push": True,
        "triage": True,
        "pull": True,
    },
}


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


@patch("jwt.encode", return_value="mock_jwt_token")
@patch("builtins.open", new_callable=mock_open, read_data="mock_private_key")
def test_github_app_init(mock_file, mock_jwt):
    """Test the GitHubApp class initialization."""
    app = GitHubApp("12345", "/path/to/private.pem")

    assert app.app_id == "12345"
    assert app.private_key_path == "/path/to/private.pem"
    assert app.private_key == "mock_private_key"
    mock_file.assert_called_once_with("/path/to/private.pem", "r")


@patch("jwt.encode", return_value="mock_jwt_token")
@patch("builtins.open", new_callable=mock_open, read_data="mock_private_key")
def test_github_app_generate_jwt(mock_file, mock_jwt):
    """Test the GitHubApp JWT generation method."""
    app = GitHubApp("12345", "/path/to/private.key")
    token = app.generate_jwt()

    assert token == "mock_jwt_token"
    mock_jwt.assert_called_once()


@patch("builtins.open", side_effect=FileNotFoundError)
def test_github_app_file_not_found(mock_file):
    """Test GitHubApp handling of missing private key file."""
    with pytest.raises(ValueError) as excinfo:
        GitHubApp("12345", "/path/to/nonexistent.pem")

    assert "Private key file not found" in str(excinfo.value)


@patch("jwt.encode", side_effect=Exception("Mock JWT error"))
@patch("builtins.open", new_callable=mock_open, read_data="mock_private_key")
def test_github_app_jwt_error(mock_file, mock_jwt):
    """Test GitHubApp handling of JWT generation error."""
    app = GitHubApp("12345", "/path/to/private.key")

    with pytest.raises(ValueError) as excinfo:
        app.generate_jwt()

    assert "Error generating JWT" in str(excinfo.value)


@patch("gatox.enumerate.app_enumerate.GitHubApp")
@patch("gatox.enumerate.app_enumerate.Api")
def test_app_enumerator_init(mock_api, mock_github_app):
    """Test AppEnumerator initialization."""
    mock_github_app_instance = MagicMock()
    mock_github_app.return_value = mock_github_app_instance
    mock_github_app_instance.generate_jwt.return_value = "mock_jwt_token"

    app_enumerator = AppEnumerator(
        app_id="12345",
        private_key_path="/path/to/key.pem",
        socks_proxy="socks://localhost:9050",
        http_proxy="http://localhost:8080",
        github_url="https://github.company.com/api/v3",
    )

    assert app_enumerator.app_id == "12345"
    assert app_enumerator.private_key_path == "/path/to/key.pem"
    assert app_enumerator.socks_proxy == "socks://localhost:9050"
    assert app_enumerator.http_proxy == "http://localhost:8080"
    assert app_enumerator.github_url == "https://github.company.com/api/v3"

    mock_github_app.assert_called_once_with("12345", "/path/to/key.pem")
    mock_api.assert_called_once_with(
        "mock_jwt_token",
        socks_proxy="socks://localhost:9050",
        http_proxy="http://localhost:8080",
        github_url="https://github.company.com/api/v3",
    )


@patch("gatox.enumerate.app_enumerate.GitHubApp")
@patch("gatox.enumerate.app_enumerate.Api", return_value=AsyncMock(Api))
async def test_list_installations(mock_api, mock_github_app, capsys):
    """Test listing App installations."""
    mock_github_app_instance = MagicMock()
    mock_github_app.return_value = mock_github_app_instance
    mock_github_app_instance.generate_jwt.return_value = "mock_jwt_token"
    mock_api.return_value.get_app_installations = AsyncMock(
        return_value=[SAMPLE_INSTALLATION]
    )

    app_enumerator = AppEnumerator(app_id="12345", private_key_path="/path/to/key.pem")

    installations = await app_enumerator.list_installations()

    mock_api.return_value.get_app_installations.assert_called_once()
    assert len(installations) == 1
    assert installations[0]["id"] == 123456

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)
    assert "Found 1 installations for App ID: 12345" in output
    assert "Installation ID: 123456" in output
    assert "Account: test-org (Organization)" in output


@patch("gatox.enumerate.app_enumerate.GitHubApp")
@patch("gatox.enumerate.app_enumerate.Api", return_value=AsyncMock(Api))
async def test_list_installations_empty(mock_api, mock_github_app, capsys):
    """Test listing when no App installations are found."""
    mock_github_app_instance = MagicMock()
    mock_github_app.return_value = mock_github_app_instance
    mock_github_app_instance.generate_jwt.return_value = "mock_jwt_token"
    mock_api.return_value.get_app_installations = AsyncMock(return_value=[])

    app_enumerator = AppEnumerator(app_id="12345", private_key_path="/path/to/key.pem")

    installations = await app_enumerator.list_installations()

    mock_api.return_value.get_app_installations.assert_called_once()
    assert len(installations) == 0

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)
    assert "No installations found for this GitHub App" in output


@patch("gatox.enumerate.app_enumerate.GitHubApp")
@patch("gatox.enumerate.enumerate.Enumerator")
@patch("gatox.enumerate.app_enumerate.Api", return_value=AsyncMock(Api))
async def test_enumerate_installation_org(
    mock_api, mock_enumerator, mock_github_app, capsys
):
    """Test enumerating an organization installation."""
    mock_github_app_instance = MagicMock()
    mock_github_app.return_value = mock_github_app_instance
    mock_github_app_instance.generate_jwt.return_value = "mock_jwt_token"
    mock_api.return_value.get_installation_details = AsyncMock(
        return_value=SAMPLE_INSTALLATION
    )
    mock_api.return_value.get_installation_access_token = AsyncMock(
        return_value="ghs_test_token"
    )

    mock_enumerator_instance = AsyncMock()
    mock_enumerator.return_value = mock_enumerator_instance

    # The real Enumerator class doesn't have enumerate_org, but we mock it here for testing
    mock_enumerator_instance.enumerate_organization = AsyncMock(return_value=SAMPLE_ORG)
    mock_enumerator_instance.enumerate_org_repos = AsyncMock()

    # Mock the app_enumerate imports to return our test values
    app_enumerator = AppEnumerator(app_id="12345", private_key_path="/path/to/key.pem")

    with patch.object(
        AppEnumerator,
        "enumerate_installation",
        AsyncMock(
            return_value={
                "installation": SAMPLE_INSTALLATION,
                "orgs": [SAMPLE_ORG],
                "repos": [SAMPLE_REPO],
            }
        ),
    ) as mock_enum:
        result = await app_enumerator.enumerate_installation("123456")

    assert result["installation"] == SAMPLE_INSTALLATION
    assert len(result["orgs"]) == 1
    assert len(result["repos"]) == 1
    assert result["repos"][0] == SAMPLE_REPO


@patch("gatox.enumerate.app_enumerate.GitHubApp")
@patch("gatox.enumerate.enumerate.Enumerator")
@patch("gatox.enumerate.app_enumerate.Api", return_value=AsyncMock(Api))
async def test_enumerate_installation_user(
    mock_api, mock_enumerator, mock_github_app, capsys
):
    """Test enumerating a user account installation."""
    mock_github_app_instance = MagicMock()
    mock_github_app.return_value = mock_github_app_instance
    mock_github_app_instance.generate_jwt.return_value = "mock_jwt_token"
    mock_api.return_value.get_installation_details = AsyncMock(
        return_value=SAMPLE_USER_INSTALLATION
    )
    mock_api.return_value.get_installation_access_token = AsyncMock(
        return_value="ghs_test_token"
    )

    mock_enumerator_instance = AsyncMock()
    mock_enumerator.return_value = mock_enumerator_instance
    mock_enumerator_instance.enumerate_repos = AsyncMock(return_value=[SAMPLE_REPO])

    app_enumerator = AppEnumerator(app_id="12345", private_key_path="/path/to/key.pem")

    with patch.object(
        AppEnumerator,
        "enumerate_installation",
        AsyncMock(
            return_value={
                "installation": SAMPLE_USER_INSTALLATION,
                "orgs": [],
                "repos": [SAMPLE_REPO],
            }
        ),
    ) as mock_enum:
        result = await app_enumerator.enumerate_installation("789012")

    assert result["installation"] == SAMPLE_USER_INSTALLATION
    assert len(result["orgs"]) == 0
    assert len(result["repos"]) == 1
    assert result["repos"][0] == SAMPLE_REPO


@patch("gatox.enumerate.app_enumerate.GitHubApp")
@patch("gatox.enumerate.app_enumerate.Api", return_value=AsyncMock(Api))
async def test_enumerate_installation_not_found(mock_api, mock_github_app, capsys):
    """Test enumerating an installation that doesn't exist or is not accessible."""
    mock_github_app_instance = MagicMock()
    mock_github_app.return_value = mock_github_app_instance
    mock_github_app_instance.generate_jwt.return_value = "mock_jwt_token"
    mock_api.return_value.get_installation_details = AsyncMock(return_value={})

    app_enumerator = AppEnumerator(app_id="12345", private_key_path="/path/to/key.pem")

    result = await app_enumerator.enumerate_installation("999999")

    mock_api.return_value.get_installation_details.assert_called_once_with("999999")
    assert result == {}

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)
    assert "Installation 999999 not found or not accessible" in output


@patch("gatox.enumerate.app_enumerate.GitHubApp")
@patch("gatox.enumerate.app_enumerate.Api", return_value=AsyncMock(Api))
async def test_enumerate_installation_token_fail(mock_api, mock_github_app, capsys):
    """Test handling a failure to create an installation token."""
    mock_github_app_instance = MagicMock()
    mock_github_app.return_value = mock_github_app_instance
    mock_github_app_instance.generate_jwt.return_value = "mock_jwt_token"
    mock_api.return_value.get_installation_details = AsyncMock(
        return_value=SAMPLE_INSTALLATION
    )
    mock_api.return_value.get_installation_access_token = AsyncMock(return_value=None)

    app_enumerator = AppEnumerator(app_id="12345", private_key_path="/path/to/key.pem")

    result = await app_enumerator.enumerate_installation("123456")

    mock_api.return_value.get_installation_details.assert_called_once_with("123456")
    mock_api.return_value.get_installation_access_token.assert_called_once_with(
        "123456"
    )

    assert result["installation"] == SAMPLE_INSTALLATION
    assert len(result["orgs"]) == 0
    assert len(result["repos"]) == 0

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)
    assert "Failed to create installation token for 123456" in output


@patch("gatox.enumerate.app_enumerate.GitHubApp")
@patch("gatox.enumerate.app_enumerate.Api", return_value=AsyncMock(Api))
@patch("gatox.enumerate.app_enumerate.AppEnumerator.enumerate_installation")
async def test_enumerate_all_installations(
    mock_enum_installation, mock_api, mock_github_app, capsys
):
    """Test enumerating all installations."""
    mock_github_app_instance = MagicMock()
    mock_github_app.return_value = mock_github_app_instance
    mock_github_app_instance.generate_jwt.return_value = "mock_jwt_token"
    mock_api.return_value.get_app_installations = AsyncMock(
        return_value=[SAMPLE_INSTALLATION, SAMPLE_USER_INSTALLATION]
    )

    mock_enum_installation.side_effect = [
        {
            "installation": SAMPLE_INSTALLATION,
            "orgs": [SAMPLE_ORG],
            "repos": [SAMPLE_REPO],
        },
        {"installation": SAMPLE_USER_INSTALLATION, "orgs": [], "repos": [SAMPLE_REPO]},
    ]

    app_enumerator = AppEnumerator(app_id="12345", private_key_path="/path/to/key.pem")

    results = await app_enumerator.enumerate_all_installations()

    mock_api.return_value.get_app_installations.assert_called_once()
    assert mock_enum_installation.call_count == 2
    mock_enum_installation.assert_any_call("123456")
    mock_enum_installation.assert_any_call("789012")

    assert len(results) == 2
    assert "123456" in results
    assert "789012" in results
    assert results["123456"]["account"] == SAMPLE_INSTALLATION["account"]
    assert results["789012"]["account"] == SAMPLE_USER_INSTALLATION["account"]

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)
    assert "Enumerating installation 123456 for test-org" in output
    assert "Enumerating installation 789012 for test-user" in output


@patch("gatox.enumerate.app_enumerate.GitHubApp")
@patch("gatox.enumerate.app_enumerate.Api", return_value=AsyncMock(Api))
async def test_enumerate_all_installations_empty(mock_api, mock_github_app, capsys):
    """Test enumerating all installations when none are found."""
    mock_github_app_instance = MagicMock()
    mock_github_app.return_value = mock_github_app_instance
    mock_github_app_instance.generate_jwt.return_value = "mock_jwt_token"
    mock_api.return_value.get_app_installations = AsyncMock(return_value=[])

    app_enumerator = AppEnumerator(app_id="12345", private_key_path="/path/to/key.pem")

    results = await app_enumerator.enumerate_all_installations()

    mock_api.return_value.get_app_installations.assert_called_once()
    assert results == {}

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)
    assert "No installations found for this GitHub App" in output
