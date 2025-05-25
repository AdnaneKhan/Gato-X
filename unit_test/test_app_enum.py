import os
import pathlib
import pytest
import json
import httpx
import tempfile
import jwt
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, AsyncMock, MagicMock, mock_open

# Import pytest-asyncio for async test support
import pytest_asyncio

from gatox.github.api import Api
from gatox.github.app_auth import GitHubAppAuth
from gatox.enumerate.app_enumerate import AppEnumerator
from gatox.cli.output import Output
from gatox.models.execution import Execution

from unit_test.utils import escape_ansi

# Initialize output for testing
Output(True)

# Mock data for testing
MOCK_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN
OPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP
QRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR
STUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST
UVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV
WXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX
YZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12
-----END RSA PRIVATE KEY-----"""

MOCK_APP_INFO = {
    "id": 12345,
    "slug": "test-app",
    "name": "Test App",
    "owner": {"login": "test-owner", "id": 67890},
    "description": "Test GitHub App",
    "permissions": {"contents": "read", "metadata": "read", "actions": "write"},
}

MOCK_INSTALLATIONS = [
    {
        "id": 11111,
        "account": {"login": "test-org", "id": 22222, "type": "Organization"},
        "app_id": 12345,
        "permissions": {"contents": "read", "metadata": "read", "actions": "write"},
        "repository_selection": "all",
    },
    {
        "id": 33333,
        "account": {"login": "test-user", "id": 44444, "type": "User"},
        "app_id": 12345,
        "permissions": {"contents": "read", "metadata": "read"},
        "repository_selection": "selected",
    },
]

MOCK_INSTALLATION_REPOS = [
    {
        "id": 55555,
        "name": "test-repo-1",
        "full_name": "test-org/test-repo-1",
        "private": False,
        "permissions": {"admin": False, "push": True, "pull": True},
    },
    {
        "id": 66666,
        "name": "test-repo-2",
        "full_name": "test-org/test-repo-2",
        "private": True,
        "permissions": {"admin": True, "push": True, "pull": True},
    },
]

MOCK_ACCESS_TOKEN = {
    "token": "ghs_abcdefghijklmnopqrstuvwxyz123456",
    "expires_at": "2024-01-01T12:00:00Z",
}


class TestGitHubAppAuth:
    """Test cases for GitHubAppAuth class."""

    def test_init(self):
        """Test GitHubAppAuth initialization."""
        app_auth = GitHubAppAuth("12345", "/path/to/key.pem")
        assert app_auth.app_id == "12345"
        assert str(app_auth.private_key_path) == "/path/to/key.pem"
        assert app_auth._private_key is None

    def test_load_private_key_file_not_found(self):
        """Test private key loading with non-existent file."""
        app_auth = GitHubAppAuth("12345", "/nonexistent/key.pem")

        with pytest.raises(FileNotFoundError, match="Private key file not found"):
            app_auth._load_private_key()

    @patch("builtins.open", new_callable=mock_open, read_data=MOCK_PRIVATE_KEY)
    @patch("pathlib.Path.exists", return_value=True)
    def test_load_private_key_success(self, mock_exists, mock_file):
        """Test successful private key loading."""
        app_auth = GitHubAppAuth("12345", "/path/to/key.pem")

        key = app_auth._load_private_key()
        assert key == MOCK_PRIVATE_KEY
        assert app_auth._private_key == MOCK_PRIVATE_KEY

        # Test caching
        key2 = app_auth._load_private_key()
        assert key2 == MOCK_PRIVATE_KEY
        mock_file.assert_called_once()  # Should only be called once due to caching

    @patch("builtins.open", new_callable=mock_open, read_data=MOCK_PRIVATE_KEY)
    @patch("pathlib.Path.exists", return_value=True)
    @patch("jwt.encode")
    def test_generate_jwt_success(self, mock_jwt_encode, mock_exists, mock_file):
        """Test successful JWT generation."""
        mock_jwt_encode.return_value = "mock.jwt.token"
        app_auth = GitHubAppAuth("12345", "/path/to/key.pem")

        token = app_auth.generate_jwt()

        assert token == "mock.jwt.token"
        mock_jwt_encode.assert_called_once()

        # Verify JWT payload structure
        call_args = mock_jwt_encode.call_args
        payload = call_args[0][0]

        assert payload["iss"] == "12345"
        assert "iat" in payload
        assert "exp" in payload
        assert payload["exp"] > payload["iat"]

    @patch("builtins.open", new_callable=mock_open, read_data=MOCK_PRIVATE_KEY)
    @patch("pathlib.Path.exists", return_value=True)
    def test_generate_jwt_expiration_too_long(self, mock_exists, mock_file):
        """Test JWT generation with expiration time too long."""
        app_auth = GitHubAppAuth("12345", "/path/to/key.pem")

        with pytest.raises(ValueError, match="JWT expiration cannot exceed 10 minutes"):
            app_auth.generate_jwt(expiration_minutes=15)

    @patch("builtins.open", new_callable=mock_open, read_data=MOCK_PRIVATE_KEY)
    @patch("pathlib.Path.exists", return_value=True)
    @patch("jwt.encode")
    def test_generate_jwt_custom_expiration(
        self, mock_jwt_encode, mock_exists, mock_file
    ):
        """Test JWT generation with custom expiration time."""
        mock_jwt_encode.return_value = "mock.jwt.token"
        app_auth = GitHubAppAuth("12345", "/path/to/key.pem")

        token = app_auth.generate_jwt(expiration_minutes=5)

        assert token == "mock.jwt.token"
        call_args = mock_jwt_encode.call_args
        payload = call_args[0][0]

        # Verify expiration is approximately 5 minutes from now
        now = datetime.now(timezone.utc).timestamp()
        exp_time = payload["exp"]
        assert abs(exp_time - now - 300) < 10  # Within 10 seconds of 5 minutes


class TestAppEnumerator:
    """Test cases for AppEnumerator class."""

    def test_init(self):
        """Test AppEnumerator initialization."""
        enumerator = AppEnumerator(
            app_id="12345",
            private_key_path="/path/to/key.pem",
            socks_proxy="localhost:9050",
            http_proxy="localhost:8080",
            github_url="https://github.enterprise.com/api/v3",
            skip_log=False,
            ignore_workflow_run=True,
            deep_dive=True,
        )

        assert enumerator.app_id == "12345"
        assert enumerator.private_key_path == "/path/to/key.pem"
        assert enumerator.socks_proxy == "localhost:9050"
        assert enumerator.http_proxy == "localhost:8080"
        assert enumerator.github_url == "https://github.enterprise.com/api/v3"
        assert enumerator.skip_log is False
        assert enumerator.ignore_workflow_run is True
        assert enumerator.deep_dive is True
        assert isinstance(enumerator.app_auth, GitHubAppAuth)

    @pytest.mark.asyncio
    @patch("gatox.enumerate.app_enumerate.Api")
    async def test_initialize_api_with_jwt(self, mock_api_class):
        """Test API client initialization with JWT."""
        # Create mocks
        mock_app_auth = MagicMock()
        mock_app_auth.generate_jwt.return_value = "mock.jwt.token"
        mock_api_instance = MagicMock()
        mock_api_class.return_value = mock_api_instance

        # Create test object
        enumerator = AppEnumerator("12345", "/path/to/key.pem")
        enumerator.app_auth = mock_app_auth

        # Call method
        await enumerator._initialize_api_with_jwt()

        # Verify JWT was generated and API was created
        mock_app_auth.generate_jwt.assert_called_once()
        mock_api_class.assert_called_once()
        assert mock_api_class.call_args.args[0] == "mock.jwt.token"

    @pytest.mark.asyncio
    @pytest.mark.asyncio
    @patch("gatox.github.api.Api")
    async def test_validate_app_success(self, mock_api):
        """Test successful app validation."""
        # Setup mocks
        mock_api_instance = MagicMock()
        mock_api_instance.get_app_info = AsyncMock(return_value=MOCK_APP_INFO)
        mock_api.return_value = mock_api_instance

        enumerator = AppEnumerator("12345", "/path/to/key.pem")
        enumerator.api = mock_api_instance

        result = await enumerator.validate_app()

        assert isinstance(result, dict)
        mock_api_instance.get_app_info.assert_called_once()

    @pytest.mark.asyncio
    @patch("gatox.github.api.Api")
    async def test_validate_app_failure(self, mock_api):
        """Test app validation failure."""
        # Setup mocks
        mock_api_instance = MagicMock()
        mock_api_instance.get_app_info = AsyncMock(side_effect=Exception("API Error"))
        mock_api.return_value = mock_api_instance

        enumerator = AppEnumerator("12345", "/path/to/key.pem")
        enumerator.api = mock_api_instance

        with pytest.raises(Exception, match="API Error"):
            await enumerator.validate_app()

    @pytest.mark.asyncio
    @patch("gatox.github.api.Api")
    @patch("gatox.cli.output.Output.info")
    @patch("gatox.cli.output.Output.error")
    async def test_list_installations(self, mock_error, mock_info, mock_api):
        """Test listing app installations."""
        # Setup mocks
        mock_api_instance = MagicMock()
        mock_api_instance.get_app_installations = AsyncMock(
            return_value=MOCK_INSTALLATIONS
        )
        mock_api_instance.get_installation_info = AsyncMock(
            side_effect=lambda id: next(
                (inst for inst in MOCK_INSTALLATIONS if inst["id"] == id), None
            )
        )
        mock_api_instance.get_installation_repositories = AsyncMock(
            return_value=MOCK_INSTALLATION_REPOS
        )
        mock_api.return_value = mock_api_instance

        enumerator = AppEnumerator("12345", "/path/to/key.pem")
        enumerator.api = mock_api_instance

        installations = await enumerator.list_installations()

        assert len(installations) == 2
        mock_api_instance.get_app_installations.assert_called_once()
        assert mock_api_instance.get_installation_info.call_count == 2
        assert mock_api_instance.get_installation_repositories.call_count == 2
        mock_info.assert_called()

    @pytest.mark.asyncio
    @patch("gatox.enumerate.enumerate.Enumerator")
    @patch("gatox.github.api.Api")
    @patch("gatox.cli.output.Output.info")
    @patch("gatox.cli.output.Output.error")
    async def test_enumerate_installation_repositories(
        self, mock_error, mock_info, mock_api, mock_enumerator_class
    ):
        """Test getting repositories for an installation."""
        # Setup mocks
        mock_api_instance = MagicMock()
        mock_api_instance.get_installation_access_token = AsyncMock(
            return_value=MOCK_ACCESS_TOKEN
        )
        mock_api_instance.get_installation_repositories = AsyncMock(
            return_value=MOCK_INSTALLATION_REPOS
        )
        mock_api_instance.get_installation_info = AsyncMock(
            return_value=MOCK_INSTALLATIONS[0]
        )

        # For the mock API constructor, return different instances
        mock_installation_api = MagicMock()
        mock_api.side_effect = [mock_api_instance, mock_installation_api]

        # Mock enumerator class
        mock_enumerator_instance = MagicMock()
        execution_result = Execution()
        execution_result.repositories = ["test-org/test-repo-1"]
        mock_enumerator_instance.enumerate = AsyncMock(return_value=execution_result)
        mock_enumerator_class.return_value = mock_enumerator_instance

        # Create test object
        enumerator = AppEnumerator("12345", "/path/to/key.pem")
        enumerator.api = mock_api_instance

        # Call the enumerate_installation method and ensure it completes
        result = await enumerator.enumerate_installation(11111)

        # Verify the API token was requested
        mock_api_instance.get_installation_access_token.assert_called_once_with(11111)

    @pytest.mark.asyncio
    @patch("gatox.enumerate.app_enumerate.Enumerator")
    @patch("gatox.cli.output.Output.info")
    @patch("gatox.cli.output.Output.error")
    async def test_enumerate_installation(
        self, mock_error, mock_info, mock_enumerator_class
    ):
        """Test enumerating a specific installation."""
        # Setup mocks for the API
        mock_api_instance = AsyncMock()
        mock_api_instance.get_installation_access_token = AsyncMock(
            return_value=MOCK_ACCESS_TOKEN
        )
        mock_api_instance.get_installation_info = AsyncMock(
            return_value=MOCK_INSTALLATIONS[0]
        )
        mock_api_instance.close = AsyncMock()

        # Mock for installation API
        mock_installation_api = AsyncMock()
        mock_installation_api.get_installation_repos = AsyncMock(
            return_value={
                "total_count": len(MOCK_INSTALLATION_REPOS),
                "repositories": MOCK_INSTALLATION_REPOS,
            }
        )
        mock_installation_api.close = AsyncMock()

        # Setup mock for Enumerator
        mock_enumerator_instance = MagicMock()
        mock_enumerator_instance.enumerate_repos = AsyncMock(
            return_value=["test-org/test-repo-1", "test-org/test-repo-2"]
        )
        mock_enumerator_class.return_value = mock_enumerator_instance

        # Create enumerator with mocked API
        enumerator = AppEnumerator("12345", "/path/to/key.pem")
        enumerator.api = mock_api_instance

        # Patch the Api constructor directly inside the test
        with patch(
            "gatox.enumerate.app_enumerate.Api", return_value=mock_installation_api
        ):
            # Run test
            result = await enumerator.enumerate_installation(11111)

        # Verify API calls
        mock_api_instance.get_installation_access_token.assert_called_once_with(11111)
        mock_installation_api.get_installation_repos.assert_called_once()
        mock_enumerator_instance.enumerate_repos.assert_called_once()
        assert result is not None
        assert isinstance(result, Execution)

    @pytest.mark.asyncio
    @patch("gatox.enumerate.app_enumerate.AppEnumerator.enumerate_installation")
    @patch("gatox.cli.output.Output.info")
    async def test_enumerate_all_installations(self, mock_info, mock_enum_installation):
        """Test enumerating all installations."""
        # Setup mocks with proper AsyncMock methods
        mock_api_instance = AsyncMock()
        mock_api_instance.get_app_installations = AsyncMock(
            return_value=MOCK_INSTALLATIONS
        )
        mock_api_instance.get_app_info = AsyncMock(return_value=MOCK_APP_INFO)
        mock_api_instance.get_installation_info = AsyncMock(
            return_value=MOCK_INSTALLATIONS[0]
        )
        mock_api_instance.get_installation_repositories = AsyncMock(
            return_value=MOCK_INSTALLATION_REPOS
        )
        mock_api_instance.close = AsyncMock()

        # Setup mock for enumerate_installation
        installation_result1 = Execution()
        installation_result1.add_repositories(["repo1", "repo2"])
        installation_result1.set_user_details({"installation_id": 11111})

        installation_result2 = Execution()
        installation_result2.add_repositories(["repo3"])
        installation_result2.set_user_details({"installation_id": 33333})

        mock_enum_installation.side_effect = [
            installation_result1,
            installation_result2,
        ]

        # Create enumerator with mocked API
        enumerator = AppEnumerator("12345", "/path/to/key.pem")
        enumerator.api = mock_api_instance

        # We need to patch validate_app to return directly
        with patch.object(
            enumerator, "validate_app", AsyncMock(return_value=MOCK_APP_INFO)
        ):
            # Run test
            results = await enumerator.enumerate_all_installations()

        # Verify calls
        mock_api_instance.get_app_installations.assert_called_once()
        mock_api_instance.get_installation_repositories.assert_called()
        assert mock_enum_installation.call_count == 2

        # Verify that results is a list of execution objects
        assert len(results) == 2
        assert all(isinstance(result, Execution) for result in results)


class TestAppEnumeratorIntegration:
    """Integration tests for AppEnumerator."""

    def test_real_pem_file_validation(self):
        """Test with a real temporary PEM file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(MOCK_PRIVATE_KEY)
            pem_path = f.name

        try:
            app_auth = GitHubAppAuth("12345", pem_path)
            key = app_auth._load_private_key()
            assert key == MOCK_PRIVATE_KEY
        finally:
            os.unlink(pem_path)

    @pytest.mark.asyncio
    @patch("gatox.enumerate.app_enumerate.Api")
    async def test_app_enumerator_with_real_file(self, mock_api):
        """Test AppEnumerator with a real temporary PEM file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(MOCK_PRIVATE_KEY)
            pem_path = f.name

        try:
            # Create API mock
            mock_api_instance = MagicMock()
            mock_api.return_value = mock_api_instance

            # Create and test the enumerator
            enumerator = AppEnumerator("12345", pem_path)

            # Mock the JWT generation specifically
            enumerator.app_auth = MagicMock()
            enumerator.app_auth.generate_jwt.return_value = "mock.jwt.token"

            # Initialize API
            await enumerator._initialize_api_with_jwt()

            # Verify results
            enumerator.app_auth.generate_jwt.assert_called_once()
            mock_api.assert_called_once()
            assert enumerator.api is mock_api_instance
        finally:
            os.unlink(pem_path)


class TestAppEnumeratorErrorHandling:
    """Test error handling in AppEnumerator."""

    @pytest.mark.asyncio
    async def test_jwt_generation_error(self):
        """Test handling of JWT generation errors."""
        # Create a mock GitHubAppAuth that raises an exception
        mock_app_auth = MagicMock()
        mock_app_auth.generate_jwt.side_effect = Exception("JWT generation failed")

        # Create enumerator with mocked auth
        enumerator = AppEnumerator("12345", "/path/to/key.pem")
        enumerator.app_auth = mock_app_auth

        # Test exception propagation
        with pytest.raises(Exception, match="JWT generation failed"):
            await enumerator._initialize_api_with_jwt()

    @pytest.mark.asyncio
    @patch("gatox.github.api.Api")
    @patch("gatox.cli.output.Output.error")
    async def test_api_error_handling(self, mock_error, mock_api):
        """Test handling of API errors."""
        # Setup mock API with error
        mock_api_instance = MagicMock()
        mock_api_instance.get_app_installations = AsyncMock(
            side_effect=httpx.HTTPStatusError(
                "API Error", request=MagicMock(), response=MagicMock()
            )
        )
        mock_api.return_value = mock_api_instance

        # Create enumerator with mocked API
        enumerator = AppEnumerator("12345", "/path/to/key.pem")
        enumerator.api = mock_api_instance

        # Test error handling during list_installations
        with pytest.raises(httpx.HTTPStatusError):
            await enumerator.list_installations()

        # Verify error was called
        mock_api_instance.get_app_installations.assert_called_once()
