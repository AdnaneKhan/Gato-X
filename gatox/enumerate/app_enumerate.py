"""Module for GitHub App enumeration functionality."""

import logging
import asyncio
from typing import List, Dict, Optional, Tuple, Any

from gatox.cli.output import Output
from gatox.github.api import Api
from gatox.github.app import GitHubApp
from gatox.enumerate.enumerate import Enumerator

logger = logging.getLogger(__name__)


class AppEnumerator:
    """Enumerator for GitHub App installations and their accessible resources."""

    def __init__(
        self,
        app_id: str,
        private_key_path: str,
        specific_installation_id: Optional[str] = None,
        socks_proxy: Optional[str] = None,
        http_proxy: Optional[str] = None,
        github_url: str = "https://api.github.com",
    ):
        """Initialize the AppEnumerator.

        Args:
            app_id: GitHub App ID
            private_key_path: Path to the private key file (PEM format)
            specific_installation_id: Optional specific installation ID to enumerate
            socks_proxy: Optional SOCKS proxy URL
            http_proxy: Optional HTTP proxy URL
            github_url: GitHub API URL
        """
        self.app_id = app_id
        self.private_key_path = private_key_path
        self.github_app = GitHubApp(app_id, private_key_path)
        self.specific_installation_id = specific_installation_id
        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.github_url = github_url
        self.api = None

        # Create API instance with JWT token
        jwt_token = self.github_app.generate_jwt()
        self.api = Api(
            jwt_token,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
            github_url=github_url,
        )

    async def list_installations(self) -> List[Dict]:
        """List all installations for the GitHub App.

        Returns:
            List of installation dictionaries
        """
        installations = await self.api.get_app_installations()

        if installations:
            Output.info(
                f"Found {len(installations)} installations for App ID: {self.app_id}"
            )

            for inst in installations:
                account = inst.get("account", {})
                account_name = account.get("login", "Unknown")
                account_type = account.get("type", "Unknown")
                inst_id = inst.get("id", "Unknown")

                Output.info(f"Installation ID: {inst_id}")
                Output.info(f"  Account: {account_name} ({account_type})")
                Output.info(f"  Target Type: {inst.get('target_type', 'Unknown')}")
                Output.info(
                    f"  Repository Selection: {inst.get('repository_selection', 'Unknown')}"
                )
                Output.info("")
        else:
            Output.info("No installations found for this GitHub App")

        return installations

    async def enumerate_installation(self, installation_id: str) -> Dict:
        """Enumerate a specific installation.

        Args:
            installation_id: ID of the installation to enumerate

        Returns:
            Dictionary containing enumeration results
        """
        # Get installation details
        installation = await self.api.get_installation_details(installation_id)

        if not installation:
            Output.error(f"Installation {installation_id} not found or not accessible")
            return {}

        # Create installation access token
        installation_token = await self.api.get_installation_access_token(
            installation_id
        )

        if not installation_token:
            Output.error(f"Failed to create installation token for {installation_id}")
            return {
                "installation": installation,
                "orgs": [],
                "repos": [],
            }

        # Create a new API instance with the installation token
        installation_api = Api(
            installation_token,
            socks_proxy=self.socks_proxy,
            http_proxy=self.http_proxy,
            github_url=self.github_url,
        )

        # Initialize enumerator with installation token
        enumerator = Enumerator(
            pat=installation_token,
            socks_proxy=self.socks_proxy,
            http_proxy=self.http_proxy,
            github_url=self.github_url,
        )

        results = {
            "installation": installation,
            "orgs": [],
            "repos": [],
        }

        # Get account details from installation
        account = installation.get("account", {})
        account_type = account.get("type", "").lower()

        # Based on account type, enumerate appropriate resources
        if account_type == "organization":
            org_name = account.get("login")
            Output.info(f"Enumerating organization: {org_name}")
            org_details = await enumerator.enumerate_org(org_name)
            results["orgs"].append(org_details)

            # Get organization repositories
            repos = await enumerator.enumerate_org_repos(org_name)
            results["repos"].extend(repos)
        else:
            # User account - enumerate user repos
            user_name = account.get("login")
            Output.info(f"Enumerating user account: {user_name}")

            repos = await enumerator.enumerate_repos([f"{user_name}/*"])
            results["repos"].extend(repos)

        return results

    async def enumerate_all_installations(self) -> Dict[str, Dict]:
        """Enumerate all installations for the GitHub App.

        Returns:
            Dictionary mapping installation IDs to enumeration results
        """
        installations = await self.api.get_app_installations()

        if not installations:
            Output.info("No installations found for this GitHub App")
            return {}

        results = {}
        for installation in installations:
            installation_id = installation.get("id")
            account = installation.get("account", {})
            account_name = account.get("login", "Unknown")

            Output.info(
                f"Enumerating installation {installation_id} for {account_name}"
            )

            installation_results = await self.enumerate_installation(
                str(installation_id)
            )

            results[str(installation_id)] = {
                "account": account,
                "results": installation_results,
            }

        return results
