"""GitHub App specific functionality for generating JWT tokens and interacting with GitHub App APIs."""

import jwt
import time
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class GitHubApp:
    """Class for GitHub App authentication and interactions."""

    def __init__(self, app_id, private_key_path):
        """Initialize the GitHub App with app ID and private key path.

        Args:
            app_id (str): GitHub App ID
            private_key_path (str): Path to the private key file
        """
        self.app_id = app_id
        self.private_key_path = private_key_path
        self.private_key = None

        try:
            with open(private_key_path, "r") as key_file:
                self.private_key = key_file.read()
        except FileNotFoundError:
            logger.error(f"Private key file not found at: {private_key_path}")
            raise ValueError(f"Private key file not found: {private_key_path}")
        except Exception as e:
            logger.error(f"Error reading private key: {str(e)}")
            raise ValueError(f"Error reading private key: {str(e)}")

    def generate_jwt(self):
        """Generate a JWT token for GitHub App authentication.

        Returns:
            str: JWT token for GitHub API authentication
        """
        now = int(time.time())
        payload = {
            # Issued at time
            "iat": now,
            # JWT expiration time (10 minutes maximum)
            "exp": now + (10 * 60),
            # GitHub App's identifier
            "iss": self.app_id,
        }

        try:
            # Create JWT using RS256 algorithm
            token = jwt.encode(payload, self.private_key, algorithm="RS256")
            return token
        except Exception as e:
            logger.error(f"Error generating JWT: {str(e)}")
            raise ValueError(f"Error generating JWT: {str(e)}")
