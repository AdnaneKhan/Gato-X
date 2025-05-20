import jwt
import time
import httpx
from pathlib import Path
from typing import List, Dict, Any

class GitHubAppEnumerator:
    def __init__(self, app_id: str, pem_path: str, api_url: str = "https://api.github.com"):
        self.app_id = app_id
        self.pem_path = pem_path
        self.api_url = api_url
        self.jwt = self._generate_jwt()

    def _generate_jwt(self) -> str:
        private_key = Path(self.pem_path).read_text()
        now = int(time.time())
        payload = {
            'iat': now - 60,
            'exp': now + (10 * 60),
            'iss': self.app_id
        }
        token = jwt.encode(payload, private_key, algorithm='RS256')
        return token

    async def get_installations(self) -> List[Dict[str, Any]]:
        headers = {"Authorization": f"Bearer {self.jwt}", "Accept": "application/vnd.github+json"}
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.api_url}/app/installations", headers=headers)
            resp.raise_for_status()
            return resp.json()

    async def get_installation_token(self, installation_id: int) -> str:
        headers = {"Authorization": f"Bearer {self.jwt}", "Accept": "application/vnd.github+json"}
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{self.api_url}/app/installations/{installation_id}/access_tokens", headers=headers)
            resp.raise_for_status()
            return resp.json()["token"]

    async def get_installation_repos(self, installation_token: str) -> List[Dict[str, Any]]:
        headers = {"Authorization": f"Bearer {installation_token}", "Accept": "application/vnd.github+json"}
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.api_url}/installation/repositories", headers=headers)
            resp.raise_for_status()
            return resp.json()["repositories"]

    async def get_installation_permissions(self, installation_token: str) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {installation_token}", "Accept": "application/vnd.github+json"}
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.api_url}/user/installations", headers=headers)
            resp.raise_for_status()
            return resp.json()
