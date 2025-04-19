import time
import logging
import asyncio
from typing import Optional, Set

from gatox.github.api import Api
from gatox.cli.output import Output
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


class Search:
    """Search utility for GH api in order to find public repos that may have
    security issues.
    """

    def __init__(self, api_accessor: Api):
        """Initialize class to call GH search methods.

        Args:
            api_accesor (Api): API accessor to use when making GitHub
            API requests.
        """
        self.api_accessor = api_accessor

    async def search_enumeration(self, org: str) -> Optional[Set[str]]:
        """Search for interesting targets within an organization.

        Args:
            org (str): Organization to search within.

        Returns:
            Set[str]: Set of repository names that matched the search criteria.
        """
        query = f"org:{org} filename:yml filename:yaml path:.github/workflows"

        Output.info(f"Querying workflow files in {Output.bright(org)}!")

        results = set()
        attempt = 0
        while attempt < 5:
            try:
                search_response = await self.api_accessor.call_get(
                    "/search/code",
                    params={"q": query, "per_page": "100"},
                )

                if search_response.status_code == 403:
                    if "rate limit exceeded" in search_response.text.lower():
                        Output.warn("[!] Secondary API Rate Limit Hit.")
                        await asyncio.sleep(30)
                        attempt += 1
                        continue
                    elif "number of indexes" in search_response.text.lower():
                        Output.error(
                            f"{org} contains too many results for "
                            f"the search API to handle!"
                        )
                        return None
                    else:
                        Output.warn(f"403 from the API: {search_response.text}")
                        return None

                if search_response.status_code == 401:
                    Output.error("Token cannot perform this enumeration!")
                    return None

                if search_response.status_code == 422:
                    Output.error("Unprocessable entity, likely invalid org/user name!")
                    return None

                if search_response.status_code != 200:
                    Output.error(
                        f"Failed to retrieve search results: {search_response.status_code}"
                    )
                    return None

                search_results = search_response.json()

                if search_results["total_count"] == 0:
                    Output.warn("No results were found!")
                    return None

                Output.info(
                    f"The org has "
                    f"{Output.bright(str(search_results['total_count']))}"
                    " workflow files!"
                )

                current_page = search_results
                while True:
                    for item in current_page["items"]:
                        if not item["repository"]["fork"]:
                            results.add(item["repository"]["full_name"])

                    if "next" not in search_response.links:
                        break

                    await asyncio.sleep(2)  # Rate limit compliance
                    search_response = await self.api_accessor.call_get(
                        search_response.links["next"]["url"],
                        strip_auth=True,
                    )
                    if search_response.status_code != 200:
                        break

                    current_page = search_response.json()

                break

            except Exception as e:
                logger.error(f"Exception searching org: {str(e)}")
                return None

        return results
