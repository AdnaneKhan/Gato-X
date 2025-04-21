import httpx
import json
import asyncio
from typing import List

from gatox.configuration.configuration_manager import ConfigurationManager


async def send_slack_webhook(message: str) -> None:
    """Send a message to configured Slack webhooks asynchronously.

    Args:
        message: The message to send to Slack

    Raises:
        ValueError: If the request to Slack fails
    """
    payload = {"text": json.dumps(message, indent=4)}
    hooks: List[str] = ConfigurationManager().NOTIFICATIONS["SLACK_WEBHOOKS"]

    async with httpx.AsyncClient(
        http2=True, follow_redirects=True, timeout=10.0
    ) as client:
        for webhook in hooks:
            response = await client.post(webhook, json=payload)
            if response.status_code != 200:
                raise ValueError(
                    "Request to slack returned an error %s, the response is:\n%s"
                    % (response.status_code, response.text)
                )
