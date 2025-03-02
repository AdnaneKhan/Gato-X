import requests
import json

from gatox.configuration.configuration_manager import ConfigurationManager


def send_slack_webhook(message):
    # Create the payload
    payload = {"text": json.dumps(message, indent=4)}
    hooks = ConfigurationManager().NOTIFICATIONS["SLACK_WEBHOOKS"]

    for webhook in hooks:
        # Send the request
        response = requests.post(webhook, json=payload)
        # Check the response
        if response.status_code != 200:
            raise ValueError(
                "Request to slack returned an error %s, the response is:\n%s"
                % (response.status_code, response.text)
            )
