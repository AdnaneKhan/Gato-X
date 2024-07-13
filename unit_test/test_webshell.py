from unittest.mock import patch
from unittest.mock import MagicMock

from gatox.attack.runner.webshell import WebShell


def test_ror_workflow():


    workflow = WebShell.create_ror_workflow(
        "foobar",
        "evil",
        "https://example.com",
        runner_labels=['self-hosted','super-secure']
    )


    assert "continue-on-error: true" in workflow
