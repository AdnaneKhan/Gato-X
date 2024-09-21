import unittest
from unittest.mock import MagicMock
from gatox.enumerate.reports.actions import ActionsReport
from gatox.enumerate.reports.runners import RunnersReport

PWN_DETAILS = {
    "workflow_name": "pwn1.yml",
    "workflow_url": "https://github.com/testOrg/testRepo/blob/main/.github/workflows/pwn1.yml",
    "details": {
        "candidates": {
            "build": {
                "confidence": "MEDIUM",
                "gated": False,
                "steps": [
                    {
                        "ref": "${{ github.event_name == 'pull_request_target' && format('refs/pull/{0}/merge', github.event.number) || '' }}",
                        "if_check": None,
                        "step_name": "Checkout",
                    }
                ],
                "if_check": "",
            }
        },
        "triggers": ["pull_request_target"],
    },
    "environments": [],
}

PWN_DETAILS_TOCTOU = {
    "workflow_name": "pwn2.yml",
    "workflow_url": "https://github.com/testOrg/testRepo/blob/main/.github/workflows/pwn2.yml",
    "details": {
        "candidates": {
            "build": {
                "confidence": "MEDIUM",
                "gated": False,
                "steps": [
                    {
                        "ref": "github.event.pull_request.head.ref",
                        "if_check": None,
                        "step_name": "Checkout",
                    }
                ],
                "if_check": "",
            }
        },
        "triggers": ["pull_request_target:labeled"],
    },
    "environments": [],
}


PWN_DETAILS_TOCTOU2 = {
    "workflow_name": "pwn3.yml",
    "workflow_url": "https://github.com/testOrg/testRepo/blob/main/.github/workflows/pwn3.yml",
    "details": {
        "candidates": {
            "build": {
                "confidence": "MEDIUM",
                "gated": False,
                "steps": [
                    {
                        "ref": "format('refs/pull/{0}/merge', github.event.number)",
                        "if_check": None,
                        "step_name": "Checkout",
                    }
                ],
                "if_check": "",
            }
        },
        "triggers": ["pull_request_target"],
    },
    "environments": ["ci"],
}

PWN_DETAILS_TOCTOU3 = {
    "workflow_name": "pwn4.yml",
    "workflow_url": "https://github.com/testOrg/testRepo/blob/main/.github/workflows/pwn4.yml",
    "details": {
        "candidates": {
            "build": {
                "confidence": "MEDIUM",
                "gated": True,
                "steps": [
                    {
                        "ref": "format('refs/pull/{0}/merge', github.event.number)",
                        "if_check": None,
                        "step_name": "Checkout",
                    }
                ],
                "if_check": "",
            }
        },
        "triggers": ["issue_comment"],
    },
    "environments": [],
}

INJ_DETAILS = {
    "workflow_name": "inj1.yml",
    "workflow_url": "https://github.com/testOrg/testRepo/blob/main/.github/workflows/inj1.yml",
    "details": {
        "build": {
            "if_check": None,
            "Set comment body": {"variables": ["steps.extract.outputs.filename"]},
        },
        "triggers": ["pull_request_target"],
    },
    "environments": [],
}


def test_report_pwn(capfd):
    """Test reporting a pwn request vulnerability."""
    repository = MagicMock()
    repository.pwn_req_risk = [PWN_DETAILS]

    ActionsReport.report_pwn(repository)

    out, err = capfd.readouterr()

    assert "The workflow runs on a risky trigger and might check out the PR" in out
    assert "Checkout Ref: ${{ github.event_name == 'pull_request_target' && format('refs/pull/{0}/merge', github.event.number) || '' }}"


def test_report_pwn_toctou_label(capfd):
    """Test reporting a pwn request vulnerability with TOCTOU."""

    repository = MagicMock()
    repository.pwn_req_risk = [PWN_DETAILS_TOCTOU]
    repository.name = "testOrg/testRepo"

    ActionsReport.report_pwn(repository)
    out, err = capfd.readouterr()

    assert " The workflow contains label-based gating but the workflow uses a" in out
    assert "Checkout Ref: github.event.pull_request.head.ref" in out
    assert "Trigger(s): pull_request_target:labeled" in out


def test_report_pwn_toctou_env(capfd):
    """Test reporting a pwn request vulnerability with TOCTOU, where
    the gate check if a deployment environment.
    """

    repository = MagicMock()
    repository.pwn_req_risk = [PWN_DETAILS_TOCTOU2]
    repository.name = "testOrg/testRepo"

    ActionsReport.report_pwn(repository)
    out, err = capfd.readouterr()

    assert "Issue Type: Pwn Request with Approval TOCTOU" in out
    assert "Checkout Ref: format('refs/pull/{0}/merge', github.event.number)" in out


def test_report_pwn_toctou_comment(capfd):
    """Test reporting a pwn request vulnerability with TOCTOU, where
    the gate check if a deployment environment.
    """

    repository = MagicMock()
    repository.pwn_req_risk = [PWN_DETAILS_TOCTOU3]
    repository.name = "testOrg/testRepo"

    ActionsReport.report_pwn(repository)
    out, err = capfd.readouterr()

    assert "Issue Type: Pwn Request With Permission TOCTOU" in out
    assert "Checkout Ref: format('refs/pull/{0}/merge', github.event.number)" in out
    assert "The workflow contains a permission check, but uses a mutable" in out


def test_report_inj(capfd):
    """Test reporting an injection vulnerability."""
    repository = MagicMock()
    repository.name = "testOrg/testRepo"
    repository.injection_risk = [INJ_DETAILS]
    ActionsReport.report_injection(repository)

    out, err = capfd.readouterr()

    assert " The workflow uses variables by context expression within run or" in out
