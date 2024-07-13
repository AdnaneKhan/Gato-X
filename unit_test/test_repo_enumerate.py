import os
import pathlib
import pytest
import json

from unittest.mock import MagicMock

from gatox.models.repository import Repository
from gatox.enumerate.repository import RepositoryEnum
from gatox.cli.output import Output

TEST_REPO_DATA = None
TEST_WORKFLOW_YML = None

Output(True)


@pytest.fixture(scope="session", autouse=True)
def load_test_files(request):
    global TEST_REPO_DATA
    global TEST_WORKFLOW_YML
    curr_path = pathlib.Path(__file__).parent.resolve()
    test_repo_path = os.path.join(curr_path, "files/example_repo.json")
    test_wf_path = os.path.join(curr_path, 'files/main.yaml')

    with open(test_repo_path, 'r') as repo_data:
        TEST_REPO_DATA = json.load(repo_data)

    with open(test_wf_path, 'r') as wf_data:
        TEST_WORKFLOW_YML = wf_data.read()


def test_enumerate_repo():
    """Test constructor for enumerator.
    """
    mock_api = MagicMock()

    gh_enumeration_runner = RepositoryEnum(
        mock_api, False, True
    )

    mock_api.check_user.return_value = {
        "user": 'testUser',
        "scopes": ['repo', 'workflow']
    }

    mock_api.retrieve_run_logs.return_value = [{
        "machine_name": "unittest1",
        "runner_name": "much_unit_such_test",
        "runner_type": "organization",
        "non_ephemeral": False,
        "token_permissions": {
            "Actions": "write"
        },
        "runner_group": "Default",
        "requested_labels": [
            "self-hosted",
            "Linux",
            "X64"
        ]
    }]

    repo_data = json.loads(json.dumps(TEST_REPO_DATA))
    test_repo = Repository(repo_data)

    gh_enumeration_runner.enumerate_repository(
        test_repo
    )

    assert test_repo.sh_runner_access is True
    assert len(test_repo.accessible_runners) > 0
    assert test_repo.accessible_runners[0].runner_name == "much_unit_such_test"


def test_enumerate_repo_admin():
    """Test constructor for enumerator.
    """
    mock_api = MagicMock()

    gh_enumeration_runner = RepositoryEnum(
        mock_api, False, True
    )

    mock_api.check_user.return_value = {
        "user": 'testUser',
        "scopes": ['repo', 'workflow']
    }

    mock_api.retrieve_run_logs.return_value = [{
        "machine_name": "unittest1",
        "runner_name": "much_unit_such_test",
        "runner_type": "organization",
        "non_ephemeral": False,
        "token_permissions": {
            "Actions": "write"
        },
        "runner_group": "Default",
        "requested_labels": [
            "self-hosted",
            "Linux",
            "X64"
        ]
    }]

    repo_data = json.loads(json.dumps(TEST_REPO_DATA))
    repo_data['permissions']['admin'] = True
    test_repo = Repository(repo_data)

    gh_enumeration_runner.enumerate_repository(
        test_repo
    )

    assert test_repo.is_admin()
