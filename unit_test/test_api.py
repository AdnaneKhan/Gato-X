import base64
import os
import pytest
import pathlib
import logging


from unittest.mock import MagicMock, patch

from gatox.github.api import Api
from gatox.cli.output import Output
from gatox.github.gql_queries import GqlQueries

logging.root.setLevel(logging.DEBUG)

output = Output(False)


@pytest.fixture(scope="function", autouse=True)
def mock_all_requests():
    with (
        patch("gatox.github.api.requests.get") as mock_get,
        patch("gatox.github.api.requests.post") as mock_post,
        patch("gatox.github.api.requests.put") as mock_put,
        patch("gatox.github.api.requests.delete") as mock_delete,
    ):

        yield {
            "get": mock_get,
            "post": mock_post,
            "put": mock_put,
            "delete": mock_delete,
        }


@pytest.fixture
def api_access():
    # This PAT is INVALID
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    abstraction_layer = Api(test_pat, "2022-11-28")
    yield abstraction_layer


def assert_mock_called_with_path_and_params(mock, expected_path, expected_params=None):
    for call in mock.call_args_list:
        args, kwargs = call
        print("--")
        print(kwargs.get("json"))
        print("AND")
        print(expected_params)
        print("AND")
        print(args[0])
        print("--")
        if args[0].endswith(expected_path):
            if (
                expected_params is None
                or kwargs.get("params") == expected_params
                or kwargs.get("json") == expected_params
            ):
                return
    assert (
        False
    ), f"No call found with path '{expected_path}' and params '{expected_params}'."


def test_initialize(api_access):
    """Test initialization of API abstraction layer."""
    assert api_access.pat == "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    assert api_access.verify_ssl is True


def test_socks(api_access):
    """Test that we can successfully configure a SOCKS proxy."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    abstraction_layer = Api(test_pat, "2022-11-28", socks_proxy="localhost:9090")
    assert abstraction_layer.proxies["http"] == "socks5://localhost:9090"
    assert abstraction_layer.proxies["https"] == "socks5://localhost:9090"


def test_http_proxy(api_access):
    """Test that we can successfully configure an HTTP proxy."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    abstraction_layer = Api(test_pat, "2022-11-28", http_proxy="localhost:1080")
    assert abstraction_layer.proxies["http"] == "http://localhost:1080"
    assert abstraction_layer.proxies["https"] == "http://localhost:1080"


def test_user_scopes(api_access, mock_all_requests):
    """Check user."""
    mock_get = mock_all_requests["get"]

    mock_result = MagicMock()
    mock_result.headers.get.return_value = "repo, admin:org"
    mock_result.json.return_value = {"login": "TestUserName", "name": "TestUser"}
    mock_result.status_code = 200

    mock_get.return_value = mock_result

    user_info = api_access.check_user()

    assert user_info["user"] == "TestUserName"
    assert "repo" in user_info["scopes"]
    assert_mock_called_with_path_and_params(mock_get, "/user")


def test_socks_and_http(api_access, mock_all_requests):
    """Test initializing API abstraction layer with SOCKS and HTTP proxy,
    which should raise a ValueError.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    with pytest.raises(ValueError):
        Api(
            test_pat,
            "2022-11-28",
            socks_proxy="localhost:1090",
            http_proxy="localhost:8080",
        )


def test_validate_sso(api_access, mock_all_requests):
    """Validate SSO with successful response."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200

    res = api_access.validate_sso("testorg", "testRepo")

    assert res is True
    # assert_mock_called_with_path_and_params(mock_get, "expected_url_based_on_method_logic")


def test_validate_sso_fail(api_access, mock_all_requests):
    """Validate SSO with failed response."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 403
    res = api_access.validate_sso("testorg", "testRepo")

    assert res is False
    # assert_mock_called_with_path_and_params(mock_get, "expected_url_based_on_method_logic")


def test_invalid_pat(api_access, mock_all_requests):
    """Test calling a request with an invalid PAT"""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 401

    assert api_access.check_user() is None
    # assert_mock_called_with_path_and_params(mock_get, "expected_url_based_on_method_logic")


def test_delete_repo(api_access, mock_all_requests):
    """Test deleting a repository"""
    mock_delete = mock_all_requests["delete"]
    mock_delete.return_value.status_code = 204

    result = api_access.delete_repository("testOrg/TestRepo")

    assert result is True
    assert_mock_called_with_path_and_params(mock_delete, "/repos/testOrg/TestRepo")


def test_delete_fail(api_access, mock_all_requests):
    """Test deleting a repository with failure"""
    mock_delete = mock_all_requests["delete"]
    mock_delete.return_value.status_code = 403

    result = api_access.delete_repository("testOrg/TestRepo")

    assert result is False
    assert_mock_called_with_path_and_params(mock_delete, "/repos/testOrg/TestRepo")


def test_fork_repository(api_access, mock_all_requests):
    """Test fork repo happy path"""
    mock_post = mock_all_requests["post"]
    mock_post.return_value.status_code = 202
    mock_post.return_value.json.return_value = {"full_name": "myusername/TestRepo"}

    result = api_access.fork_repository("testOrg/TestRepo")

    assert result == "myusername/TestRepo"
    assert_mock_called_with_path_and_params(mock_post, "/repos/testOrg/TestRepo/forks")


def test_fork_repository_forbid(api_access, mock_all_requests):
    """Test repo fork forbidden."""
    mock_post = mock_all_requests["post"]
    mock_post.return_value.status_code = 403
    mock_post.return_value.json.return_value = {"full_name": "myusername/TestRepo"}

    result = api_access.fork_repository("testOrg/TestRepo")
    assert result is False
    assert_mock_called_with_path_and_params(mock_post, "/repos/testOrg/TestRepo/forks")


def test_fork_repository_notfound(api_access, mock_all_requests):
    """Test repo fork 404."""
    mock_post = mock_all_requests["post"]
    mock_post.return_value.status_code = 404
    mock_post.return_value.json.return_value = {"full_name": "myusername/TestRepo"}

    result = api_access.fork_repository("testOrg/TestRepo")
    assert result is False
    assert_mock_called_with_path_and_params(mock_post, "/repos/testOrg/TestRepo/forks")


def test_fork_repository_fail(api_access, mock_all_requests):
    """Test repo fork failure"""
    mock_post = mock_all_requests["post"]
    mock_post.return_value.status_code = 422
    mock_post.return_value.json.return_value = {"full_name": "myusername/TestRepo"}

    result = api_access.fork_repository("testOrg/TestRepo")
    assert result is False
    assert_mock_called_with_path_and_params(mock_post, "/repos/testOrg/TestRepo/forks")


def test_fork_pr(api_access, mock_all_requests):
    """Test creating a fork PR"""
    mock_post = mock_all_requests["post"]
    mock_post.return_value.status_code = 201
    mock_post.return_value.json.return_value = {
        "html_url": "https://github.com/testOrg/testRepo/pull/11"
    }

    result = api_access.create_fork_pr(
        "testOrg/testRepo", "testuser", "badBranch", "develop", "Test PR Title"
    )

    assert result == "https://github.com/testOrg/testRepo/pull/11"

    assert_mock_called_with_path_and_params(
        mock_post,
        "/repos/testOrg/testRepo/pulls",
        expected_params={
            "title": "Test PR Title",
            "head": "testuser:badBranch",
            "base": "develop",
            "body": "This is a test pull request created for CI/CD"
            " vulnerability testing purposes.",
            "maintainer_can_modify": False,
            "draft": True,
        },
    )


def test_fork_pr_failed(api_access, mock_all_requests):
    """Test creating a fork PR with failure"""
    mock_post = mock_all_requests["post"]
    mock_post.return_value.status_code = 401
    mock_post.return_value.json.return_value = {
        "html_url": "https://github.com/testOrg/testRepo/pull/11"
    }

    result = api_access.create_fork_pr(
        "testOrg/testRepo", "testuser", "badBranch", "develop", "Test PR Title"
    )

    assert result is None
    assert_mock_called_with_path_and_params(
        mock_post,
        "/repos/testOrg/testRepo/pulls",
        expected_params={
            "title": "Test PR Title",
            "head": "testuser:badBranch",
            "base": "develop",
            "body": "This is a test pull request created for CI/CD"
            " vulnerability testing purposes.",
            "maintainer_can_modify": False,
            "draft": True,
        },
    )


def test_get_repo(api_access, mock_all_requests):
    """Test getting repo info."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"repo1": "fakerepodata"}

    result = api_access.get_repository("testOrg/TestRepo")

    assert result["repo1"] == "fakerepodata"
    assert_mock_called_with_path_and_params(mock_get, "/repos/testOrg/TestRepo")


def test_get_org(api_access, mock_all_requests):
    """Test retrieving org info."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"org1": "fakeorgdata"}

    result = api_access.get_organization_details("testOrg")

    assert result["org1"] == "fakeorgdata"
    assert_mock_called_with_path_and_params(mock_get, "/orgs/testOrg")


def test_get_org_notfound(api_access, mock_all_requests):
    """Test 404 code when retrieving org info."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 404

    result = api_access.get_organization_details("testOrg")

    assert result is None
    assert_mock_called_with_path_and_params(mock_get, "/orgs/testOrg")


def test_check_org_runners(api_access, mock_all_requests):
    """Test method to retrieve runners from org."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"total_count": 5}

    result = api_access.check_org_runners("testOrg")

    assert result == {"total_count": 5}
    assert_mock_called_with_path_and_params(mock_get, "/orgs/testOrg/actions/runners")


def test_check_org_runners_fail(api_access, mock_all_requests):
    """Test method to retrieve runners from org with failure."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 403

    result = api_access.check_org_runners("testOrg")

    assert result is None
    assert_mock_called_with_path_and_params(mock_get, "/orgs/testOrg/actions/runners")


def test_check_repo_runners(api_access, mock_all_requests):
    """Test method to retrieve runners from a repository."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200

    runner_list = [
        {"runnerinfo": "test"},
        {"runnerinfo": "test"},
        {"runnerinfo": "test"},
    ]
    mock_get.return_value.json.return_value = {"runners": runner_list}

    result = api_access.get_repo_runners("testOrg/TestRepo")

    assert result == runner_list
    assert_mock_called_with_path_and_params(
        mock_get, "/repos/testOrg/TestRepo/actions/runners"
    )

    # Simulate a failure
    mock_get.return_value.status_code = 401

    result = api_access.get_repo_runners("testOrg/TestRepo")
    assert not result
    assert mock_get.call_count == 2


def test_check_org_repos_invalid(api_access, mock_all_requests):
    """Test method to retrieve repositories from org with invalid type."""
    with pytest.raises(ValueError):
        api_access.check_org_repos("testOrg", "invalid")


def test_check_org_repos(api_access, mock_all_requests):
    """Test method to retrieve repositories from org."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = [
        {"repo1": "fakerepodata", "archived": False},
        {"repo2": "fakerepodata", "archived": False},
        {"repo3": "fakerepodata", "archived": False},
        {"repo4": "fakerepodata", "archived": False},
        {"repo5": "fakerepodata", "archived": False},
    ]

    result = api_access.check_org_repos("testOrg", "internal")

    assert len(result) == 5
    mock_get.assert_called()


def test_check_org(api_access, mock_all_requests):
    """Test method to retrieve organizations."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = [
        {"login": "org1"},
        {"login": "org2"},
        {"login": "org3"},
        {"login": "org4"},
        {"login": "org5"},
    ]

    result = api_access.check_organizations()

    assert len(result) == 5
    assert result[0] == "org1"
    assert_mock_called_with_path_and_params(mock_get, "/user/orgs")


def test_retrieve_run_logs(api_access, mock_all_requests):
    """Test retrieving run logs."""
    curr_path = pathlib.Path(__file__).parent.resolve()
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200

    # Mock the workflow runs response
    mock_get.return_value.json.return_value = {
        "workflow_runs": [
            {
                "id": 123,
                "run_attempt": 1,
                "conclusion": "success",
                "head_branch": "dev",
                "path": ".github/workflows/build.yml@dev",
            }
        ]
    }

    # Read in the zip file previously downloaded
    with open(os.path.join(curr_path, "files/run_log.zip"), "rb") as run_log:
        zip_bytes = run_log.read()
        mock_get.return_value.content = zip_bytes

    logs = api_access.retrieve_run_logs("testOrg/testRepo")

    assert len(logs) == 1
    assert list(logs)[0]["runner_name"] == "runner-30"

    logs = api_access.retrieve_run_logs("testOrg/testRepo", short_circuit=False)

    assert len(logs) == 1
    assert list(logs)[0]["runner_name"] == "runner-30"
    assert_mock_called_with_path_and_params(
        mock_get, "/repos/testOrg/testRepo/actions/runs/123/attempts/1/logs"
    )


def test_parse_wf_runs(api_access, mock_all_requests):
    """Test retrieving workflow run count."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"total_count": 2}

    wf_count = api_access.parse_workflow_runs("testOrg/testRepo")

    assert wf_count == 2
    assert_mock_called_with_path_and_params(
        mock_get, "/repos/testOrg/testRepo/actions/runs"
    )


def test_parse_wf_runs_fail(api_access, mock_all_requests):
    """Test 403 code when retrieving workflow run count"""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 403

    wf_count = api_access.parse_workflow_runs("testOrg/testRepo")

    assert wf_count is None
    assert_mock_called_with_path_and_params(
        mock_get, "/repos/testOrg/testRepo/actions/runs"
    )


def test_get_recent_workflow(api_access, mock_all_requests):
    """Test retrieving a recent workflow by sha."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "total_count": 1,
        "workflow_runs": [{"id": 15, "path": ".github/workflows/testwf.yml@main"}],
    }

    workflow_id = api_access.get_recent_workflow("repo", "MOCK_SHA", "testwf")

    assert workflow_id == 15
    assert_mock_called_with_path_and_params(
        mock_get, "/repos/repo/actions/runs", expected_params={"head_sha": "MOCK_SHA"}
    )


def test_get_recent_workflow_missing(api_access, mock_all_requests):
    """Test retrieving a missing recent workflow by sha."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "total_count": 0,
        "workflow_runs": [],
        "path": ".github/workflows/testwf.yml@main",
    }

    workflow_id = api_access.get_recent_workflow("repo", "MOCK_SHA", "testwf")

    assert workflow_id == 0
    assert_mock_called_with_path_and_params(
        mock_get, "/repos/repo/actions/runs", expected_params={"head_sha": "MOCK_SHA"}
    )


def test_get_recent_workflow_fail(api_access, mock_all_requests):
    """Test failing the retrieval of a recent workflow by sha."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 401

    workflow_id = api_access.get_recent_workflow("repo", "MOCK_SHA", "testwf")

    assert workflow_id == -1
    assert_mock_called_with_path_and_params(
        mock_get, "/repos/repo/actions/runs", expected_params={"head_sha": "MOCK_SHA"}
    )


def test_get_workflow_status_queued(api_access, mock_all_requests):
    """Test retrieving the status of a workflow."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"status": "queued"}

    assert api_access.get_workflow_status("repo", 5) == 0
    assert_mock_called_with_path_and_params(mock_get, "/repos/repo/actions/runs/5")


def test_get_workflow_status_failed(api_access, mock_all_requests):
    """Test retrieving the status of a workflow."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "status": "completed",
        "conclusion": "failure",
    }

    assert api_access.get_workflow_status("repo", 5) == -1
    assert_mock_called_with_path_and_params(mock_get, "/repos/repo/actions/runs/5")


def test_get_workflow_status_error(api_access, mock_all_requests):
    """Test retrieving the status of a workflow with error."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 401

    assert api_access.get_workflow_status("repo", 5) == -1
    assert_mock_called_with_path_and_params(mock_get, "/repos/repo/actions/runs/5")


def test_delete_workflow_fail(api_access, mock_all_requests):
    """Test deleting a workflow run with failure."""
    mock_delete = mock_all_requests["delete"]
    mock_delete.return_value.status_code = 401

    assert not api_access.delete_workflow_run("repo", 5)

    assert_mock_called_with_path_and_params(mock_delete, "/repos/repo/actions/runs/5")


def test_download_workflow_success(api_access, mock_all_requests):
    """Test downloading workflow logs successfully."""
    with patch("gatox.github.api.open", mock_open=MagicMock()) as mock_file:
        mock_get = mock_all_requests["get"]
        mock_get.return_value.status_code = 200

        assert api_access.download_workflow_logs("repo", 5)
        assert_mock_called_with_path_and_params(
            mock_get, "/repos/repo/actions/runs/5/logs"
        )
        mock_file.assert_called_once_with("5.zip", "wb+")


def test_download_workflow_fail(api_access, mock_all_requests):
    """Test downloading workflow logs with failure."""
    with patch("gatox.github.api.open", mock_open=MagicMock()) as mock_file:
        mock_get = mock_all_requests["get"]
        mock_get.return_value.status_code = 401

        assert not api_access.download_workflow_logs("repo", 5)
        assert_mock_called_with_path_and_params(
            mock_get, "/repos/repo/actions/runs/5/logs"
        )
        mock_file.assert_not_called()


def test_get_repo_branch(api_access, mock_all_requests):
    """Test retrieving the existence of a branch."""
    mock_get = mock_all_requests["get"]

    # Successful response
    mock_get.return_value.status_code = 200
    assert api_access.get_repo_branch("repo", "branch") == 1
    assert_mock_called_with_path_and_params(mock_get, "/repos/repo/branches/branch")

    # Branch not found
    mock_get.return_value.status_code = 404
    assert api_access.get_repo_branch("repo", "branch") == 0
    assert mock_get.call_count == 2

    # Unauthorized
    mock_get.return_value.status_code = 401
    assert api_access.get_repo_branch("repo", "branch") == -1
    assert mock_get.call_count == 3


def test_create_branch(api_access, mock_all_requests):
    """Test creating a new branch"""
    mock_get = mock_all_requests["get"]
    mock_post = mock_all_requests["post"]

    mock_get.side_effect = [
        MagicMock(status_code=404),
        MagicMock(
            status_code=200, json=MagicMock(return_value={"default_branch": "dev"})
        ),
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={
                    "ref": "refs/heads/dev",
                    "node_id": "REF_AAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "url": "https://api.github.com/repos/testOrg/testRepo/git/refs/heads/dev",
                    "object": {
                        "sha": "988881adc9fc3655077dc2d4d757d480b5ea0e11",
                        "type": "commit",
                        "url": "https://api.github.com/repos/praetorian-inc/testOrg/commits/988881adc9fc3655077dc2d4d757d480b5ea0e11",
                    },
                }
            ),
        ),
    ]
    mock_post.return_value.status_code = 201

    res = api_access.create_branch("testOrg/testRepo", "abcdefg")
    assert mock_get.call_count == 3
    assert_mock_called_with_path_and_params(
        mock_post,
        "/repos/testOrg/testRepo/git/refs",
        expected_params={
            "ref": "refs/heads/abcdefg",
            "sha": "988881adc9fc3655077dc2d4d757d480b5ea0e11",
        },
    )


def test_create_branch_fail(api_access, mock_all_requests):
    """Test creating a new branch with failure"""
    mock_get = mock_all_requests["get"]
    mock_post = mock_all_requests["post"]

    mock_get.side_effect = [
        MagicMock(status_code=404, json=MagicMock()),
        MagicMock(
            status_code=200, json=MagicMock(return_value={"default_branch": "dev"})
        ),
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={
                    "ref": "refs/heads/dev",
                    "node_id": "REF_AAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "url": "https://api.github.com/repos/testOrg/testRepo/git/refs/heads/dev",
                    "object": {
                        "sha": "988881adc9fc3655077dc2d4d757d480b5ea0e11",
                        "type": "commit",
                        "url": "https://api.github.com/repos/praetorian-inc/testOrg/commits/988881adc9fc3655077dc2d4d757d480b5ea0e11",
                    },
                }
            ),
        ),
    ]
    mock_post.return_value.status_code = 422

    assert api_access.create_branch("testOrg/testRepo", "abcdefg") is False
    assert mock_get.call_count == 3
    assert_mock_called_with_path_and_params(
        mock_post,
        "/repos/testOrg/testRepo/git/refs",
        expected_params={
            "ref": "refs/heads/abcdefg",
            "sha": "988881adc9fc3655077dc2d4d757d480b5ea0e11",
        },
    )


def test_commit_file(api_access, mock_all_requests):
    """Test committing a file"""
    mock_get = mock_all_requests["get"]
    mock_put = mock_all_requests["put"]

    mock_get.side_effect = [MagicMock(status_code=200), MagicMock(status_code=404)]

    test_filedata = b"foobarbaz"
    test_sha = "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"

    mock_put.return_value.status_code = 201
    mock_put.return_value.json.return_value = {"commit": {"sha": test_sha}}

    commit_sha = api_access.commit_file(
        "testOrg/testRepo",
        "testBranch",
        "test/newFile",
        test_filedata,
        commit_author="testUser",
        commit_email="testemail@example.org",
    )

    assert commit_sha == test_sha
    assert_mock_called_with_path_and_params(
        mock_put,
        "/repos/testOrg/testRepo/contents/test/newFile",
        expected_params={
            "message": "Testing",
            "content": base64.b64encode(test_filedata).decode(),
            "branch": "testBranch",
            "committer": {"name": "testUser", "email": "testemail@example.org"},
        },
    )


def test_workflow_ymls(api_access, mock_all_requests):
    """Test retrieving workflow yml files using the API."""
    mock_get = mock_all_requests["get"]
    test_return = [
        {
            "name": "integration.yaml",
            "path": ".github/workflows/integration.yaml",
            "sha": "a38970d0b6a86e1ac108854979d47ec412789708",
            "size": 2095,
            "url": "https://api.github.com/repos/praetorian-inc/gato/contents/.github/workflows/integration.yaml?ref=main",
            "html_url": "https://github.com/praetorian-inc/gato/blob/main/.github/workflows/integration.yaml",
            "git_url": "https://api.github.com/repos/praetorian-inc/gato/git/blobs/a38970d0b6a86e1ac108854979d47ec412789708",
            "download_url": "https://raw.githubusercontent.com/praetorian-inc/gato/main/.github/workflows/integration.yaml",
            "type": "file",
            "_links": {
                "self": "https://api.github.com/repos/praetorian-inc/gato/contents/.github/workflows/integration.yaml?ref=main",
                "git": "https://api.github.com/repos/praetorian-inc/gato/git/blobs/a38970d0b6a86e1ac108854979d47ec412789708",
                "html": "https://github.com/praetorian-inc/gato/blob/main/.github/workflows/integration.yaml",
            },
        }
    ]

    base64_enc = base64.b64encode(b"FooBarBaz")

    test_file_content = {"content": base64_enc}
    mock_get.side_effect = [
        MagicMock(status_code=200, json=MagicMock(return_value=test_return)),
        MagicMock(status_code=200, json=MagicMock(return_value=test_file_content)),
    ]

    ymls = api_access.retrieve_workflow_ymls("testOrg/testRepo")

    assert len(ymls) == 1
    assert ymls[0].workflow_name == "integration.yaml"
    assert ymls[0].workflow_contents == "FooBarBaz"


def test_get_secrets(api_access, mock_all_requests):
    """Test getting repo secret names."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "total_count": 3,
        "secrets": [{}, {}, {}],
    }

    secrets = api_access.get_secrets("testOrg/testRepo")

    assert len(secrets) == 3
    assert_mock_called_with_path_and_params(
        mock_get, "/repos/testOrg/testRepo/actions/secrets"
    )


def test_get_org_secrets(api_access, mock_all_requests):
    """Tests getting org secrets"""
    mock_get = mock_all_requests["get"]
    mock_get.side_effect = [
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={
                    "total_count": 2,
                    "secrets": [
                        {
                            "name": "DEPLOY_TOKEN",
                            "created_at": "2019-08-10T14:59:22Z",
                            "updated_at": "2020-01-10T14:59:22Z",
                            "visibility": "all",
                        },
                        {
                            "name": "GH_TOKEN",
                            "created_at": "2019-08-10T14:59:22Z",
                            "updated_at": "2020-01-10T14:59:22Z",
                            "visibility": "selected",
                            "selected_repositories_url": "https://api.github.com/orgs/testOrg/actions/secrets/GH_TOKEN/repositories",
                        },
                    ],
                }
            ),
        ),
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={
                    "total_count": 2,
                    "repositories": [
                        {"full_name": "testOrg/testRepo1"},
                        {"full_name": "testOrg/testRepo2"},
                    ],
                }
            ),
        ),
    ]

    secrets = api_access.get_org_secrets("testOrg")

    assert len(secrets) == 2
    assert secrets[0]["name"] == "DEPLOY_TOKEN"
    assert secrets[1]["name"] == "GH_TOKEN"
    assert len(secrets[1]["repos"]) == 2
    assert mock_get.call_count == 2
    assert_mock_called_with_path_and_params(mock_get, "/orgs/testOrg/actions/secrets")
    assert_mock_called_with_path_and_params(
        mock_get, "/orgs/testOrg/actions/secrets/GH_TOKEN/repositories"
    )


def test_get_org_secrets_empty(api_access, mock_all_requests):
    """Tests getting org secrets with empty response"""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"total_count": 0, "secrets": []}

    secrets = api_access.get_org_secrets("testOrg")

    assert secrets == []
    assert_mock_called_with_path_and_params(mock_get, "/orgs/testOrg/actions/secrets")


def test_get_repo_org_secrets(api_access, mock_all_requests):
    """Tests getting org secrets accessible to a repo."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"total_count": 2, "secrets": [{}, {}]}

    secrets = api_access.get_repo_org_secrets("testOrg/testRepo")

    assert len(secrets) == 2
    assert_mock_called_with_path_and_params(
        mock_get, "/repos/testOrg/testRepo/actions/organization-secrets"
    )


def test_handle_ratelimit(api_access, mock_all_requests):
    """Test rate limit handling"""
    mock_time = MagicMock()
    with patch("gatox.github.api.time", mock_time):
        test_headers = {
            "X-Ratelimit-Remaining": 100,
            "Date": "Fri, 09 Jun 2023 22:12:41 GMT",
            "X-Ratelimit-Reset": 1686351401,
            "X-Ratelimit-Resource": "core",
            "X-RateLimit-Limit": 5000,
        }

        api_access._Api__check_rate_limit(test_headers)

        mock_time.sleep.assert_called_once()


def test_commit_workflow(api_access, mock_all_requests):
    """Test committing a workflow successfully."""
    mock_get = mock_all_requests["get"]
    mock_post = mock_all_requests["post"]

    mock_get.side_effect = [
        MagicMock(
            status_code=200, json=MagicMock(return_value={"default_branch": "main"})
        ),
        MagicMock(status_code=200, json=MagicMock(return_value={"sha": "123"})),
        MagicMock(
            status_code=200, json=MagicMock(return_value={"tree": {"sha": "456"}})
        ),
        MagicMock(
            status_code=200, json=MagicMock(return_value={"sha": "789", "tree": []})
        ),
    ]
    mock_post.side_effect = [
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "abc"})),
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "def"})),
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "ghi"})),
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "jkl"})),
    ]

    result = api_access.commit_workflow(
        "testOrg/testRepo", "test_branch", b"test_content", "test_file"
    )

    assert result == "ghi"
    assert mock_get.call_count == 4
    assert mock_post.call_count == 4

    assert_mock_called_with_path_and_params(
        mock_post,
        "/repos/testOrg/testRepo/git/commits",
        expected_params={
            "message": "Testing",
            "tree": "def",
            "parents": ["123"],
            "author": {"name": "Gato-X", "email": "Gato-X@pwn.com"},
        },
    )

    assert_mock_called_with_path_and_params(
        mock_post,
        "/repos/testOrg/testRepo/git/refs",
        expected_params={"sha": "ghi", "ref": "refs/heads/test_branch"},
    )


def test_commit_workflow_failure(api_access, mock_all_requests):
    """Test committing a workflow with failure."""
    mock_get = mock_all_requests["get"]
    mock_post = mock_all_requests["post"]

    mock_get.side_effect = [
        MagicMock(
            status_code=200, json=MagicMock(return_value={"default_branch": "main"})
        ),
        MagicMock(status_code=200, json=MagicMock(return_value={"sha": "123"})),
        MagicMock(
            status_code=200, json=MagicMock(return_value={"tree": {"sha": "456"}})
        ),
        MagicMock(
            status_code=200, json=MagicMock(return_value={"sha": "789", "tree": []})
        ),
    ]
    mock_post.side_effect = [
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "abc"})),
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "def"})),
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "ghi"})),
        MagicMock(status_code=400, json=MagicMock(return_value={"sha": "jkl"})),
    ]

    result = api_access.commit_workflow(
        "testOrg/testRepo", "test_branch", b"test_content", "test_file"
    )

    assert result is None
    assert mock_get.call_count == 4
    assert mock_post.call_count == 4


def test_commit_workflow_failure2(api_access, mock_all_requests):
    """Test committing a workflow with partial failure."""
    mock_get = mock_all_requests["get"]
    mock_post = mock_all_requests["post"]

    mock_get.side_effect = [
        MagicMock(
            status_code=200, json=MagicMock(return_value={"default_branch": "main"})
        ),
        MagicMock(status_code=200, json=MagicMock(return_value={"sha": "123"})),
        MagicMock(
            status_code=200, json=MagicMock(return_value={"tree": {"sha": "456"}})
        ),
        MagicMock(
            status_code=200, json=MagicMock(return_value={"sha": "789", "tree": []})
        ),
    ]
    mock_post.side_effect = [
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "abc"})),
        MagicMock(status_code=404, json=MagicMock(return_value=None)),
    ]

    result = api_access.commit_workflow(
        "test_repo", "test_branch", b"test_content", "test_file"
    )

    assert result is None
    assert mock_get.call_count == 4
    assert mock_post.call_count == 2


def test_graphql_org_query(api_access, mock_all_requests):
    """Test GraphQL query for organization repositories."""
    mock_post = mock_all_requests["post"]
    mock_results = {
        "data": {
            "organization": {
                "repositories": {
                    "edges": [
                        {
                            "node": {"name": "TestWF2"},
                            "cursor": "Y3Vyc29yOnYyOpHOLK21Tw==",
                        },
                        {
                            "node": {"name": "TestPwnRequest"},
                            "cursor": "Y3Vyc29yOnYyOpHOLK24YQ==",
                        },
                        {
                            "node": {"name": "BH_DC_2024Demo"},
                            "cursor": "Y3Vyc29yOnYyOpHOMR_3jQ==",
                        },
                    ],
                    "pageInfo": {
                        "endCursor": "Y3Vyc29yOnYyOpHOMR_3jQ==",
                        "hasNextPage": False,
                    },
                }
            }
        }
    }

    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = mock_results

    names = api_access.get_org_repo_names_graphql("testOrg", "PUBLIC")

    assert "TestWF2" in names
    assert "TestPwnRequest" in names
    assert "BH_DC_2024Demo" in names
    assert_mock_called_with_path_and_params(
        mock_post,
        "/graphql",
        expected_params={
            "query": GqlQueries.GET_ORG_REPOS,
            "variables": {"orgName": "testOrg", "repoTypes": "PUBLIC", "cursor": None},
        },
    )


def test_graphql_org_query_badtype(api_access):
    """Test GraphQL query with invalid type."""
    with pytest.raises(ValueError):
        api_access.get_org_repo_names_graphql("testOrg", "UNKNOWN")


def test_graphql_mergedat_query(api_access, mock_all_requests):
    """Test GraphQL query for commit merge date."""
    mock_post = mock_all_requests["post"]
    mock_results = {
        "data": {
            "repository": {
                "commit": {
                    "associatedPullRequests": {
                        "edges": [
                            {
                                "node": {
                                    "merged": True,
                                    "mergedAt": "2024-06-21T09:57:58Z",
                                }
                            }
                        ]
                    }
                }
            }
        }
    }

    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = mock_results

    date = api_access.get_commit_merge_date(
        "testOrg/testRepo", "9659fdc7ba35a9eba00c183bccc67083239383e8"
    )

    assert date == "2024-06-21T09:57:58Z"
    assert_mock_called_with_path_and_params(
        mock_post,
        "/graphql",
        expected_params={
            "query": GqlQueries.GET_PR_MERGED,
            "variables": {
                "sha": "9659fdc7ba35a9eba00c183bccc67083239383e8",
                "repo": "testRepo",
                "owner": "testOrg",
            },
        },
    )


def test_get_user_type(api_access, mock_all_requests):
    """Test getting user type."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"type": "User"}

    user_type = api_access.get_user_type("someUser")

    assert user_type == "User"
    assert_mock_called_with_path_and_params(mock_get, "/users/someUser")


def test_get_user_repos(api_access, mock_all_requests):
    """Test getting user repositories."""
    mock_get = mock_all_requests["get"]
    mock_get.side_effect = [
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value=[
                    {"full_name": "testRepo", "archived": False},
                    {"full_name": "testRepo2", "archived": False},
                ]
            ),
        ),
    ]

    repos = api_access.get_user_repos("someUser")

    assert repos[0] == "testRepo"
    assert repos[1] == "testRepo2"
    assert_mock_called_with_path_and_params(mock_get, "/users/someUser/repos")


def test_get_own_repos_single_page(api_access, mock_all_requests):
    """Test getting own repositories with single page response."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = [
        {"full_name": "owner/testRepo", "archived": False},
        {"full_name": "owner/testRepo2", "archived": False},
    ]

    repos = api_access.get_own_repos()
    assert repos == ["owner/testRepo", "owner/testRepo2"]
    assert_mock_called_with_path_and_params(mock_get, "/user/repos")


def test_get_own_repos_multiple_pages(api_access, mock_all_requests):
    """Test getting own repositories with multiple page responses."""
    mock_get = mock_all_requests["get"]

    def generate_repo_list():
        """Generate a list containing 100 copies of a predefined repository dictionary."""
        repo_dict = {"full_name": "owner/repo1", "archived": False}
        repo_list = [repo_dict for _ in range(100)]
        return repo_list

    # Mock the API response for multiple pages
    mock_get.side_effect = [
        MagicMock(status_code=200, json=MagicMock(return_value=generate_repo_list())),
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value=[{"full_name": "owner/repo101", "archived": False}]
            ),
        ),
    ]

    repos = api_access.get_own_repos()
    assert len(repos) == 101
    assert "owner/repo1" in repos
    assert "owner/repo101" in repos
    assert mock_get.call_count == 2
    assert_mock_called_with_path_and_params(
        mock_get,
        "/user/repos",
        expected_params={
            "page": 2,
            "affiliation": "collaborator,owner",
            "per_page": 100,
        },
    )


def test_get_own_repos_empty_response(api_access, mock_all_requests):
    """Test getting own repositories with empty response."""
    mock_get = mock_all_requests["get"]
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = []

    repos = api_access.get_own_repos()
    assert repos == []
    assert_mock_called_with_path_and_params(mock_get, "/user/repos")
