import base64
import os
import pytest
import pathlib
import logging

from unittest.mock import MagicMock, patch

from gatox.github.api import Api
from gatox.cli.output import Output

logging.root.setLevel(logging.DEBUG)

output = Output(False)


@pytest.fixture
def api_access():

    # This PAT is INVALID,
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(test_pat, "2022-11-28")

    yield abstraction_layer


def test_initialize():
    """Test initialization of API abstraction layer."""

    # This PAT is INVALID,
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(test_pat, "2022-11-28")

    assert abstraction_layer.pat == test_pat
    assert abstraction_layer.verify_ssl is True


def test_socks(api_access):
    """Test that we can successfully configure a SOCKS proxy."""
    # This PAT is INVALID,
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(test_pat, "2022-11-28", socks_proxy="localhost:9090")

    assert abstraction_layer.proxies["http"] == "socks5://localhost:9090"
    assert abstraction_layer.proxies["https"] == "socks5://localhost:9090"


def test_http_proxy(api_access):
    """Test that we can successfully configure an HTTP proxy."""
    # This PAT is INVALID,
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(test_pat, "2022-11-28", http_proxy="localhost:1080")

    assert abstraction_layer.proxies["http"] == "http://localhost:1080"
    assert abstraction_layer.proxies["https"] == "http://localhost:1080"


@patch("gatox.github.api.requests.get")
def test_user_scopes(mock_get):
    """Check user."""
    # This PAT is INVALID,
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(test_pat, "2022-11-28")

    mock_result = MagicMock()
    mock_result.configure_mock(
        **{
            "headers.get.return_value": "repo, admin:org",
            "json.return_value": {"login": "TestUserName", "name": "TestUser"},
            "status_code": 200,
        }
    )

    mock_get.return_value = mock_result

    user_info = abstraction_layer.check_user()

    assert user_info["user"] == "TestUserName"
    assert "repo" in user_info["scopes"]


def test_socks_and_http(api_access):
    """Test initializing API abstraction layer with SOCKS and HTTP proxy,
    which should raise a valueerror.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    with pytest.raises(ValueError):
        Api(
            test_pat,
            "2022-11-28",
            socks_proxy="localhost:1090",
            http_proxy="localhost:8080",
        )


@patch("gatox.github.api.requests.get")
def test_validate_sso(mock_get):
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(test_pat, "2022-11-28")

    mock_get().status_code = 200

    res = abstraction_layer.validate_sso("testorg", "testRepo")

    assert res is True


@patch("gatox.github.api.requests.get")
def test_validate_sso_fail(mock_get):
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(test_pat, "2022-11-28")

    mock_get().status_code = 403

    res = abstraction_layer.validate_sso("testorg", "testRepo")

    assert res is False


@patch("gatox.github.api.requests.get")
def test_invalid_pat(mock_get):
    """Test calling a request with an invalid PAT"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(test_pat, "2022-11-28")

    mock_get().status_code = 401

    assert abstraction_layer.check_user() is None


@patch("gatox.github.api.requests.delete")
def test_delete_repo(mock_delete):
    """Test forking a repository"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_delete().status_code = 204

    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.delete_repository("testOrg/TestRepo")

    assert result is True


@patch("gatox.github.api.requests.delete")
def test_delete_fail(mock_delete):
    """Test forking a repository"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_delete().status_code = 403
    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.delete_repository("testOrg/TestRepo")

    assert result is False


@patch("gatox.github.api.requests.post")
def test_fork_repository(mock_post):
    """Test fork repo happy path"""

    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_post().status_code = 202

    mock_post.return_value.json.return_value = {"full_name": "myusername/TestRepo"}
    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.fork_repository("testOrg/TestRepo")

    assert result == "myusername/TestRepo"


@patch("gatox.github.api.requests.post")
def test_fork_repository_forbid(mock_post):
    """Test repo fork forbidden."""

    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_post().status_code = 403

    mock_post.return_value.json.return_value = {"full_name": "myusername/TestRepo"}
    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.fork_repository("testOrg/TestRepo")
    assert result is False


@patch("gatox.github.api.requests.post")
def test_fork_repository_notfound(mock_post):
    """Test repo fork 404."""

    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_post().status_code = 404

    mock_post.return_value.json.return_value = {"full_name": "myusername/TestRepo"}
    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.fork_repository("testOrg/TestRepo")
    assert result is False


@patch("gatox.github.api.requests.post")
def test_fork_repository_fail(mock_post):
    """Test repo fork failure"""

    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_post().status_code = 422

    mock_post.return_value.json.return_value = {"full_name": "myusername/TestRepo"}
    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.fork_repository("testOrg/TestRepo")
    assert result is False


@patch("gatox.github.api.requests.post")
def test_fork_pr(mock_post):
    """Test creating a fork PR"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_post().status_code = 201

    mock_post.return_value.json.return_value = {
        "html_url": "https://github.com/testOrg/testRepo/pull/11"
    }

    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.create_fork_pr(
        "testOrg/testRepo", "testuser", "badBranch", "develop", "Test PR Title"
    )

    assert result == "https://github.com/testOrg/testRepo/pull/11"


@patch("gatox.github.api.requests.post")
def test_fork_pr_failed(mock_post):
    """Test creating a fork PR"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_post().status_code = 401

    mock_post.return_value.json.return_value = {
        "html_url": "https://github.com/testOrg/testRepo/pull/11"
    }

    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.create_fork_pr(
        "testOrg/testRepo", "testuser", "badBranch", "develop", "Test PR Title"
    )

    assert result is None


@patch("gatox.github.api.requests.get")
def test_get_repo(mock_get):
    """Test getting repo info."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200
    mock_get.return_value.json.return_value = {"repo1": "fakerepodata"}

    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.get_repository("testOrg/TestRepo")

    assert result["repo1"] == "fakerepodata"


@patch("gatox.github.api.requests.get")
def test_get_org(mock_get):
    """Test retrievign org info."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200
    mock_get.return_value.json.return_value = {"org1": "fakeorgdata"}

    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.get_organization_details("testOrg")

    assert result["org1"] == "fakeorgdata"


@patch("gatox.github.api.requests.get")
def test_get_org_notfound(mock_get):
    """Test 404 code when retrieving org info."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 404

    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.get_organization_details("testOrg")

    assert result is None


@patch("gatox.github.api.requests.get")
def test_check_org_runners(mock_get):
    """Test method to retrieve runners from org."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200

    mock_get.return_value.json.return_value = {"total_count": 5}

    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.check_org_runners("testOrg")

    assert result == {"total_count": 5}


@patch("gatox.github.api.requests.get")
def test_check_org_runners_fail(mock_get):
    """Test method to retrieve runners from org."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 403

    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.check_org_runners("testOrg")

    assert result is None


@patch("gatox.github.api.requests.get")
def test_check_repo_runners(mock_get):
    """Test method to retrieve runners from org."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200

    runner_list = [
        {"runnerinfo": "test"},
        {"runnerinfo": "test"},
        {"runnerinfo": "test"},
    ]
    mock_get.return_value.json.return_value = {"runners": runner_list}

    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.get_repo_runners("testOrg/TestRepo")

    assert result == runner_list

    mock_get().status_code = 401

    result = abstraction_layer.get_repo_runners("testOrg/TestRepo")
    assert not result


@patch("gatox.github.api.requests.get")
def test_check_org_repos_invalid(mock_get):
    """Test method to retrieve runners from org."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(test_pat, "2022-11-28")

    with pytest.raises(ValueError):
        abstraction_layer.check_org_repos("testOrg", "invalid")


@patch("gatox.github.api.requests.get")
def test_check_org_repos(mock_get):
    """Test method to retrieve runners from org."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200

    mock_get.return_value.json.return_value = [
        {"repo1": "fakerepodata", "archived": False},
        {"repo2": "fakerepodata", "archived": False},
        {"repo3": "fakerepodata", "archived": False},
        {"repo4": "fakerepodata", "archived": False},
        {"repo5": "fakerepodata", "archived": False},
    ]

    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.check_org_repos("testOrg", "internal")

    assert len(result) == 5


@patch("gatox.github.api.requests.get")
def test_check_org(mock_get):
    """Test method to retrieve runners from org."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200

    mock_get.return_value.json.return_value = [
        {"login": "org1"},
        {"login": "org2"},
        {"login": "org3"},
        {"login": "org4"},
        {"login": "org5"},
    ]

    abstraction_layer = Api(test_pat, "2022-11-28")

    result = abstraction_layer.check_organizations()

    assert len(result) == 5
    assert result[0] == "org1"


@patch("gatox.github.api.requests.get")
def test_retrieve_run_logs(mock_get):
    """Test retrieving run logs."""
    curr_path = pathlib.Path(__file__).parent.resolve()
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200

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

    abstraction_layer = Api(test_pat, "2022-11-28")
    logs = abstraction_layer.retrieve_run_logs(
        "testOrg/testRepo", workflows=["build.yml"]
    )

    assert len(logs) == 1
    assert list(logs)[0]["runner_name"] == "runner-30"

    logs = abstraction_layer.retrieve_run_logs(
        "testOrg/testRepo", workflows=["build.yml"]
    )

    assert len(logs) == 1
    assert list(logs)[0]["runner_name"] == "runner-30"


@patch("gatox.github.api.requests.get")
def test_parse_wf_runs(mock_get):
    """Test retrieving wf run count."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 200

    mock_get.return_value.json.return_value = {"total_count": 2}

    abstraction_layer = Api(test_pat, "2022-11-28")
    wf_count = abstraction_layer.parse_workflow_runs("testOrg/testRepo")

    assert wf_count == 2


@patch("gatox.github.api.requests.get")
def test_parse_wf_runs_fail(mock_get):
    """Test 403 code when retrieving wf run count"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get().status_code = 403

    abstraction_layer = Api(test_pat, "2022-11-28")
    wf_count = abstraction_layer.parse_workflow_runs("testOrg/testRepo")

    assert wf_count is None


@patch("gatox.github.api.requests.get")
def test_get_recent_workflow(mock_get):
    """Test retrieving a recent workflow by sha."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "total_count": 1,
        "workflow_runs": [{"id": 15, "path": ".github/workflows/testwf.yml@main"}],
    }

    api = Api(test_pat, "2022-11-28")
    workflow_id = api.get_recent_workflow("repo", "sha", "testwf")

    assert workflow_id == 15


@patch("gatox.github.api.requests.get")
def test_get_recent_workflow_missing(mock_get):
    """Test retrieving a missing recent workflow by sha."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "total_count": 0,
        "workflow_runs": [],
        "path": ".github/workflows/testwf.yml@main",
    }

    api = Api(test_pat, "2022-11-28")
    workflow_id = api.get_recent_workflow("repo", "sha", "testwf")

    assert workflow_id == 0


@patch("gatox.github.api.requests.get")
def test_get_recent_workflow_fail(mock_get):
    """Test failing the retrieval of a recent workflow by sha."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 401

    api = Api(test_pat, "2022-11-28")
    workflow_id = api.get_recent_workflow("repo", "sha", "testwf")

    assert workflow_id == -1


@patch("gatox.github.api.requests.get")
def test_get_workflow_status_queued(mock_get):
    """Test retrieving the status of a workflow."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"status": "queued"}

    api = Api(test_pat, "2022-11-28")
    assert api.get_workflow_status("repo", 5) == 0


@patch("gatox.github.api.requests.get")
def test_get_workflow_status_failed(mock_get):
    """Test retrieving the status of a workflow."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "status": "completed",
        "conclusion": "failure",
    }

    api = Api(test_pat, "2022-11-28")
    assert api.get_workflow_status("repo", 5) == -1


@patch("gatox.github.api.requests.get")
def test_get_workflow_status_errorr(mock_get):
    """Test retrieving the status of a workflow."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 401

    api = Api(test_pat, "2022-11-28")
    assert api.get_workflow_status("repo", 5) == -1


@patch("gatox.github.api.requests.delete")
def test_delete_workflow_fail(mock_get):
    """Test retrieving the status of a workflow."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 401

    api = Api(test_pat, "2022-11-28")
    assert not api.delete_workflow_run("repo", 5)


@patch("gatox.github.api.open")
@patch("gatox.github.api.requests.get")
def test_download_workflow_success(mock_get, mock_open):
    """Test retrieving the status of a workflow."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 200

    api = Api(test_pat, "2022-11-28")
    assert api.download_workflow_logs("repo", 5)


@patch("gatox.github.api.open")
@patch("gatox.github.api.requests.get")
def test_download_workflow_fail(mock_get, mock_open):
    """Test retrieving the status of a workflow."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 401

    api = Api(test_pat, "2022-11-28")
    assert not api.download_workflow_logs("repo", 5)


@patch("gatox.github.api.requests.get")
def test_get_repo_branch(mock_get):
    """Test retrieving the existence of a branch."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_get.return_value.status_code = 200

    api = Api(test_pat, "2022-11-28")
    assert api.get_repo_branch("repo", "branch") == 1

    mock_get.return_value.status_code = 404
    assert api.get_repo_branch("repo", "branch") == 0

    mock_get.return_value.status_code = 401
    assert api.get_repo_branch("repo", "branch") == -1


@patch("gatox.github.api.requests.post")
@patch("gatox.github.api.requests.get")
def test_create_branch(mock_get, mock_post):
    """Test creating a new branch"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get.return_value.status_code = 200

    mock_get.return_value.json.side_effect = [
        {"default_branch": "dev"},
        {
            "ref": "refs/heads/dev",
            "node_id": "REF_AAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "url": "https://api.github.com/repos/testOrg/testRepo/git/refs/heads/dev",
            "object": {
                "sha": "988881adc9fc3655077dc2d4d757d480b5ea0e11",
                "type": "commit",
                "url": "https://api.github.com/repos/praetorian-inc/testOrg/commits/988881adc9fc3655077dc2d4d757d480b5ea0e11",
            },
        },
    ]

    mock_post.return_value.status_code = 201

    api = Api(test_pat, "2022-11-28")

    assert api.create_branch("test_repo", "abcdefg") is True


@patch("gatox.github.api.requests.post")
@patch("gatox.github.api.requests.get")
def test_create_branch_fail(mock_get, mock_post):
    """Test creating a new branch"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_get.return_value.status_code = 200

    mock_get.return_value.json.side_effect = [
        {"default_branch": "dev"},
        {
            "ref": "refs/heads/dev",
            "node_id": "REF_AAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "url": "https://api.github.com/repos/testOrg/testRepo/git/refs/heads/dev",
            "object": {
                "sha": "988881adc9fc3655077dc2d4d757d480b5ea0e11",
                "type": "commit",
                "url": "https://api.github.com/repos/praetorian-inc/testOrg/commits/988881adc9fc3655077dc2d4d757d480b5ea0e11",
            },
        },
    ]

    mock_post.return_value.status_code = 422

    api = Api(test_pat, "2022-11-28")

    assert api.create_branch("test_repo", "abcdefg") is False


@patch("gatox.github.api.requests.delete")
def test_delete_branch(mock_delete):
    """Test deleting branch"""

    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_delete.return_value.status_code = 204
    api = Api(test_pat, "2022-11-28")

    assert api.delete_branch("testRepo", "testBranch")


@patch("gatox.github.api.requests.put")
def test_commit_file(mock_put):
    """Test commiting a file"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    test_filedata = b"foobarbaz"

    test_sha = "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"

    mock_put.return_value.status_code = 201
    mock_put.return_value.json.return_value = {"commit": {"sha": test_sha}}

    api = Api(test_pat, "2022-11-28")

    commit_sha = api.commit_file(
        "testOrg/testRepo",
        "testBranch",
        "test/newFile",
        test_filedata,
        commit_author="testUser",
        commit_email="testemail@example.org",
    )

    assert commit_sha == test_sha


@patch("gatox.github.api.requests.get")
def test_workflow_ymls(mock_get):
    """Test retrieving workflow yml files using the API."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
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
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.side_effect = [
        test_return,
        test_file_content,
    ]

    api = Api(test_pat, "2022-11-28")
    ymls = api.retrieve_workflow_ymls("testOrg/testRepo")

    assert len(ymls) == 1
    assert ymls[0].workflow_name == "integration.yaml"
    assert ymls[0].workflow_contents == "FooBarBaz"


@patch("gatox.github.api.requests.get")
def test_get_secrets(mock_get):
    """Test getting repo secret names."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "total_count": 3,
        "secrets": [{}, {}, {}],
    }

    secrets = api.get_secrets("testOrg/testRepo")

    assert len(secrets) == 3


@patch("gatox.github.api.requests.get")
def test_get_org_secrets(mock_get):
    """Tests getting org secrets"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.side_effect = [
        {
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
        },
        {
            "total_count": 2,
            "repositories": [
                {"full_name": "testOrg/testRepo1"},
                {"full_name": "testOrg/testRepo2"},
            ],
        },
    ]

    secrets = api.get_org_secrets("testOrg")

    assert len(secrets) == 2
    assert secrets[0]["name"] == "DEPLOY_TOKEN"
    assert secrets[1]["name"] == "GH_TOKEN"
    assert len(secrets[1]["repos"]) == 2


@patch("gatox.github.api.requests.get")
def test_get_org_secrets_empty(mock_get):
    """Tests getting org secrets"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"total_count": 0, "secrets": []}

    secrets = api.get_org_secrets("testOrg")

    assert secrets == []


@patch("gatox.github.api.requests.get")
def test_get_repo_org_secrets(mock_get):
    """Tests getting org secrets accessible to a repo."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"total_count": 3, "secrets": [{}, {}]}

    secrets = api.get_repo_org_secrets("testOrg/testRepo")

    assert len(secrets) == 2


@patch("gatox.github.api.time")
def test_handle_ratelimit(mock_time):
    """Test rate limit handling"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")

    test_headers = {
        "X-Ratelimit-Remaining": 100,
        "Date": "Fri, 09 Jun 2023 22:12:41 GMT",
        "X-Ratelimit-Reset": 1686351401,
        "X-Ratelimit-Resource": "core",
        "X-RateLimit-Limit": 5000,
    }

    api._Api__check_rate_limit(test_headers)

    mock_time.sleep.assert_called_once()


@patch("gatox.github.api.requests.get")
@patch("gatox.github.api.requests.post")
def test_commit_workflow(mock_call_post, mock_call_get):
    # Arrange
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")
    mock_call_get.side_effect = [
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
    mock_call_post.side_effect = [
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "abc"})),
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "def"})),
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "ghi"})),
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "jkl"})),
    ]

    # Act
    result = api.commit_workflow(
        "test_repo", "test_branch", b"test_content", "test_file"
    )

    # Assert
    assert result == "ghi"
    assert mock_call_get.call_count == 4
    assert mock_call_post.call_count == 4


@patch("gatox.github.api.requests.get")
@patch("gatox.github.api.requests.post")
def test_commit_workflow_failure(mock_call_post, mock_call_get):
    # Arrange
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")
    mock_call_get.side_effect = [
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
    mock_call_post.side_effect = [
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "abc"})),
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "def"})),
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "ghi"})),
        MagicMock(status_code=400, json=MagicMock(return_value={"sha": "jkl"})),
    ]

    # Act
    result = api.commit_workflow(
        "test_repo", "test_branch", b"test_content", "test_file"
    )

    # Assert
    assert result is None
    assert mock_call_get.call_count == 4
    assert mock_call_post.call_count == 4


@patch("gatox.github.api.requests.get")
@patch("gatox.github.api.requests.post")
def test_commit_workflow_failure2(mock_call_post, mock_call_get):
    # Arrange
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")
    mock_call_get.side_effect = [
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
    mock_call_post.side_effect = [
        MagicMock(status_code=201, json=MagicMock(return_value={"sha": "abc"})),
        MagicMock(status_code=404, json=MagicMock(return_value=None)),
    ]

    # Act
    result = api.commit_workflow(
        "test_repo", "test_branch", b"test_content", "test_file"
    )

    # Assert
    assert result is None
    assert mock_call_get.call_count == 4
    assert mock_call_post.call_count == 2


@patch("gatox.github.api.requests.get")
@patch("gatox.github.api.requests.post")
def test_graphql_org_query(mock_call_post, mock_call_get):
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")

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

    mock_call_post.side_effect = [
        MagicMock(status_code=200, json=MagicMock(return_value=mock_results)),
    ]

    names = api.get_org_repo_names_graphql("testOrg", "PUBLIC")

    assert "TestWF2" in names
    assert "TestPwnRequest" in names
    assert "BH_DC_2024Demo" in names


def test_graphql_org_query_badtype():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")

    with pytest.raises(ValueError):
        api.get_org_repo_names_graphql("testOrg", "UNKNOWN")


@patch("gatox.github.api.requests.get")
@patch("gatox.github.api.requests.post")
def test_graphql_mergedat_query(mock_call_post, mock_call_get):
    """ """
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

    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")

    mock_call_post.side_effect = [
        MagicMock(status_code=200, json=MagicMock(return_value=mock_results)),
    ]

    date = api.get_commit_merge_date(
        "testOrg/testRepo", "9659fdc7ba35a9eba00c183bccc67083239383e8"
    )

    assert date == "2024-06-21T09:57:58Z"


@patch("gatox.github.api.requests.get")
def test_get_user_type(mock_call_get):

    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")

    mock_call_get.side_effect = [
        MagicMock(status_code=200, json=MagicMock(return_value={"type": "User"})),
    ]

    user_type = api.get_user_type("someUser")

    assert user_type == "User"


@patch("gatox.github.api.requests.get")
def test_get_user_repos(mock_call_get):
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")

    mock_call_get.side_effect = [
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

    repos = api.get_user_repos("someUser")

    assert repos[0] == "testRepo"
    assert repos[1] == "testRepo2"


@patch("gatox.github.api.requests.get")
def test_get_own_repos_single_page(mock_call_get):
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")

    # Mock the API response for a single page
    mock_call_get.side_effect = [
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value=[
                    {"full_name": "owner/testRepo", "archived": False},
                    {"full_name": "owner/testRepo2", "archived": False},
                ]
            ),
        ),
    ]
    repos = api.get_own_repos()
    assert repos == ["owner/testRepo", "owner/testRepo2"]
    mock_call_get.assert_called_once()


@patch("gatox.github.api.requests.get")
def test_get_own_repos_multiple_pages(mock_call_get):
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")

    def generate_repo_list():
        """
        Generate a list containing 100 copies of a predefined repository dictionary.

        Returns:
            list: A list of 100 repository dictionaries.
        """
        repo_dict = {"full_name": "owner/repo1", "archived": False}
        repo_list = [repo_dict for _ in range(100)]
        return repo_list

    # Mock the API response for multiple pages
    mock_call_get.side_effect = [
        MagicMock(status_code=200, json=MagicMock(return_value=generate_repo_list())),
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value=[{"full_name": "owner/repo101", "archived": False}]
            ),
        ),
    ]

    repos = api.get_own_repos()
    assert len(repos) == 101
    assert mock_call_get.call_count == 2


@patch("gatox.github.api.requests.get")
def test_get_own_repos_empty_response(mock_call_get):

    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    api = Api(test_pat, "2022-11-28")

    # Mock the API response for an empty response

    mock_call_get.return_value.status_code = 200
    mock_call_get.return_value.json.return_value = []

    repos = api.get_own_repos()
    assert repos == []
    mock_call_get.assert_called_once()
