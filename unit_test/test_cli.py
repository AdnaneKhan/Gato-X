import pytest
import os
import pathlib
import requests  # If using the requests library

from unittest import mock
from unittest.mock import patch

from gatox.cli import cli
from gatox.util.arg_utils import read_file_and_validate_lines, is_valid_directory


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """
    Fixture to block real network calls during tests,
    raising an error if any attempt to send a request is made.
    """

    def mock_request(*args, **kwargs):
        raise RuntimeError("Blocked a real network call during tests.")

    monkeypatch.setattr(requests.sessions.Session, "request", mock_request)


@pytest.fixture(autouse=True)
def mock_settings_env_vars():
    """
    Fixture that mocks the GH_TOKEN environment variable
    for all tests in this module.
    """
    with mock.patch.dict(
        os.environ, {"GH_TOKEN": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
    ):
        yield


@patch("builtins.input", return_value="")
def test_cli_no_gh_token(mock_input, capfd):
    """Test case where no GH Token is provided"""
    del os.environ["GH_TOKEN"]

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-t", "test"])

    mock_input.assert_called_with(
        "No 'GH_TOKEN' environment variable set! Please enter a GitHub" " PAT.\n"
    )


def test_cli_fine_grained_pat(capfd):
    """Test case where an unsupported PAT is provided."""
    os.environ["GH_TOKEN"] = "github_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-t", "test"])
    out, err = capfd.readouterr()
    assert "not supported" in err


def test_cli_s2s_token(capfd):
    """Test case where a service-to-service token is provided."""
    os.environ["GH_TOKEN"] = "ghs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-t", "test"])
    out, err = capfd.readouterr()
    assert "not support App tokens without machine flag" in err


def test_cli_s2s_token_no_machine(capfd):
    """Test case where a service-to-service token is provided."""
    os.environ["GH_TOKEN"] = "ghs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-r", "testOrg/testRepo"])
    out, err = capfd.readouterr()
    assert "not support App tokens without machine flag" in err


@patch("gatox.enumerate.enumerate.Api.call_get")
@patch("gatox.enumerate.enumerate.Api.call_post")
def test_cli_s2s_token_machine(mock_post, mock_get, capfd):
    """Test case where a service-to-service token is provided."""
    import os
    from gatox.cli import cli  # [gatox/cli/cli.py](gatox/cli/cli.py)

    os.environ["GH_TOKEN"] = "ghs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    # Mock out the enumerator’s HTTP calls here as needed
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {"total_count": 0}
    mock_post.return_value.status_code = 200

    cli.cli(["enumerate", "-r", "testOrg/testRepo", "--machine"])
    out, _ = capfd.readouterr()
    assert "Allowing the use of a GitHub App token for single repo enumeration" in out


def test_cli_u2s_token(capfd):
    """Test case where a service-to-service token is provided."""
    os.environ["GH_TOKEN"] = "ghu_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-t", "test"])
    out, err = capfd.readouterr()
    assert "Provided GitHub PAT is malformed or unsupported" in err


@mock.patch("gatox.cli.cli.Enumerator")
def test_cli_oauth_token(mock_enumerate, capfd):
    """Test case where a GitHub oauth token is provided."""
    os.environ["GH_TOKEN"] = "gho_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_instance = mock_enumerate.return_value
    mock_api = mock.MagicMock()
    mock_api.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo", "workflow"],
    }
    mock_api.get_user_type.return_value = "Organization"
    mock_instance.api = mock_api

    cli.cli(["enumerate", "-t", "test"])
    out, err = capfd.readouterr()

    mock_enumerate.return_value.enumerate_organization.assert_called_once()


@mock.patch("gatox.cli.cli.Enumerator")
def test_cli_old_token(mock_enumerate, capfd):
    """Test case where an old, but still potentially valid GitHub token is provided."""
    os.environ["GH_TOKEN"] = "43255147468edf32a206441ad296ce648f44ee32"

    mock_instance = mock_enumerate.return_value
    mock_api = mock.MagicMock()
    mock_api.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo", "workflow"],
    }
    mock_api.get_user_type.return_value = "Organization"
    mock_instance.api = mock_api

    cli.cli(["enumerate", "-t", "test"])
    out, err = capfd.readouterr()

    mock_instance.enumerate_organization.assert_called_once()


def test_cli_invalid_pat(capfd):
    """Test case where a clearly invalid PAT is provided."""
    os.environ["GH_TOKEN"] = "invalid"

    with pytest.raises(SystemExit):
        cli.cli(["enumerate", "-t", "test"])
    out, err = capfd.readouterr()
    assert "malformed" in err


def test_cli_double_proxy(capfd):
    """Test case where conflicing proxies are provided."""
    with pytest.raises(SystemExit):
        cli.cli(["-sp", "socks", "-p", "http", "enumerate", "-t", "test"])

    out, err = capfd.readouterr()
    assert "proxy at the same time" in err


def test_attack_bad_args1(capfd):
    """Test attack command without the attack method."""

    with pytest.raises(SystemExit):
        cli.cli(["attack", "-t", "test"])

    out, err = capfd.readouterr()
    assert "must select one" in err


def test_attack_bad_args2(capfd):
    """Test attack command with conflicting params."""
    curr_path = pathlib.Path(__file__).parent.resolve()

    with pytest.raises(SystemExit):
        cli.cli(
            [
                "attack",
                "-t",
                "test",
                "-pr",
                "-f",
                os.path.join(curr_path, "files/main.yaml"),
                "-n",
                "invalid",
            ]
        )

    out, err = capfd.readouterr()
    assert "cannot be used with a custom" in err


def test_attack_invalid_path(capfd):
    """Test attack command with an invalid path."""

    with pytest.raises(SystemExit):
        cli.cli(["attack", "-t", "test", "-pr", "-f", "path"])

    out, err = capfd.readouterr()
    assert "argument --custom-file/-f: The file: path does not exist!" in err


def test_repos_file_good():
    """Test that the good file is validated without errors."""
    curr_path = pathlib.Path(__file__).parent.resolve()

    res = read_file_and_validate_lines(
        os.path.join(curr_path, "files/test_repos_good.txt"),
        r"[A-Za-z0-9-_.]+\/[A-Za-z0-9-_.]+",
    )

    assert "someorg/somerepository" in res
    assert "some_org/some-repo" in res


def test_repos_file_bad(capfd):
    """Test that the good file is validated without errors."""
    curr_path = pathlib.Path(__file__).parent.resolve()

    with pytest.raises(SystemExit):
        cli.cli(
            ["enumerate", "-R", os.path.join(curr_path, "files/test_repos_bad.txt")]
        )

    out, err = capfd.readouterr()

    assert "invalid repository name!" in err


def test_valid_dir():
    """Test that the directory validation function works."""
    curr_path = pathlib.Path(__file__).parent.resolve()
    mock_parser = mock.MagicMock()

    res = is_valid_directory(mock_parser, os.path.join(curr_path, "files/"))

    assert res == os.path.join(curr_path, "files/")


def test_invalid_dir(capfd):
    """Test that the directory validation function works."""
    curr_path = pathlib.Path(__file__).parent.resolve()
    mock_parser = mock.MagicMock()

    res = is_valid_directory(mock_parser, os.path.join(curr_path, "invaliddir/"))

    assert res is None

    mock_parser.error.assert_called_with(
        "The directory {} does not exist!".format(
            os.path.join(curr_path, "invaliddir/")
        )
    )


@mock.patch("gatox.attack.runner.webshell.WebShell.runner_on_runner")
def test_attack_pr(mock_attack):
    """Test attack command using the pr method."""
    cli.cli(
        ["attack", "-t", "test", "-pr", "--target-os", "linux", "--target-arch", "x64"]
    )
    mock_attack.assert_called_once()


@mock.patch("gatox.attack.runner.webshell.WebShell.runner_on_runner")
def test_attack_pr_bados(mock_attack, capfd):
    """Test attack command using the pr method."""
    with pytest.raises(SystemExit):
        cli.cli(
            [
                "attack",
                "-t",
                "test",
                "-pr",
                "--target-os",
                "solaris",
                "--target-arch",
                "x64",
            ]
        )

    out, err = capfd.readouterr()
    assert "invalid choice: 'solaris'" in err


@mock.patch("gatox.attack.attack.Attacker.push_workflow_attack")
def test_attack_workflow(mock_attack):
    """Test attack command using the workflow method."""

    cli.cli(["attack", "-t", "test", "-w"])
    mock_attack.assert_called_once()


@mock.patch("os.path.isdir")
def test_enum_bad_args1(mock_dircheck, capfd):
    """Test enum command with invalid output location."""
    mock_dircheck.return_value = False

    with pytest.raises(SystemExit):
        cli.cli(["enum", "-o", "invalid"])

    out, err = capfd.readouterr()
    assert "--output-yaml/-o: The directory: invalid does not exist!" in err


def test_enum_bad_args2(capfd):
    """Test enum command without a type selection."""
    with pytest.raises(SystemExit):
        cli.cli(["enum"])

    out, err = capfd.readouterr()
    assert "type was specified" in err


def test_enum_bad_args3(capfd):
    """Test enum command with multiple type selections."""
    with pytest.raises(SystemExit):
        cli.cli(["enum", "-t", "test", "-r", "testorg/test2"])

    out, err = capfd.readouterr()
    assert "select one enumeration" in err


@mock.patch("gatox.enumerate.enumerate.Enumerator.self_enumeration")
def test_enum_self(mock_enumerate):
    """Test enum command using the self enumerattion."""

    mock_enumerate.return_value = [["org1"], ["org2"]]

    cli.cli(["enum", "-s"])
    mock_enumerate.assert_called_once()


@mock.patch("gatox.models.execution.Execution.add_repositories")
@mock.patch("gatox.models.execution.Execution.add_organizations")
@mock.patch("gatox.enumerate.enumerate.Enumerator.self_enumeration")
def test_enum_self_json_empty(mock_enumerate, mock_executor_org, mock_executor_repo):
    """Test enum command using the self enumerattion."""

    mock_enumerate.return_value = ([], ["repo1", "repo2"])

    cli.cli(["enum", "-s", "-oJ", "test.json"])
    mock_enumerate.assert_called_once()

    mock_executor_org.assert_called_with([])
    mock_executor_repo.assert_called_with(["repo1", "repo2"])


@mock.patch("gatox.cli.cli.Enumerator")
def test_enum_org(mock_enumerate):
    """Test enum command using the organization enumerattion."""

    mock_instance = mock_enumerate.return_value
    mock_api = mock.MagicMock()

    print(mock_instance)

    mock_api.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo", "workflow"],
    }
    mock_api.get_user_type.return_value = "Organization"
    mock_instance.api = mock_api

    cli.cli(["enum", "-t", "test"])

    mock_instance.enumerate_organization.assert_called_once()


@mock.patch("gatox.cli.cli.Enumerator")
def test_enum_user(mock_enumerate):
    """Test enum command using the organization enumeration."""

    mock_instance = mock_enumerate.return_value
    mock_api = mock.MagicMock()

    mock_api.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo", "workflow"],
    }
    mock_api.get_user_type.return_value = "User"
    mock_instance.api = mock_api

    cli.cli(["enum", "-t", "testUser"])

    mock_instance.enumerate_user.assert_called_once()


@mock.patch("gatox.enumerate.enumerate.Enumerator.enumerate_repos")
@mock.patch("gatox.util.read_file_and_validate_lines")
def test_enum_repos(mock_read, mock_enumerate):
    """Test enum command using the repo list."""
    curr_path = pathlib.Path(__file__).parent.resolve()
    mock_read.return_value = "repos"

    cli.cli(["enum", "-R", os.path.join(curr_path, "files/test_repos_good.txt")])
    mock_read.assert_called_once()
    mock_enumerate.assert_called_once()


@mock.patch("gatox.enumerate.enumerate.Enumerator.enumerate_repos")
def test_enum_repo(mock_enumerate):
    """Test enum command using the organization enumerattion."""
    cli.cli(["enum", "-r", "testorg/testrepo"])
    mock_enumerate.assert_called_once()


@mock.patch("gatox.search.search.Searcher.use_search_api")
def test_search(mock_search):
    """Test search command"""

    cli.cli(["search", "-t", "test"])
    mock_search.assert_called_once()


def test_long_repo_name(capfd):
    """Test enum command using name that is too long."""

    repo_name = "Org/" + "A" * 80

    with pytest.raises(SystemExit):
        cli.cli(["enum", "-r", repo_name])

    out, err = capfd.readouterr()

    assert "The maximum length is 79 characters!" in err


def test_invalid_repo_name(capfd):
    """Test enum command using invalid full repo name."""
    with pytest.raises(SystemExit):
        cli.cli(["enum", "-r", "RepoWithoutOrg"])

    out, err = capfd.readouterr()

    assert (
        "argument --repository/-r: The argument" " is not in the valid format!" in err
    )


@mock.patch("gatox.util.arg_utils.os.access")
def test_unreadable_file(mock_access, capfd):
    """Test enum command unreadable file."""
    curr_path = pathlib.Path(__file__).parent.resolve()

    mock_access.return_value = False

    with pytest.raises(SystemExit):
        cli.cli(["enum", "-R", os.path.join(curr_path, "files/bad_dir/bad_file")])

    out, err = capfd.readouterr()

    assert " is not readable" in err


@mock.patch("gatox.util.arg_utils.os.access")
def test_unwritable_dir(mock_access, capfd):
    """Test enum command unwriable dir."""
    curr_path = pathlib.Path(__file__).parent.resolve()

    mock_access.return_value = False

    with pytest.raises(SystemExit):
        cli.cli(
            [
                "enum",
                "-r",
                "testOrg/testRepo",
                "-o",
                os.path.join(curr_path, "files/bad_dir"),
            ]
        )

    out, err = capfd.readouterr()

    assert " is not writeable" in err
