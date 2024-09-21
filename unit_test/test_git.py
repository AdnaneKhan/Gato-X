import pathlib
import os
import pytest
import subprocess

from unittest.mock import MagicMock, patch, call, ANY, mock_open
from gatox.git.git import Git
from gatox.git.utils import version_check, path_check, sed_check


@patch("gatox.git.utils.subprocess.run")
def test_check_git(mock_run):
    """Test test that the git version check works."""

    mock_stdout = MagicMock()
    mock_stdout.configure_mock(**{"stdout": "git version 2.38.2\n", "returncode": 0})

    mock_run.return_value = mock_stdout

    git_status = version_check()
    mock_run.assert_called_once()

    assert git_status == "2.38.2"


@patch("gatox.git.utils.subprocess.run")
def test_check_git_fail(mock_run):
    """Test failure case of git version check."""

    mock_stdout = MagicMock()
    mock_stdout.configure_mock(
        **{"stdout": "command not found: git\n", "returncode": 1}
    )

    mock_run.return_value = mock_stdout

    git_status = version_check()
    mock_run.assert_called_once()

    assert git_status is False


@patch("gatox.git.utils.subprocess.run")
def test_check_git_malformed(mock_run):
    """Test failure case of git version check."""

    mock_stdout = MagicMock()
    mock_stdout.configure_mock(**{"stdout": "git bad!\n", "returncode": 0})

    mock_run.return_value = mock_stdout

    git_status = version_check()
    mock_run.assert_called_once()

    assert git_status is False


@patch("gatox.git.utils.shutil.which")
def test_git_path_check(mock_run):
    """Test checking whether git exists on the path."""

    mock_run.return_value = "/usr/local/bin/git"

    exists = path_check()
    mock_run.assert_called_once()

    assert exists == "/usr/local/bin/git"


@patch("gatox.git.utils.shutil.which")
def test_sed_check(mock_run):
    """Test checking whether sed exists on the path."""
    mock_run.return_value = "/usr/bin/sed"

    exists = sed_check()
    mock_run.assert_called_once()

    assert exists == "/usr/bin/sed"


@patch("gatox.git.utils.shutil.which")
def test_git_path_not_found(mock_run):
    """Test case where git is not on path."""
    mock_run.return_value = None

    exists = path_check()
    mock_run.assert_called_once()

    assert exists is None


def test_constructor():
    """Tests the constructor for the git class."""
    with pytest.raises(ValueError):
        Git(
            "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "RepoOnly",
            proxies={"http": "http://proxy", "https": "https://proxy"},
        )


def test_extract_workflows():
    """Tests extracting workflows from the '.github' folder."""
    curr_path = pathlib.Path(__file__).parent.resolve()

    git = Git("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "dummy/workflow_test")

    test_repo_path = os.path.join(curr_path, "files/")
    ymls = git.extract_workflow_ymls(repo_path=test_repo_path)

    assert len(ymls) == 1


@patch("gatox.git.git.subprocess.Popen")
def test_perform_clone(mock_subprocess):
    """Test performing a repo clone."""
    git = Git("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gitferret/workflow_test")

    call_1 = (
        "git clone --depth 1 --filter=blob:none --sparse "
        "https://ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "@github.com/gitferret/workflow_test"
    ).split(" ")
    call_2 = "git sparse-checkout set .github".split(" ")

    mock_pipe = MagicMock()

    mock_pipe.returncode = 0
    mock_subprocess.return_value = mock_pipe

    ret = git.perform_clone()
    assert ret is True
    mock_subprocess.assert_has_calls(
        [
            call(call_1, cwd=ANY, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
            call(call_2, cwd=ANY, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        ],
        any_order=True,
    )
    assert mock_pipe.wait.call_count == 4


@patch("gatox.git.git.subprocess.Popen")
def test_perform_clone_fail(mock_subprocess):
    """Failure test case performing a repo clone."""
    git = Git("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gitferret/workflow_test")

    call_1 = (
        "git clone --depth 1 --filter=blob:none --sparse "
        "https://ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "@github.com/gitferret/workflow_test"
    ).split(" ")
    mock_pipe = MagicMock()

    mock_pipe.returncode = 1
    mock_subprocess.return_value = mock_pipe

    ret = git.perform_clone()

    mock_subprocess.assert_called_once_with(
        call_1, cwd=ANY, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    assert mock_pipe.wait.call_count == 1
    assert ret is False


@patch("gatox.git.git.subprocess.Popen")
def test_perform_commit(mock_subprocess):
    """Test performing a commit"""
    git = Git("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gitferret/workflow_test")

    message = "unittest commit"

    curr_path = pathlib.Path(__file__).parent.resolve()
    test_repo_path = os.path.join(curr_path, "files/")

    call_1 = "git add test.txt".split(" ")
    call_2 = f"git commit -m".split(" ")
    call_2.append(message)
    call_3 = "git rev-parse HEAD".split(" ")

    mock_pipe = MagicMock()

    mock_pipe.returncode = 0
    mock_subprocess.return_value = mock_pipe

    with patch("builtins.open", mock_open(read_data="")) as mock_file:

        ret = git.commit_file(
            b"TESTDATA", "test.txt", repo_path=test_repo_path, message=message
        )

        mock_file().write.assert_called_once()

        mock_subprocess.assert_has_calls(
            [
                call(
                    call_1,
                    cwd=ANY,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ),
                call(
                    call_2,
                    cwd=ANY,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ),
                call(
                    call_3, cwd=ANY, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
                ),
            ],
            any_order=True,
        )
    assert mock_pipe.wait.call_count == 3
    # TODO: Mock return value of rev-parse
    # assert ret is True


@patch("gatox.git.git.subprocess.Popen")
def test_rewrite_commit(mock_subprocess):
    """Unit test for re-writing commit history."""
    git = Git("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gitferret/workflow_test")

    curr_path = pathlib.Path(__file__).parent.resolve()
    test_repo_path = os.path.join(curr_path, "files/")

    call_1 = ("git rebase -i HEAD^").split(" ")
    mock_pipe = MagicMock()

    mock_pipe.returncode = 0
    mock_subprocess.return_value = mock_pipe

    ret = git.rewrite_commit(repo_path=test_repo_path)

    mock_subprocess.assert_called_once_with(
        call_1, cwd=ANY, env=ANY, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    assert mock_pipe.wait.call_count == 1
    _, kwargs = mock_subprocess.call_args_list[0]
    assert "GIT_SEQUENCE_EDITOR" in kwargs["env"]
    seq_editor = kwargs["env"]["GIT_SEQUENCE_EDITOR"]

    assert seq_editor == "sed -i.bak 's/pick/drop/g'"

    assert ret is True


@patch("gatox.git.git.subprocess.Popen")
def test_push(mock_subprocess):
    """Test performing a commit"""
    git = Git("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gitferret/workflow_test")

    curr_path = pathlib.Path(__file__).parent.resolve()
    test_repo_path = os.path.join(curr_path, "files/")

    branch_name = "testingBranch"
    upstream_branch = "develop"

    call_1 = "git rev-parse --abbrev-ref HEAD".split(" ")
    call_2 = (
        f"git push --set-upstream origin" f" {branch_name}:{upstream_branch}"
    ).split(" ")

    mock_pipe = MagicMock()

    mock_pipe.returncode = 0
    # Set mock for the upstream branch when we rev parse
    mock_pipe.communicate.return_value.__getitem__.return_value.decode.return_value.strip.return_value = (
        "testingBranch"
    )

    mock_subprocess.return_value = mock_pipe

    ret = git.push_repository("develop", repo_path=test_repo_path)

    mock_subprocess.assert_has_calls(
        [
            call(call_1, cwd=ANY, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL),
            call(call_2, cwd=ANY, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        ],
        any_order=True,
    )
    assert mock_pipe.wait.call_count == 2
    assert ret is True


@patch("gatox.git.git.subprocess.Popen")
def test_push_fail(mock_subprocess):
    """Test performing a commit"""
    git = Git("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gitferret/workflow_test")

    curr_path = pathlib.Path(__file__).parent.resolve()
    test_repo_path = os.path.join(curr_path, "files/")

    branch_name = "testingBranch"
    upstream_branch = "develop"

    call_1 = "git rev-parse --abbrev-ref HEAD".split(" ")
    call_2 = (
        f"git push --set-upstream origin" f" {branch_name}:{upstream_branch}"
    ).split(" ")

    mock_pipe = MagicMock()

    mock_pipe.returncode = 1
    # Set mock for the upstream branch when we rev parse
    mock_pipe.communicate.return_value.__getitem__.return_value.decode.return_value.strip.return_value = (
        "testingBranch"
    )

    mock_subprocess.return_value = mock_pipe

    ret = git.push_repository("develop", repo_path=test_repo_path)

    mock_subprocess.assert_has_calls(
        [
            call(call_1, cwd=ANY, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL),
            call(call_2, cwd=ANY, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        ],
        any_order=True,
    )
    assert mock_pipe.wait.call_count == 2
    assert ret is False


@patch("gatox.git.git.subprocess.Popen")
def test_push_force(mock_subprocess):
    """Test performing a commit"""
    git = Git("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gitferret/workflow_test")

    curr_path = pathlib.Path(__file__).parent.resolve()
    test_repo_path = os.path.join(curr_path, "files/")

    branch_name = "testingBranch"
    upstream_branch = "develop"

    call_1 = "git rev-parse --abbrev-ref HEAD".split(" ")
    call_2 = (
        f"git push --set-upstream origin" f" {branch_name}:{upstream_branch} -f"
    ).split(" ")

    mock_pipe = MagicMock()

    mock_pipe.returncode = 0
    # Set mock for the upstream branch when we rev parse
    mock_pipe.communicate.return_value.__getitem__.return_value.decode.return_value.strip.return_value = (
        "testingBranch"
    )

    mock_subprocess.return_value = mock_pipe

    ret = git.push_repository("develop", force=True, repo_path=test_repo_path)

    mock_subprocess.assert_has_calls(
        [
            call(call_1, cwd=ANY, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL),
            call(call_2, cwd=ANY, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        ],
        any_order=True,
    )
    assert mock_pipe.wait.call_count == 2
    assert ret is True


@patch("gatox.git.git.subprocess.Popen")
def test_delete_branch(mock_subprocess):
    """Test performing a commit"""
    git = Git("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gitferret/workflow_test")

    curr_path = pathlib.Path(__file__).parent.resolve()
    test_repo_path = os.path.join(curr_path, "files/")

    call_1 = "git push origin --delete testbranch -f".split(" ")

    mock_pipe = MagicMock()

    mock_pipe.returncode = 0
    mock_subprocess.return_value = mock_pipe

    ret = git.delete_branch("testbranch", repo_path=test_repo_path)

    mock_subprocess.assert_has_calls(
        [call(call_1, cwd=ANY, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)],
        any_order=True,
    )
    assert mock_pipe.wait.call_count == 1
    assert ret is True


@patch("gatox.git.git.subprocess.Popen")
def test_delete_branch_fail(mock_subprocess):
    """Test performing a commit"""
    git = Git("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gitferret/workflow_test")

    curr_path = pathlib.Path(__file__).parent.resolve()
    test_repo_path = os.path.join(curr_path, "files/")

    call_1 = "git push origin --delete testbranch -f".split(" ")

    mock_pipe = MagicMock()

    mock_pipe.returncode = 1
    mock_subprocess.return_value = mock_pipe

    ret = git.delete_branch("testbranch", repo_path=test_repo_path)

    mock_subprocess.assert_has_calls(
        [call(call_1, cwd=ANY, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)],
        any_order=True,
    )
    assert mock_pipe.wait.call_count == 1
    assert ret is False
