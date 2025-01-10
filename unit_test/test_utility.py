import pytest
from gatox.workflow_parser.utility import decompose_action_ref


def test_decompose_action_ref_standard_action():
    action_path = "actions/checkout@v2"
    repo_name = "test/repo"
    result = decompose_action_ref(action_path, repo_name)
    expected = {
        "key": "actions/checkout@v2",
        "path": "",
        "ref": "v2",
        "local": False,
        "docker": False,
        "repo": "actions/checkout",
    }
    assert result == expected


def test_decompose_action_ref_local_action():
    action_path = "./local-action"
    repo_name = "test/repo"
    result = decompose_action_ref(action_path, repo_name)
    expected = {
        "key": "./local-action",
        "path": "local-action",
        "ref": "",
        "local": True,
        "docker": False,
        "repo": "test/repo",
    }
    assert result == expected


def test_decompose_action_ref_docker_action():
    action_path = "docker://alpine:3.8"
    repo_name = "test/repo"
    result = decompose_action_ref(action_path, repo_name)
    expected = {
        "key": "docker://alpine:3.8",
        "path": "docker://alpine:3.8",
        "ref": "",
        "local": False,
        "docker": True,
    }
    assert result == expected


def test_decompose_action_ref_standard_action_no_ref():
    action_path = "test/repo"
    repo_name = "test/repo"
    result = decompose_action_ref(action_path, repo_name)
    expected = {
        "key": "test/repo",
        "path": "",
        "ref": "",
        "local": False,
        "docker": False,
        "repo": "test/repo",
    }
    assert result == expected


def test_decompose_action_ref_nested_action_path():
    action_path = "actions/checkout/path/to/action@v2"
    repo_name = "test/repo"
    result = decompose_action_ref(action_path, repo_name)
    expected = {
        "key": "actions/checkout/path/to/action@v2",
        "path": "path/to/action",
        "ref": "v2",
        "local": False,
        "docker": False,
        "repo": "actions/checkout",
    }
    assert result == expected
